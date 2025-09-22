// SPDX-License-Identifier: GPL-2.0
/*
* XDMA netdev bridge: create a net_device that pumps data between
* XDMA engines and the Linux networking stack without modifying XDMA core.
*/

#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/skbuff.h>
#include <linux/pci.h>
#include <linux/scatterlist.h>
#include <linux/ip.h>
#include <linux/if_arp.h>
#include <linux/icmp.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <linux/workqueue.h>
#include "libxdma_api.h"

static bool netxdma_param_lo = true;
module_param_named(lo, netxdma_param_lo, bool, 0644);
MODULE_PARM_DESC(lo, "Rewrite RX dst/src MAC and IPv4 to loopback");

static bool netxdma_param_debug = false;
module_param_named(debug, netxdma_param_debug, bool, 0644);
MODULE_PARM_DESC(debug, "Enable debug output for performance monitoring");

static int netxdma_param_channels = 1; /* 默认1个通道 */
module_param_named(channels, netxdma_param_channels, int, 0644);
MODULE_PARM_DESC(channels, "Number of parallel channels (default: 1)");

struct net_xdma_priv {
	struct net_device *netdev;
	void *xdev_hndl;
	int num_channels;  /* 通道数量 */
	int *c2h_ch;       /* RX channels */
	int *h2c_ch;       /* TX channels */
	struct task_struct **rx_thread;  /* RX threads */
	struct task_struct *tx_thread;
	struct sk_buff_head txq;
	bool stopping;

	/* TX aggregation: 64KB buffer with 1600-byte fixed slots (2B length + payload) */
    void *tx_agg_bufs[2];
    int tx_agg_idx;
	size_t tx_agg_buf_size;
	size_t tx_agg_slot_size;
	int tx_agg_capacity;
	int tx_agg_slot_count;
	size_t tx_agg_bytes;
	spinlock_t tx_agg_lock;
	struct hrtimer tx_agg_timer;
	bool tx_timer_active;
	struct work_struct tx_agg_work;

	/* RX 64KB block buffer and reusable SG - multi channel */
	struct page **rx_blk_pages;
	void **rx_blk_virt;
	size_t rx_blk_size;
	struct sg_table *rx_blk_sgt;
	/* Performance monitoring */
	u64 rx_packets_processed;
	u64 tx_packets_processed;
	u64 icmp_requests_handled;
	u64 arp_requests_handled;
};

/* forward declaration for TX DMA helper used by aggregation flush */
static int net_xdma_tx_send_buf(struct net_xdma_priv *priv,
				    const void *data, size_t len);

/**
 * @description		: Flush 64KB TX aggregation buffer via XDMA
 * @param priv		: device private
 * @return			: 0 on success, <0 on error
 */
static int net_xdma_tx_flush_agg(struct net_xdma_priv *priv)
{
    int rv;
    unsigned long flags;
    void *buf_to_send;
    int slots_to_account;
    size_t bytes_to_account;
    size_t pad_offset;

    /* Swap out the active buffer under lock, then send without holding lock */
    spin_lock_irqsave(&priv->tx_agg_lock, flags);
    if (priv->tx_agg_bytes == 0) {
        spin_unlock_irqrestore(&priv->tx_agg_lock, flags);
        return 0;
    }
    buf_to_send = priv->tx_agg_bufs[priv->tx_agg_idx];
    slots_to_account = priv->tx_agg_slot_count;
    bytes_to_account = priv->tx_agg_bytes;
    /* Switch to the other buffer */
    priv->tx_agg_idx ^= 1;
    /* Reset counters for new active buffer */
    priv->tx_agg_slot_count = 0;
    priv->tx_agg_bytes = 0;
    /* Ensure the new active buffer starts clean (avoid stale slot headers) */
    memset(priv->tx_agg_bufs[priv->tx_agg_idx], 0, priv->tx_agg_buf_size);
    spin_unlock_irqrestore(&priv->tx_agg_lock, flags);

    /* Zero unused tail in the buffer being sent so RX sees empty slots */
    pad_offset = (size_t)slots_to_account * priv->tx_agg_slot_size;
    if (pad_offset < priv->tx_agg_buf_size)
        memset((u8 *)buf_to_send + pad_offset, 0, priv->tx_agg_buf_size - pad_offset);

    /* Debug: Print aggregated TX data */
    if (netxdma_param_debug && bytes_to_account > 0) {
        pr_info("net_xdma: TX flush agg (slots=%d, bytes=%zu):\n", slots_to_account, bytes_to_account);
        print_hex_dump(KERN_INFO, "TX_FLUSH: ", DUMP_PREFIX_OFFSET, 16, 1, buf_to_send, min(bytes_to_account, 128UL), true);
    }

    /* Send the full 64KB block. Unused area is already zero-padded per slot. */
    rv = net_xdma_tx_send_buf(priv, buf_to_send, priv->tx_agg_buf_size);
    if (rv >= 0) {
        priv->netdev->stats.tx_packets += slots_to_account;
        priv->netdev->stats.tx_bytes += bytes_to_account;
        priv->tx_packets_processed += slots_to_account;
    }
    return rv;
}

static enum hrtimer_restart net_xdma_tx_timer_fn(struct hrtimer *t)
{
	struct net_xdma_priv *priv = container_of(t, struct net_xdma_priv, tx_agg_timer);
	/* Defer flush to process context to avoid sleeping in hardirq */
	schedule_work(&priv->tx_agg_work);
	/* One-shot timer */
	priv->tx_timer_active = false;
	return HRTIMER_NORESTART;
}

static void net_xdma_tx_agg_workfn(struct work_struct *work)
{
	struct net_xdma_priv *priv = container_of(work, struct net_xdma_priv, tx_agg_work);
	net_xdma_tx_flush_agg(priv);
	/* Resume TX queue after flush completed in process context */
	netif_wake_queue(priv->netdev);
}

static void net_xdma_rewrite_headers(struct net_xdma_priv *priv,
					struct sk_buff *skb, size_t frame_len)
{
	struct ethhdr *eth;
	u32 tmp_addr;
	u8 temp_mac[ETH_ALEN];

	if (!netxdma_param_lo || frame_len < sizeof(*eth))
		return;
	
	/* Debug: Print data after header rewrite */
	if (netxdma_param_debug && frame_len > 0) {
		pr_info("net_xdma: rewrite headers (len=%zu):\n", frame_len);
		print_hex_dump(KERN_INFO, "TX: ", DUMP_PREFIX_OFFSET, 16, 1, skb->data, min(frame_len, 64UL), true);
	}

	eth = (struct ethhdr *)skb->data;
	/* For loopback, swap source and dest MAC addresses */
	ether_addr_copy(temp_mac, eth->h_source);
	ether_addr_copy(eth->h_source, eth->h_dest);
	ether_addr_copy(eth->h_dest, temp_mac);
	if (eth->h_proto == htons(ETH_P_IP)) {
		struct iphdr *iph = (struct iphdr *)(skb->data + sizeof(struct ethhdr));
		if ((u8 *)iph + sizeof(struct iphdr) <= skb_tail_pointer(skb)) {
			tmp_addr = iph->saddr;
			iph->saddr = iph->daddr;
			iph->daddr = tmp_addr;
			iph->check = 0;
			iph->check = ip_fast_csum((u8 *)iph, iph->ihl);
			skb->ip_summed = CHECKSUM_UNNECESSARY;

			// /* Handle ICMP echo request directly for lower latency */
			// if (iph->protocol == IPPROTO_ICMP) {
			// 	struct icmphdr *icmph = (struct icmphdr *)((u8 *)iph + (iph->ihl << 2));
			// 	if ((u8 *)icmph + sizeof(struct icmphdr) <= skb_tail_pointer(skb) &&
			// 	    icmph->type == ICMP_ECHO) {
			// 		/* Convert echo request to echo reply */
			// 		icmph->type = ICMP_ECHOREPLY;
			// 		icmph->checksum = 0;
			// 		icmph->checksum = ip_compute_csum(icmph, skb->len - ((u8 *)icmph - skb->data));
			// 		priv->icmp_requests_handled++;
			// 	}
			// }
		}
	} else if (eth->h_proto == htons(ETH_P_ARP)) {
		struct arphdr *arph = (struct arphdr *)(skb->data + sizeof(struct ethhdr));
		u8 *arp_ptr;
		u8 *sha, *tha;
		__be32 *spa, *tpa;

		if ((u8 *)arph + sizeof(struct arphdr) > skb_tail_pointer(skb))
			return;
		/* Only handle Ethernet/IPv4 ARP */
		if (arph->ar_hrd != htons(ARPHRD_ETHER) ||
		    arph->ar_pro != htons(ETH_P_IP) ||
		    arph->ar_hln != ETH_ALEN ||
		    arph->ar_pln != 4)
			return;

		arp_ptr = (u8 *)(arph + 1);
		/* Layout: sha(6) spa(4) tha(6) tpa(4) */
		if (arp_ptr + ETH_ALEN + 4 + ETH_ALEN + 4 > skb_tail_pointer(skb))
			return;

		sha = arp_ptr;
		spa = (__be32 *)(arp_ptr + ETH_ALEN);
		tha = arp_ptr + ETH_ALEN + 4;
		tpa = (__be32 *)(arp_ptr + ETH_ALEN + 4 + ETH_ALEN);

		/* Swap protocol (IP) addresses */
		tmp_addr = *(__force u32 *)spa;
		*(__force u32 *)spa = *(__force u32 *)tpa;
		*(__force u32 *)tpa = tmp_addr;

		/* Turn into a reply and set hardware addrs to our MAC */
		arph->ar_op = htons(ARPOP_REPLY);
		ether_addr_copy(sha, priv->netdev->dev_addr);
		ether_addr_copy(tha, priv->netdev->dev_addr);
		priv->arp_requests_handled++;
	}
}

static void net_xdma_rx_push(struct net_xdma_priv *priv, void *data, size_t len)
{
	struct sk_buff *skb;
	
	/* Debug: Print received data */
	if (netxdma_param_debug && len > 0) {
		pr_info("net_xdma: RX data (len=%zu):\n", len);
		print_hex_dump(KERN_INFO, "RX: ", DUMP_PREFIX_OFFSET, 16, 1, data, min(len, 64UL), true);
	}
	
	/* Use netdev_alloc_skb for safer memory management */
	skb = netdev_alloc_skb(priv->netdev, len);
	if (unlikely(!skb)) {
		priv->netdev->stats.rx_dropped++;
		return;
	}
	
	/* Copy data to skb */
	memcpy(skb_put(skb, len), data, len);

	/* Ensure skb points to full L2 frame before rewrite and proto setup */
	skb_reset_mac_header(skb);
	skb->dev = priv->netdev;

	/* Rewrite headers in place */
	net_xdma_rewrite_headers(priv, skb, len);
	
	/* Debug: Print data after header rewrite */
	if (netxdma_param_debug && len > 0) {
		pr_info("net_xdma: TX data after rewrite (len=%zu):\n", len);
		print_hex_dump(KERN_INFO, "TX: ", DUMP_PREFIX_OFFSET, 16, 1, skb->data, min(len, 64UL), true);
	}
	
	skb->protocol = eth_type_trans(skb, priv->netdev);

	/* Mark checksum as done for performance */
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	
	/* Use GRO for better throughput */
	netif_rx(skb);
	priv->netdev->stats.rx_packets++;
	priv->netdev->stats.rx_bytes += len;
	priv->rx_packets_processed++;
	
	/* Debug output every 1000 packets */
	if (netxdma_param_debug && (priv->rx_packets_processed % 1000 == 0)) {
		pr_info("net_xdma: RX processed %llu packets, ICMP handled %llu, ARP handled %llu\n",
			priv->rx_packets_processed, priv->icmp_requests_handled, priv->arp_requests_handled);
	}
}

static atomic_t tx_ch_selector = ATOMIC_INIT(0);

static int net_xdma_tx_send_buf(struct net_xdma_priv *priv,
				    const void *data, size_t len)
{
	struct sg_table sgt;
	struct scatterlist *sg;
	loff_t pos = 0;
	int rv;
	int tx_ch;

	/* Debug: Print TX data being sent */
	if (netxdma_param_debug && len > 0) {
		pr_info("net_xdma: TX send data (len=%zu):\n", len);
		print_hex_dump(KERN_INFO, "TX_SEND: ", DUMP_PREFIX_OFFSET, 16, 1, data, min(len, 64UL), true);
	}

	rv = sg_alloc_table(&sgt, 1, GFP_KERNEL);
	if (rv)
		return rv;

	sg = sgt.sgl;
	sg_set_buf(sg, data, len);
	sgt.nents = 1;
	sgt.orig_nents = 1;

	/* Round-robin between TX channels for load balancing */
	tx_ch = atomic_inc_return(&tx_ch_selector) % priv->num_channels;
	rv = xdma_xfer_submit(priv->xdev_hndl, priv->h2c_ch[tx_ch], true, pos, &sgt,
			       false, 1000);

	sg_free_table(&sgt);
	return rv;
}

static int net_xdma_tx_thread(void *data)
{
	struct net_xdma_priv *p = data;

	for (;;) {
		struct sk_buff *skb;
		if (kthread_should_stop())
			break;
		skb = skb_dequeue(&p->txq);
		if (!skb) {
			set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout(msecs_to_jiffies(1));  /* 减少到1ms */
			continue;
		}

		if (net_xdma_tx_send_buf(p, skb->data, skb->len) < 0) {
			p->netdev->stats.tx_dropped++;
			dev_kfree_skb(skb);
			continue;
		}

		p->netdev->stats.tx_packets++;
		p->netdev->stats.tx_bytes += skb->len;
		p->tx_packets_processed++;
		dev_kfree_skb(skb);
		if (netif_queue_stopped(p->netdev) && skb_queue_len(&p->txq) < 512)
			netif_wake_queue(p->netdev);
	}

	return 0;
}

struct rx_thread_data {
	struct net_xdma_priv *priv;
	int ch_idx;
};

static int net_xdma_rx_thread(void *data)
{
	struct rx_thread_data *thread_data = data;
	struct net_xdma_priv *priv = thread_data->priv;
	int ch_idx = thread_data->ch_idx;
	const size_t slot = 1600; /* 2B len + payload, fixed 1600 bytes per packet */
	loff_t pos = 0;
	
	/* Validate channel index */
	if (ch_idx < 0 || ch_idx >= priv->num_channels) {
		pr_err("net_xdma: invalid channel index %d (max: %d)\n", ch_idx, priv->num_channels - 1);
		return -EINVAL;
	}

	while (!kthread_should_stop()) {
		size_t got = 0;

		/* Perform C2H DMA read into 64KB block buffer */
		got = xdma_xfer_submit(priv->xdev_hndl, priv->c2h_ch[ch_idx], false, pos, &priv->rx_blk_sgt[ch_idx], false, 1000);
		if ((ssize_t)got <= 0) {
			/* Use usleep for lower latency instead of msleep */
			usleep_range(100, 500);  /* 100-500微秒，比1ms快很多 */
			continue;
		}

		/* Debug: Print raw DMA data received */
		if (netxdma_param_debug && got > 0) {
			pr_info("net_xdma: RX DMA data (ch=%d, got=%zu):\n", ch_idx, got);
			print_hex_dump(KERN_INFO, "DMA_RX: ", DUMP_PREFIX_OFFSET, 16, 1, priv->rx_blk_virt[ch_idx], min(got, 128UL), true);
		}

		/* Unpack 64KB block into 1600-byte slots: [2B len | payload | padding] */
		{
			size_t offset = 0;
			size_t max = got - (got % slot);
			
			while (offset + 2 <= max) {
				u16 slen = le16_to_cpu(*((u16 *)((u8 *)priv->rx_blk_virt[ch_idx] + offset)));
				if (slen == 0) {
					/* empty slot */
					offset += slot;
					continue;
				}
				/* Validate packet length: should not exceed slot capacity */
				if (slen > slot - 2 || offset + 2 + slen > max) {
					/* corrupted slot; stop parsing this block */
					break;
				}
				
				/* Process packet using net_xdma_rx_push */
				net_xdma_rx_push(priv, (u8 *)priv->rx_blk_virt[ch_idx] + offset + 2, slen);
				offset += slot;
			}
			/* Clear processed region to avoid re-parsing stale slots on partial overwrites */
			if (max > 0)
				memset(priv->rx_blk_virt[ch_idx], 0, max);
		}
	}
	return 0;
}

static netdev_tx_t net_xdma_start_xmit(struct sk_buff *skb, struct net_device *ndev)
{
	struct net_xdma_priv *priv = netdev_priv(ndev);
	unsigned long flags;
	const size_t slot_hdr = 2; /* u16 length */
	size_t copy_len = skb->len;
	u16 len16;
	void *dst;

	/* clamp payload to slot capacity (1600 - 2 = 1598 bytes max) */
	if (copy_len > priv->tx_agg_slot_size - slot_hdr)
		copy_len = priv->tx_agg_slot_size - slot_hdr;
	len16 = (u16)copy_len;

	spin_lock_irqsave(&priv->tx_agg_lock, flags);
	/* allocate next slot; if full, flush first */
	if (priv->tx_agg_slot_count >= priv->tx_agg_capacity) {
		spin_unlock_irqrestore(&priv->tx_agg_lock, flags);
		/* schedule flush in process context to avoid sleeping in atomic */
		netif_stop_queue(ndev);
		schedule_work(&priv->tx_agg_work);
		/* free skb and return early; flush will run asynchronously */
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}

	/* compute destination */
    dst = (u8 *)priv->tx_agg_bufs[priv->tx_agg_idx] + (size_t)priv->tx_agg_slot_count * priv->tx_agg_slot_size;
	/* write length */
	*((u16 *)dst) = cpu_to_le16(len16);
	/* write payload */
	memcpy((u8 *)dst + slot_hdr, skb->data, copy_len);
	/* zero tail */
	if (priv->tx_agg_slot_size > slot_hdr + copy_len)
		memset((u8 *)dst + slot_hdr + copy_len, 0, priv->tx_agg_slot_size - slot_hdr - copy_len);

	priv->tx_agg_slot_count++;
	priv->tx_agg_bytes += slot_hdr + copy_len;

	/* start 1ms timer if first slot */
	if (!priv->tx_timer_active) {
		hrtimer_start(&priv->tx_agg_timer, ktime_set(0, 1 * 1000000), HRTIMER_MODE_REL_PINNED);
		priv->tx_timer_active = true;
	}

	/* if full 64KB, flush now */
	if (priv->tx_agg_slot_count >= priv->tx_agg_capacity) {
		spin_unlock_irqrestore(&priv->tx_agg_lock, flags);
		netif_stop_queue(ndev);
		schedule_work(&priv->tx_agg_work);
	} else {
		spin_unlock_irqrestore(&priv->tx_agg_lock, flags);
	}

	/* free skb immediately; aggregation owns copy */
	dev_kfree_skb_any(skb);
	return NETDEV_TX_OK;
}

static int net_xdma_open(struct net_device *ndev)
{
	struct net_xdma_priv *priv = netdev_priv(ndev);
	int i;
	
	netif_start_queue(ndev);
	priv->stopping = false;
	
	/* Start multi-channel RX threads */
	for (i = 0; i < priv->num_channels; i++) {
		char name[32];
		struct rx_thread_data *thread_data;
		
		thread_data = kzalloc(sizeof(struct rx_thread_data), GFP_KERNEL);
		if (!thread_data)
			return -ENOMEM;
		thread_data->priv = priv;
		thread_data->ch_idx = i;
		
		snprintf(name, sizeof(name), "netxdma-rx%d", i);
		priv->rx_thread[i] = kthread_run(net_xdma_rx_thread, thread_data, name);
		if (IS_ERR(priv->rx_thread[i])) {
			kfree(thread_data);
			return PTR_ERR(priv->rx_thread[i]);
		}
	}
	
	priv->tx_thread = kthread_run(net_xdma_tx_thread, priv, "netxdma-tx");
	if (IS_ERR(priv->tx_thread))
		return PTR_ERR(priv->tx_thread);
	return 0;
}

static int net_xdma_stop(struct net_device *ndev)
{
	struct net_xdma_priv *priv = netdev_priv(ndev);
	int i;
	
	pr_info("net_xdma: stopping device, channels=%d\n", priv->num_channels);
	netif_stop_queue(ndev);
	priv->stopping = true;
	
	/* Stop multi-channel RX threads */
	if (priv->rx_thread && priv->num_channels > 0) {
		for (i = 0; i < priv->num_channels; i++) {
			if (priv->rx_thread[i]) {
				kthread_stop(priv->rx_thread[i]);
				priv->rx_thread[i] = NULL;
			}
		}
	}
	
	if (priv->tx_thread) {
		kthread_stop(priv->tx_thread);
		priv->tx_thread = NULL;
	}
	return 0;
}

static const struct net_device_ops net_xdma_ops = {
	.ndo_open = net_xdma_open,
	.ndo_stop = net_xdma_stop,
	.ndo_start_xmit = net_xdma_start_xmit,
};

/* Simple singleton registration: attach to the first XDMA device. */
static struct net_device *g_netdev;

int net_xdma_register(void *xdev_hndl)
{
	struct net_device *ndev;
	struct net_xdma_priv *priv;
	int i, j;

	ndev = alloc_etherdev(sizeof(struct net_xdma_priv));
	if (!ndev)
		return -ENOMEM;

	priv = netdev_priv(ndev);
	memset(priv, 0, sizeof(*priv));
	priv->netdev = ndev;
	priv->xdev_hndl = xdev_hndl;
	priv->num_channels = netxdma_param_channels;
	
	/* Allocate channel arrays */
	priv->c2h_ch = kzalloc(priv->num_channels * sizeof(int), GFP_KERNEL);
	priv->h2c_ch = kzalloc(priv->num_channels * sizeof(int), GFP_KERNEL);
	priv->rx_thread = kzalloc(priv->num_channels * sizeof(struct task_struct*), GFP_KERNEL);
	if (!priv->c2h_ch || !priv->h2c_ch || !priv->rx_thread) {
		kfree(priv->c2h_ch);
		kfree(priv->h2c_ch);
		kfree(priv->rx_thread);
		free_netdev(ndev);
		return -ENOMEM;
	}
	
	/* Initialize channel numbers */
	for (i = 0; i < priv->num_channels; i++) {
		priv->c2h_ch[i] = i;
		priv->h2c_ch[i] = i;
	}
	pr_info("net_xdma: initialized %d channels (C2H: %d-%d, H2C: %d-%d)\n", 
		priv->num_channels, priv->c2h_ch[0], priv->c2h_ch[priv->num_channels-1],
		priv->h2c_ch[0], priv->h2c_ch[priv->num_channels-1]);
	skb_queue_head_init(&priv->txq);

	/* init TX aggregation resources */
	priv->tx_agg_buf_size = 64 * 1024;
	priv->tx_agg_slot_size = 1600; /* 2B len + payload padding, fixed 1600 bytes per packet */
	priv->tx_agg_capacity = priv->tx_agg_buf_size / priv->tx_agg_slot_size;
	priv->tx_agg_slot_count = 0;
	priv->tx_agg_bytes = 0;
	priv->tx_timer_active = false;
	spin_lock_init(&priv->tx_agg_lock);
    priv->tx_agg_bufs[0] = kzalloc(priv->tx_agg_buf_size, GFP_KERNEL);
    priv->tx_agg_bufs[1] = kzalloc(priv->tx_agg_buf_size, GFP_KERNEL);
    if (!priv->tx_agg_bufs[0] || !priv->tx_agg_bufs[1]) {
        kfree(priv->tx_agg_bufs[0]);
        kfree(priv->tx_agg_bufs[1]);
		free_netdev(ndev);
		return -ENOMEM;
	}
    priv->tx_agg_idx = 0;
	hrtimer_init(&priv->tx_agg_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL_PINNED);
	priv->tx_agg_timer.function = net_xdma_tx_timer_fn;
	INIT_WORK(&priv->tx_agg_work, net_xdma_tx_agg_workfn);

	/* init RX 64KB block buffer and SG - multi channel */
	priv->rx_blk_size = 64 * 1024;
	priv->rx_blk_pages = kzalloc(priv->num_channels * sizeof(struct page*), GFP_KERNEL);
	priv->rx_blk_virt = kzalloc(priv->num_channels * sizeof(void*), GFP_KERNEL);
	priv->rx_blk_sgt = kzalloc(priv->num_channels * sizeof(struct sg_table), GFP_KERNEL);
	if (!priv->rx_blk_pages || !priv->rx_blk_virt || !priv->rx_blk_sgt) {
		kfree(priv->rx_blk_pages);
		kfree(priv->rx_blk_virt);
		kfree(priv->rx_blk_sgt);
		kfree(priv->c2h_ch);
		kfree(priv->h2c_ch);
		kfree(priv->rx_thread);
		kfree(priv->tx_agg_bufs[0]);
		kfree(priv->tx_agg_bufs[1]);
		free_netdev(ndev);
		return -ENOMEM;
	}
	
	for (i = 0; i < priv->num_channels; i++) {
		priv->rx_blk_pages[i] = alloc_pages(GFP_KERNEL, get_order(priv->rx_blk_size));
		if (!priv->rx_blk_pages[i]) {
			/* cleanup previous allocations */
			for (j = 0; j < i; j++) {
				__free_pages(priv->rx_blk_pages[j], get_order(priv->rx_blk_size));
			}
			kfree(priv->rx_blk_pages);
			kfree(priv->rx_blk_virt);
			kfree(priv->rx_blk_sgt);
			kfree(priv->c2h_ch);
			kfree(priv->h2c_ch);
			kfree(priv->rx_thread);
			kfree(priv->tx_agg_bufs[0]);
			kfree(priv->tx_agg_bufs[1]);
			free_netdev(ndev);
			return -ENOMEM;
		}
		priv->rx_blk_virt[i] = page_address(priv->rx_blk_pages[i]);
		if (sg_alloc_table(&priv->rx_blk_sgt[i], 1, GFP_KERNEL)) {
			__free_pages(priv->rx_blk_pages[i], get_order(priv->rx_blk_size));
			/* cleanup previous allocations */
			for (j = 0; j < i; j++) {
				sg_free_table(&priv->rx_blk_sgt[j]);
				__free_pages(priv->rx_blk_pages[j], get_order(priv->rx_blk_size));
			}
			kfree(priv->rx_blk_pages);
			kfree(priv->rx_blk_virt);
			kfree(priv->rx_blk_sgt);
			kfree(priv->c2h_ch);
			kfree(priv->h2c_ch);
			kfree(priv->rx_thread);
			kfree(priv->tx_agg_bufs[0]);
			kfree(priv->tx_agg_bufs[1]);
			free_netdev(ndev);
			return -ENOMEM;
		}
		sg_set_page(priv->rx_blk_sgt[i].sgl, virt_to_page(priv->rx_blk_virt[i]),
			   priv->rx_blk_size, offset_in_page(priv->rx_blk_virt[i]));
		priv->rx_blk_sgt[i].nents = 1;
		priv->rx_blk_sgt[i].orig_nents = 1;
	}

	ether_setup(ndev);
	eth_hw_addr_random(ndev);
	ndev->netdev_ops = &net_xdma_ops;
	/* Enable GRO/GSO features for higher throughput */
	ndev->features |= NETIF_F_GRO | NETIF_F_GSO;
	ndev->hw_features |= NETIF_F_GRO | NETIF_F_GSO;
	snprintf(ndev->name, IFNAMSIZ, "netxdma%%d");

	if (register_netdev(ndev)) {
		free_netdev(ndev);
		return -EINVAL;
	}

	g_netdev = ndev;
	pr_info("net_xdma: registered %s for xdev %p\n", ndev->name, xdev_hndl);
	pr_info("net_xdma: TX aggregation: %zu bytes/slot, %d slots/buffer, %zu bytes/buffer\n",
		priv->tx_agg_slot_size, priv->tx_agg_capacity, priv->tx_agg_buf_size);
	pr_info("net_xdma: RX parsing: %zu bytes/slot, %d channels enabled\n", 1600UL, priv->num_channels);
	return 0;
}

void net_xdma_unregister(void)
{
	if (g_netdev) {
		struct net_xdma_priv *priv = netdev_priv(g_netdev);
		int i;
		
		/* First unregister netdev to stop threads properly */
		unregister_netdev(g_netdev);
		
		/* Then cancel tx timer and free agg buf */
		hrtimer_cancel(&priv->tx_agg_timer);
		flush_work(&priv->tx_agg_work);
		kfree(priv->tx_agg_bufs[0]);
		kfree(priv->tx_agg_bufs[1]);
		
		/* free RX 64KB block resources - multi channel */
		if (priv->rx_blk_sgt && priv->rx_blk_pages && priv->num_channels > 0) {
			for (i = 0; i < priv->num_channels; i++) {
				sg_free_table(&priv->rx_blk_sgt[i]);
				__free_pages(priv->rx_blk_pages[i], get_order(priv->rx_blk_size));
			}
		}
		kfree(priv->rx_blk_pages);
		kfree(priv->rx_blk_virt);
		kfree(priv->rx_blk_sgt);
		kfree(priv->c2h_ch);
		kfree(priv->h2c_ch);
		kfree(priv->rx_thread);
		free_netdev(g_netdev);
		g_netdev = NULL;
		pr_info("net_xdma: unregistered\n");
	}
}

MODULE_AUTHOR("net_xdma");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("XDMA to netdev bridge");

