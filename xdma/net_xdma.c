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
#include "libxdma_api.h"

static bool netxdma_param_lo = false;
module_param_named(lo, netxdma_param_lo, bool, 0644);
MODULE_PARM_DESC(lo, "Rewrite RX dst/src MAC and IPv4 to loopback");

struct net_xdma_priv {
	struct net_device *netdev;
	void *xdev_hndl;
	int c2h_ch;
	int h2c_ch;
	struct task_struct *rx_thread;
	struct task_struct *tx_thread;
	struct sk_buff_head txq;
	bool stopping;
};

static void net_xdma_rewrite_headers(struct net_xdma_priv *priv,
					struct sk_buff *skb, size_t frame_len)
{
	struct ethhdr *eth;
	u32 tmp_addr;

	if (!netxdma_param_lo || frame_len < sizeof(*eth))
		return;

	eth = (struct ethhdr *)skb->data;
	ether_addr_copy(eth->h_source, priv->netdev->dev_addr);
	ether_addr_copy(eth->h_dest, priv->netdev->dev_addr);
	if (eth->h_proto == htons(ETH_P_IP)) {
		struct iphdr *iph = (struct iphdr *)(skb->data + sizeof(struct ethhdr));
		if ((u8 *)iph + sizeof(struct iphdr) <= skb_tail_pointer(skb)) {
			tmp_addr = iph->saddr;
			iph->saddr = iph->daddr;
			iph->daddr = tmp_addr;
			iph->check = 0;
			iph->check = ip_fast_csum((u8 *)iph, iph->ihl);
			skb->ip_summed = CHECKSUM_UNNECESSARY;
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
	}
}

static void net_xdma_rx_push(struct net_xdma_priv *priv, void *data, size_t len)
{
	struct sk_buff *skb = netdev_alloc_skb(priv->netdev, len);
	if (unlikely(!skb)) {
		priv->netdev->stats.rx_dropped++;
		return;
	}

	memcpy(skb_put(skb, len), data, len);
	net_xdma_rewrite_headers(priv, skb, len);
	skb->protocol = eth_type_trans(skb, priv->netdev);
	netif_rx(skb);
	priv->netdev->stats.rx_packets++;
	priv->netdev->stats.rx_bytes += len;
}

static int net_xdma_tx_send_buf(struct net_xdma_priv *priv,
				    const void *data, size_t len)
{
	struct sg_table sgt;
	struct scatterlist *sg;
	loff_t pos = 0;
	int rv;

	rv = sg_alloc_table(&sgt, 1, GFP_KERNEL);
	if (rv)
		return rv;

	sg = sgt.sgl;
	sg_set_buf(sg, data, len);
	sgt.nents = 1;
	sgt.orig_nents = 1;

	rv = xdma_xfer_submit(priv->xdev_hndl, priv->h2c_ch, true, pos, &sgt,
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
			schedule_timeout(msecs_to_jiffies(10));
			continue;
		}

		if (net_xdma_tx_send_buf(p, skb->data, skb->len) < 0) {
			p->netdev->stats.tx_dropped++;
			dev_kfree_skb(skb);
			continue;
		}

		p->netdev->stats.tx_packets++;
		p->netdev->stats.tx_bytes += skb->len;
		dev_kfree_skb(skb);
		if (netif_queue_stopped(p->netdev) && skb_queue_len(&p->txq) < 512)
			netif_wake_queue(p->netdev);
	}

	return 0;
}

static int net_xdma_rx_thread(void *data)
{
	struct net_xdma_priv *priv = data;
	// 4k对齐
	const size_t buf_len = 4096; /* one standard MTU buffer */
	void *kbuf;
	struct page *page;
	struct sg_table sgt;
	struct scatterlist *sg;
	int rv;
	loff_t pos = 0;

	kbuf = kmalloc(buf_len, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	rv = sg_alloc_table(&sgt, 1, GFP_KERNEL);
	if (rv) {
		kfree(kbuf);
		return rv;
	}

	while (!kthread_should_stop()) {
		size_t got = 0;

		/* Map kernel buffer into single SG entry */
		page = virt_to_page(kbuf);
		sg = sgt.sgl;
		sg_set_page(sg, page, buf_len, offset_in_page(kbuf));
		sgt.nents = 1;
		sgt.orig_nents = 1;

		/* Perform C2H DMA read into kbuf */
		got = xdma_xfer_submit(priv->xdev_hndl, priv->c2h_ch, false, pos, &sgt, false, 1000);
		if ((ssize_t)got <= 0) {
			/* idle briefly to avoid tight loop */
			msleep(1);
			continue;
		}

		/* Push to network stack */
		if (likely(got > 0))
			net_xdma_rx_push(priv, kbuf, got);
	}

	sg_free_table(&sgt);
	kfree(kbuf);
	return 0;
}

static netdev_tx_t net_xdma_start_xmit(struct sk_buff *skb, struct net_device *ndev)
{
	struct net_xdma_priv *priv = netdev_priv(ndev);

	/* Enqueue skb and wake TX thread. Must not sleep here. */
	if (unlikely(skb_queue_len(&priv->txq) > 1024)) {
		netif_stop_queue(ndev);
	}
	__skb_queue_tail(&priv->txq, skb);
	if (priv->tx_thread)
		wake_up_process(priv->tx_thread);
	return NETDEV_TX_OK;
}

static int net_xdma_open(struct net_device *ndev)
{
	struct net_xdma_priv *priv = netdev_priv(ndev);
	netif_start_queue(ndev);
	priv->stopping = false;
	priv->rx_thread = kthread_run(net_xdma_rx_thread, priv, "netxdma-rx");
	if (IS_ERR(priv->rx_thread))
		return PTR_ERR(priv->rx_thread);
	priv->tx_thread = kthread_run(net_xdma_tx_thread, priv, "netxdma-tx");
	if (IS_ERR(priv->tx_thread))
		return PTR_ERR(priv->tx_thread);
	return 0;
}

static int net_xdma_stop(struct net_device *ndev)
{
	struct net_xdma_priv *priv = netdev_priv(ndev);
	netif_stop_queue(ndev);
	if (priv->rx_thread)
		kthread_stop(priv->rx_thread);
	priv->rx_thread = NULL;
	if (priv->tx_thread)
		kthread_stop(priv->tx_thread);
	priv->tx_thread = NULL;
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

	ndev = alloc_etherdev(sizeof(struct net_xdma_priv));
	if (!ndev)
		return -ENOMEM;

	priv = netdev_priv(ndev);
	memset(priv, 0, sizeof(*priv));
	priv->netdev = ndev;
	priv->xdev_hndl = xdev_hndl;
	/* default to channel 0 both directions */
	priv->c2h_ch = 0;
	priv->h2c_ch = 0;
	skb_queue_head_init(&priv->txq);

	ether_setup(ndev);
	eth_hw_addr_random(ndev);
	ndev->netdev_ops = &net_xdma_ops;
	snprintf(ndev->name, IFNAMSIZ, "netxdma%%d");

	if (register_netdev(ndev)) {
		free_netdev(ndev);
		return -EINVAL;
	}

	g_netdev = ndev;
	pr_info("net_xdma: registered %s for xdev %p\n", ndev->name, xdev_hndl);
	return 0;
}

void net_xdma_unregister(void)
{
	if (g_netdev) {
		unregister_netdev(g_netdev);
		free_netdev(g_netdev);
		g_netdev = NULL;
		pr_info("net_xdma: unregistered\n");
	}
}

MODULE_AUTHOR("net_xdma");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("XDMA to netdev bridge");

