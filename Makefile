 all:
	make -C xdma
	cp xdma/xdma.ko .

clean:
	make -C xdma clean
	rm -f xdma.ko