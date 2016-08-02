#makefile, ricordarsi di usare obj-m := e non obj-m += perchè usiamo exit e non cleanup

obj-m := moo_rootkit.o
KERNEL_DIR = /lib/modules/$(shell uname -r)/build
PWD = $(shell pwd)
all:
	$(MAKE) -C $(KERNEL_DIR) SUBDIRS=$(PWD)
clean:
	rm -rf *.o *.ko *.symvers *.mod.* *.order .*.cmd
#.*.cmd si potrebbe anche togliere, ma non dobbiamo compilare chissà cosa
