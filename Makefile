mod_name=recon_ghost
obj-m := $(mod_name).o
LKM-objs += simple_netfilter_LKM.o
KERN = $(shell uname -r)
REGEX = "TCP_ACK|TCP_XMAS|TCP_FIN|TCP_NULL|TCP_RFC_O|TCP_SYN"

all:
	make -C /lib/modules/$(KERN)/build M=$(shell pwd) modules
	rm -rf *.mod.c *.cmd *.symvers *.o
run:
	iptables -I OUTPUT -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT
	insmod $(mod_name).ko
stop:
	iptables -D OUTPUT -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT
	rmmod $(mod_name)
syslog:
	dmesg | grep -E $(REGEX)
clean:
	make -C /lib/modules/$(KERN)/build M=$(PWD) clean
