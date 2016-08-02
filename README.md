# moo_rootkit

it's a simple LKM rootkit. Tested on Linux Debian 6 - Kernel 2.6.32-5-686 (32bit) e con GCC 4.4.5

Just for fun

#Functionality:

- hide itself from commands like insmod, lsmod, modprobe..
- syscall hijacking
- hide a chosen tcp port
- parse commands from a /proc node
ex. echo nasconditi > /proc/moooo # hide itself

---
References

http://core.ipsecs.com/rootkit/kernel-rootkit/kbeast-v1/ipsecs-kbeast-v1.c
https://memset.wordpress.com/2011/03/18/syscall-hijacking-dynamically-obtain-syscall-table-address-kernel-2-6-x-2/
http://www.phrack.org/issues/58/6.html#article
http://www.phrack.org/issues/58/7.html#article
https://volatility-labs.blogspot.it/2012/09/movp-15-kbeast-rootkit-detecting-hidden.html
