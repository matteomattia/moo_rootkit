# moo_rootkit

it's a simple LKM rootkit. Tested on Linux Debian 6 - Kernel 2.6.32-5-686 (32bit) e con GCC 4.4.5

Just for fun

#Functionality:

- hide itself from commands like insmod, lsmod, modprobe..
- syscall hijacking
- hide a chosen tcp port
- parse commands from a /proc node
ex. echo nasconditi > /proc/moooo # hide itself
