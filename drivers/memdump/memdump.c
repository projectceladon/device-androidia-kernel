/*
 * Run command:
 * insmod memdump.ko address=0x12200000 size=1024
 * Then get the binary file in memdump.hex.
 *
 */#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

unsigned long address = 0;
module_param(address, ulong, 0);
MODULE_PARM_DESC(address, "physical address to test");

static unsigned long size = 0;
module_param(size, ulong, 0);
MODULE_PARM_DESC(size, "size in bytes to dump");

static int memdump_init(void)
{
	void* vaddr = 0;
	unsigned long i = 0;
	struct file* fp;
	mm_segment_t fs;
	loff_t pos = 0;
	unsigned char buf[200];
	unsigned char* cur = NULL;

	printk("%s\n", __func__);
	printk("paddr=%#lx\n", address);
	printk("size=%ld\n", size);

	vaddr = __va(address);
	printk("vaddr=%#p\n", vaddr);

	fp=filp_open("./memdump.hex",O_RDWR|O_CREAT|O_TRUNC, 0644);
	if(IS_ERR(fp))
	{
		printk("create memdump.hex file error\n");
		return -1;
	}
	fs=get_fs();
	set_fs(KERNEL_DS);
	vfs_write(fp, vaddr, size, &pos);
	filp_close(fp, NULL);
	set_fs(fs);

	printk("memdump start\n");
	memset(buf, 0, 100);
	cur = buf;
	for (i=0; i<size; i++)
	{
		if (i%64==0 && i!=0)
		{
			sprintf(cur, "\n");
			printk(buf);
			cur = buf;
		}
		else if (i%4==0 && i!=0)
		{
			sprintf(cur, " ");
			cur=cur+1;
		}

		sprintf(cur, "%02hhx",*((unsigned char*)vaddr+i));
		cur=cur+2;
	}
	sprintf(cur, "\n");
	printk(buf);
	printk("memdump end\n");

	return 0;
}

static void memdump_exit(void)
{
	printk("%s\n", __func__);
}

module_init(memdump_init);
module_exit(memdump_exit);
