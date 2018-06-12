#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include "test_driver.h"
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <asm/msr.h>

#define CLASS_DEV_CREATE
#ifdef CLASS_DEV_CREATE
#include <linux/device.h>
#include <linux/bitops.h>
#endif


static ssize_t dump_mem(unsigned char *arg)
{
    printk("KERNEL:writing...\n");
    mem_dump_t mem;
    if(copy_from_user(&mem, arg, sizeof(mem_dump_t)))
    {
        return -EFAULT;
    }

    printk("addr to read  = 0x%lx\n", mem.addr);
    printk("size to read  = 0x%x\n", mem.len);
    printk("user addr = %p\n", ((mem_dump_t *)arg)->buf);
    if(copy_to_user(((mem_dump_t *)arg)->buf, mem.addr, mem.len))
    {
        printk("copy_to_user failed\n");
        return -EFAULT;
    }
    return mem.len;
}

static int read_cpuid(exx_reg_val_t *reg)
{
	int ret;

	__asm__ (
			"mov %4, %%eax\n\t"
			"mov %6, %%ecx\n\t"
			"cpuid\n\t"
			"mov %%eax, %0\n\t"
			"mov %%ebx, %1\n\t"
			"mov %%ecx, %2\n\t"
			"mov %%edx, %3\n\t"

			: "=r" (reg->eax_ret_val),\
			"=r" (reg->ebx_ret_val),\
			"=r" (reg->ecx_ret_val),\
			"=r" (reg->edx_ret_val)/*output*/

			: "r" (reg->eax_val), \
			"r"(reg->ebx_val),\
			"r"(reg->ecx_val), \
			"r"(reg->edx_val),"0" (0) /*input*/
			: "%eax", "%ebx","%ecx", "%edx");

	printk("eax:0x%x, ecx:0x%x\n", reg->eax_val, reg->ecx_val);
	printk("edx_ret:0x%x\n", reg->edx_ret_val);

	return 0;
}

/*
 * bit29 is set, msr exist
 * */
static int get_msr_bit(char which_bit)
{
	int ret;

	__asm__ (
			"mov $0x07, %%eax\n\t"
			"mov $0x0, %%ecx\n\t"
			"cpuid\n\t"
			"mov %%edx, %0\n\t"
			: "=r" (ret) /*output*/
			: "0" (0) /*input*/
			: "%eax", "%ebx","%ecx", "%edx");

	printk("edx = %x\n", ret);
	//ret = (ret >> 29) & 1;
	ret = (ret >> which_bit) & 1;
	printk("edx[29] = %x\n", ret);

	return ret; //bit29
}

#define N 128
#define DEV_NAME "hello_class"
MODULE_LICENSE("GPL");

char data[N];

static int major = 220;
static int minor = 1;
unsigned long long g_magic_data_addr;

#ifdef CLASS_DEV_CREATE
static struct class *cls;
static struct device *device;
#endif

static int hello_open(struct inode *inode, struct file *fl)
{
	printk("hello_open\n");
	return 0;
}

static int hello_release(struct inode *inode, struct file *file)
{
	printk("hello_release\n");

	return 0;
}

static ssize_t hello_read(struct file *file, char __user *buf,
		size_t size, loff_t *loff)
{
	unsigned long i;
	if (size > N)
		size = N;
	if (size < 0)
		return -EINVAL;
	char * magic_addr, read_addr;

	unsigned long long magic_data[200][2] = {0};
	for (i=0; i < 200; i++) {
		magic_data[i][0] = 0xaa;
		magic_data[i][1] = 0x55;;

	}


	magic_addr = (char*)magic_data;
	magic_addr = ((unsigned long)magic_addr+0x1000) & (~0xfff);
	magic_addr -= 200;
	for (i=0; i < 2000000; i++) {
		printk("read %llx = %02x\n", (unsigned long)magic_addr+(i%200),(char *)magic_addr[i % 200]);
	}

	if (copy_to_user(buf, &magic_addr, sizeof(unsigned long long)))
		return -ENOMEM;


	printk("hello_read: %llx\n", g_magic_data_addr);
	return size;
}

static ssize_t hello_write(struct file *file, const char __user *buff,
		size_t size, loff_t *loff)
{
	if (size > N)
		size = N;
	if (size < 0)
		return -EINVAL;

	memset(data, '\0', sizeof(data));

	if (0 != copy_from_user(data, buff, size))
		return -ENOMEM;

	printk("hello_write\n");
	printk("data = %s\n", data);

	return size;
}

static long hello_unlocked_ioctl(struct file *file, unsigned int cmd,
		unsigned long arg)
{
    bool feature_val = 0;
	switch(cmd) {
	case MSR_IA32_ARCH_CAPABILITIES_IS_EXIST:
		{
			unsigned int bit_val;
#define WHICH_BIT 29 //bit29
			bit_val = (unsigned int)get_msr_bit(WHICH_BIT);
			//bit_val = 1; //test for user space
			copy_to_user((unsigned long *)arg, &bit_val, sizeof(unsigned int));

			printk("MSR_IA32_ARCH_CAPABILITIES_IS_EXIST\n");
			break;
		}
	case GET_MSR_REG_VAL:
		{
			unsigned long msr_reg;
			unsigned long msr_val;
			int err = -1;
			u32 val_low = 0x55, val_high = 0x55;
			//msr_reg = 0x17; //test: display cpu model

			copy_from_user(&msr_reg, (unsigned long *)arg, sizeof(unsigned long));
			printk("msr_reg=0x%x\n", msr_reg);

			err = rdmsr_safe(msr_reg, &val_low, &val_high);
			if (err < 0)
			{
				printk("rdmsr_safe: read msr 0x%x failed\n", msr_reg);
				msr_val = ~0x0;
			} else {
				msr_val = (unsigned long)val_high;
				msr_val <<=32;
				msr_val |= (unsigned long)val_low;
			}

			printk("val_low=0x%x, val_high=0x%x, msr_val=0x%llx; err=0x%x\n", val_low, val_high, msr_val, err);

			copy_to_user((unsigned long *)arg, &msr_val, sizeof(unsigned long));

			printk("GET_MSR_REG_VAL\n");
			break;
		}
	case SET_MSR_REG_VAL:
		{
			unsigned long msr_reg;
			unsigned long msr_val;
			int err = -1;
			u32 val_low = 0x55, val_high = 0x55;
			msr_reg_val_t msr_para;

			copy_from_user(&msr_para, arg, sizeof(msr_reg_val_t));
			msr_reg = msr_para.reg;
			val_low = msr_para.val & 0x00000000FFFFFFFF;
			val_high = msr_para.val >> 32;
			printk("msr_reg=0x%x, low=0x%x, high=0x%x\n", msr_reg, val_low, val_high);

			err = wrmsr_safe(msr_reg, val_low, val_high);
			msr_para.ret = err;
			if (err < 0)
			{
				printk("wrmsr_safe: write msr 0x%x failed\n", msr_reg);
			}

			printk("val_low=0x%x, val_high=0x%x, err=0x%x\n", val_low, val_high, err);

			copy_to_user((unsigned long *)arg, &msr_para, sizeof(msr_reg_val_t));

			printk("SET_MSR_REG_VAL\n");
			break;
		}
	case READ_CPUID:
		{
			exx_reg_val_t reg = {0};
			copy_from_user(&reg, (unsigned long *)arg, sizeof(exx_reg_val_t));
			//reg.eax_val = 0x7;
			//reg.ecx_val = 0;

			read_cpuid(&reg);

			copy_to_user((unsigned long *)arg, &reg, sizeof(exx_reg_val_t));
			printk("eax_tet_val = 0x%x\n", reg.eax_ret_val);
			printk("ebx_tet_val = 0x%x\n", reg.ebx_ret_val);
			printk("ecx_tet_val = 0x%x\n", reg.ecx_ret_val);
			printk("edx_tet_val = 0x%x\n", reg.edx_ret_val);
			printk("READ_CPUID\n");
			break;
		}
    case DUMP_MEM:
        printk("KERNEL:dump_mem begin...\n");
        dump_mem((unsigned char *)arg);
        printk("KERNEL:dump_mem done...\n");
        break;
    case CHECK_FEATURE:
        feature_val = test_bit(X86_FEATURE_RETPOLINE, (unsigned long *)(boot_cpu_data.x86_capability));
        copy_to_user(arg, &feature_val, sizeof(feature_val));
		break;

	default:
		printk("enter default\n");
		break;
	}

	printk("hello_unlocked_ioctl\n");

	return 0;
}

static struct cdev cdev;
static struct file_operations hello_ops = {
	.owner = THIS_MODULE,
	.open = hello_open,
	.read = hello_read,
	.write = hello_write,
	.release = hello_release,
	.unlocked_ioctl = hello_unlocked_ioctl,
};


typedef struct magic_heap {
	char * name;
	int magic[100];
} magic_heap_t;

int test_thread(void* data)
{
	printk("test_driver: enter %s\n", __func__);
	magic_heap_t *magic_heap_p;
	int i;

	unsigned long magic_data[20][2] = {0};
	for (i=0; i < 20; i++) {
		magic_data[i][0] = &magic_data[i][0];
		magic_data[i][1] = &magic_data[i][0];;

	}
	g_magic_data_addr = (unsigned long long)magic_data;


	printk("test_driver magic_data addr: 0x%llx\n", magic_data);

	magic_heap_p = (magic_heap_t *)kmalloc(sizeof(magic_heap_t), GFP_KERNEL);
	magic_heap_p->name = "my_magic_heap";
	for (i = 0; i < 100; i++) {
		magic_heap_p->magic[i] = 0xdeadbeef;
	}
	printk("test_driver magic_heap_p: 0x%llx\n", magic_heap_p);


	i = 0;
	while(1) {
		//printk("test_driver: magic_data %d: %x\n", magic_data[i % 20][0], magic_data[i % 20][1]);
		//printk("test_driver: magic_heap_p->magic %x\n", magic_heap_p->magic[i % 100]);
		msleep(5000);
		i++;
	}
    return 0;
}

static int hello_init(void)
{
	int ret;

	printk("hello_init\n");
	dev_t devno = MKDEV(major, minor);
	ret = register_chrdev_region(devno, 1, DEV_NAME);
	if (0 != ret) {
		//alloc_chrdev_region(&devno,0,1,DEV_NAME);
		printk("register_chrdev_region : error\n");
	}

	cdev_init(&cdev, &hello_ops);
	ret = cdev_add(&cdev, devno, 1);
	if (0 != ret) {
		printk("cdev_add\n");
		unregister_chrdev_region(devno, 1);
		return -1;
	}

#ifdef CLASS_DEV_CREATE
	cls = class_create(THIS_MODULE, DEV_NAME);
	device_create(cls, device, devno, NULL, DEV_NAME);
#endif

	printk("hello_init\n");

	kthread_run(test_thread, NULL, "my_test_thread");
	return 0;
}

static void hello_exit(void)
{
	dev_t devno = MKDEV(major, minor);

#ifdef CLASS_DEV_CREATE
	device_destroy(cls, devno);
	class_destroy(cls);
#endif

	cdev_del(&cdev);
	unregister_chrdev_region(devno, 1);

	printk("hello_exit\n");
}

module_init(hello_init);
module_exit(hello_exit);
