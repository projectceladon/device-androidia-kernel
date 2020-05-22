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



#define N 128
#define DEV_NAME "test_driver"
MODULE_LICENSE("GPL");

char data[N];

static int major = 220;
static int minor = 1;
unsigned long long g_magic_data_addr;

#ifdef CLASS_DEV_CREATE
static struct class *cls;
static struct device *device;
#endif

#define PAGE_4K_SIZE 0x1000

#define MEM_SHOW_SIZE 8

struct security_test_mem {
        uint64_t vir_addr;
        uint64_t phy_addr;
        uint32_t size;
};


struct security_test_msg { 
        uint32_t cmd_code; 
        uint32_t ret_code; 
        uint64_t msg_params; 
        uint32_t send_buf[MEM_SHOW_SIZE]; 
}; 
 
enum security_test_cmd { 
        CMD_START, 
        CMD_ALLOC_MEM, 
        CMD_FREE_MEM, 
        CMD_CHECK_MEM, 
        CMD_GPA_TO_HPA, 
        CMD_END 
}; 

int vmm_check_ret_code = 0;

struct security_test_mem *g_test_vmm_alloc;

#define TRUSTY_VMCALL_SECURITY_TEST 0x53544400
#define TRUSTY_VMCALL_ACRN_SECURITY_TEST 0x80000073

//request vmm memory
struct security_test_msg *security_test_vmcall(
        struct security_test_msg *r0)
{
        __asm__ __volatile__ (
                "vmcall;\n"
                : "=D" (r0)
                : "a" (TRUSTY_VMCALL_SECURITY_TEST), "D" (r0));
        return r0;
}

struct security_test_msg *security_test_vmcall_acrn(
        struct security_test_msg *r0)
{
        register unsigned long smc_id asm("r8") = TRUSTY_VMCALL_ACRN_SECURITY_TEST;
        __asm__ __volatile__(
                "vmcall; \n"
                : "=D"(r0)
                : "r"(smc_id), "D"(r0)
                : "rax"
        );

        return r0;
}

static inline struct security_test_mem *security_test_alloc(
        uint32_t command,
        struct security_test_mem *test_alloc,
	unsigned long p_user,
		uint32_t is_acrn)
{
        struct security_test_msg *test_msg = NULL;
        int i=0;

        test_msg = kmalloc(sizeof(struct security_test_msg), GFP_KERNEL);
        if (!test_msg)
                return NULL;
        test_msg->cmd_code = command;
        test_msg->ret_code = 0xdead;
        test_msg->msg_params = (uint64_t)test_alloc;
	if (is_acrn)
		test_msg = security_test_vmcall_acrn(test_msg);
	else
        	test_msg = security_test_vmcall(test_msg);
        if (test_msg->ret_code != 0)
                pr_err("%s failed, ret_code = 0x%x\n",
                                __func__, test_msg->ret_code);

        if (command == CMD_CHECK_MEM)
                vmm_check_ret_code = test_msg->ret_code;

	copy_to_user(p_user, &test_alloc->vir_addr, sizeof(test_alloc->vir_addr));
	copy_to_user(p_user+sizeof(test_alloc->vir_addr), test_msg->send_buf, MEM_SHOW_SIZE*sizeof(test_msg->send_buf[0]));
        if ((command == CMD_CHECK_MEM) || (command == CMD_ALLOC_MEM))
        {
                pr_info("%d bytes memorycontent from vmm:\n", MEM_SHOW_SIZE*sizeof(test_msg->send_buf[0]));
                for(i=0; i<MEM_SHOW_SIZE; i+=4)
                {
                        pr_info("%08lx %08lx %08x %08x\n", test_msg->send_buf[i],
                                                        test_msg->send_buf[i+1],
                                                        test_msg->send_buf[i+2],
                                                        test_msg->send_buf[i+3]);
                }
        }

        kfree(test_msg);

        return test_alloc;
}


struct security_test_mem *dma_debug_buffer_alloc(
        struct security_test_mem *test_alloc, uint32_t mem_size, unsigned long p_user, uint32_t is_acrn)
{
        pr_info("%s start\n", __func__);

        test_alloc = kmalloc(
                                sizeof(struct security_test_mem),
                                GFP_KERNEL);
        if (!test_alloc) {
                pr_info("dmatest Failed to allocate memory for test_alloc\n");
                return NULL;
        }
        memset((char *)test_alloc, 0, sizeof(struct security_test_mem));
        test_alloc->size = mem_size;

        test_alloc = security_test_alloc(CMD_ALLOC_MEM, test_alloc, p_user, is_acrn);

        pr_info("%s alloc-HVA=0x%lx, HPA=0x%lx, Size=0x%x\n ",
                        __func__, test_alloc->vir_addr, test_alloc->phy_addr,
                        mem_size);


        return test_alloc;
}


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
	return size;
}

static ssize_t hello_write(struct file *file, const char __user *buff,
		size_t size, loff_t *loff)
{
	return size;
}

static long hello_unlocked_ioctl(struct file *file, unsigned int cmd,
		unsigned long arg)
{
	switch(cmd) {
		case VMM_ALLOC:
		{
                	if (!g_test_vmm_alloc)
                        	g_test_vmm_alloc = dma_debug_buffer_alloc(
                                	g_test_vmm_alloc, PAGE_4K_SIZE, arg, 0);
			break;
		}
		case VMM_CHECK_FREE:
		{
	                g_test_vmm_alloc = security_test_alloc(
        	                        CMD_CHECK_MEM, g_test_vmm_alloc, arg, 0);
                	pr_info("%s check-HVA=0x%lx, HPA=0x%lx\n ",
                        	__func__,
	                        g_test_vmm_alloc->vir_addr,
        	                g_test_vmm_alloc->phy_addr);

                	g_test_vmm_alloc = security_test_alloc(
                        	        CMD_FREE_MEM, g_test_vmm_alloc, arg, 0);
	                pr_info("%s freed-HVA=0x%lx, HPA=0x%lx\n ",
        	                __func__,
                	        g_test_vmm_alloc->vir_addr,
                        	g_test_vmm_alloc->phy_addr);

	                g_test_vmm_alloc = NULL;

			break;
		}
		case ACRN_ALLOC:
		{
                	if (!g_test_vmm_alloc)
                        	g_test_vmm_alloc = dma_debug_buffer_alloc(
                                	g_test_vmm_alloc, PAGE_4K_SIZE, arg, 1);

			break;
		}
		case ACRN_CHECK_FREE:
		{
        	        g_test_vmm_alloc = security_test_alloc(
                	                CMD_CHECK_MEM, g_test_vmm_alloc, arg, 1);
	                pr_info("%s check-HVA=0x%lx, HPA=0x%lx\n ",
        	                __func__,
                	        g_test_vmm_alloc->vir_addr,
                        	g_test_vmm_alloc->phy_addr);

	                g_test_vmm_alloc = security_test_alloc(
        	                        CMD_FREE_MEM, g_test_vmm_alloc, arg, 1);
                	pr_info("%s freed-HVA=0x%lx, HPA=0x%lx\n ",
                        	__func__,
	                        g_test_vmm_alloc->vir_addr,
        	                g_test_vmm_alloc->phy_addr);

                	g_test_vmm_alloc = NULL;
			break;
		}
               case ACRN_GPA_TO_HPA:
               {
                        struct security_test_msg *test_msg = NULL;
                        struct security_test_mem *test_alloc = NULL;
                        test_alloc = kmalloc(
                                 sizeof(struct security_test_mem),
                                 GFP_KERNEL);
                        if (!test_alloc) {
                                pr_info("dmatest Failed to allocate memory for test_alloc\n");
                                return NULL;
                        }
                        memset((char *)test_alloc, 0, sizeof(struct security_test_mem));
                        copy_from_user(&test_alloc->vir_addr, arg, sizeof(test_alloc->vir_addr));
 
                        test_msg = kmalloc(sizeof(struct security_test_msg), GFP_KERNEL);
                        if (!test_msg)
                                return NULL;
                        test_msg->cmd_code = CMD_GPA_TO_HPA;
                        test_msg->ret_code = 0xdead;
                        test_msg->msg_params = (uint64_t)test_alloc;
                        test_msg = security_test_vmcall_acrn(test_msg);
                        if (test_msg->ret_code != 0)
                                pr_err("%s failed, ret_code = 0x%x\n",
                                        __func__, test_msg->ret_code);

                        copy_to_user(arg, &test_alloc->phy_addr, sizeof(test_alloc->vir_addr));
                        pr_info("%s change GPA=0x%lx, HPA=0x%lx\n ",
                                __func__,
                                test_alloc->vir_addr,
                                test_alloc->phy_addr);

                        kfree(test_msg);
                        kfree(test_alloc);
			break;
               }

	default:
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
	.compat_ioctl = hello_unlocked_ioctl,
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
