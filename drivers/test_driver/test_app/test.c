#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <string.h>
#include "../test_driver.h"

int read_cpuid(int fd, exx_reg_val_t *reg)
{
	int ret = 0;

	ioctl(fd, READ_CPUID, (unsigned int *)reg);
	printf("%s: eax_ret_val=0x%x, ebx_ret_val=0x%x, ecx_ret_val=0x%x, edx_ret_val=0x%x\n",\
			__func__, reg->eax_ret_val, reg->ebx_ret_val, reg->ecx_ret_val, reg->edx_ret_val);
	return ret;
}

int read_msr(int fd, unsigned long msr_reg, unsigned long msr_val)
{
	int ret = 0;
	unsigned long msr_register = msr_reg;

	ioctl(fd, GET_MSR_REG_VAL, (unsigned int *)&msr_reg);
	if (msr_reg == ~0x0)
		ret = -1;
	msr_val = msr_reg;
	printf("%s: msr_reg=0x%lx msr_val=0x%lx ret=%d\n",\
			__func__, msr_register, (unsigned long)msr_reg, ret);
	return ret;
}

int write_msr(int fd, unsigned long msr_reg, unsigned long msr_val)
{
	int ret = 0;
	msr_reg_val_t msr_para;
	msr_para.reg = msr_reg;
	msr_para.val = msr_val;
	msr_para.ret = 0xff;
	ioctl(fd, SET_MSR_REG_VAL, (unsigned int *)&msr_para);
	printf("%s: msr_reg=0x%lx msr_val=0x%lx ret=%ld\n",\
			__func__, msr_reg, msr_para.val, msr_para.ret);
	return ret;
}

int main(int argc, const char *argv[])
{
	int fd;
	int ret;
	unsigned long msr_reg = 0x17; //reg:0x17, display cpu model
	unsigned long msr_val;
    int val = 0;
    unsigned long long addr;
    unsigned int len;
    mem_dump_t *mem_dump = NULL;
    char wr_flag = 0;

if (argc < 3) {
	fd = open("/dev/hello_class", O_RDWR, 0664);
	if (0 > fd) {
		printf("%s: test : open : error\n", __func__);
		return -1;
	}

	//read cpuid
	exx_reg_val_t reg = {0};
	reg.eax_val = 0x7;
	reg.ecx_val = 0;
	read_cpuid(fd, &reg);

	//read_msr
	msr_reg = 0x17;
	if (argc > 1)
		msr_reg = (unsigned long)atoi(argv[1]);
	printf("\n%s: msr_reg=0x%lx\n", __func__, msr_reg);
	ret = read_msr(fd, msr_reg, msr_val);
	if (ret < 0) {
		printf("%s: read msr failed, ret=0x%x\n", __func__, ret);
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}
else if (argc < 4)
{
    sscanf(argv[1], "%llx", &addr);
    sscanf(argv[2], "%x", &len);

    mem_dump = malloc(sizeof(mem_dump_t) + len * sizeof(unsigned char));
    if(!mem_dump) {
        printf("mem alloc failed\n");
        return 0;
    }

    memset(mem_dump, 0, sizeof(mem_dump_t) + len * sizeof(unsigned char));

    mem_dump->addr = addr;
    mem_dump->len = len;

    printf("mem_base = 0x%llx\n", mem_dump->addr);
    printf("mem_size = 0x%x\n", mem_dump->len);
    printf("dump_addr = %p\n", mem_dump->buf);

    fd = open("/dev/hello_class", O_RDWR);
    if(fd == -1) {
        printf("Failed to open device %s\n", "/dev/hello_class");
        return -1;
    }

    ioctl(fd, DUMP_MEM, mem_dump);

    for (int i = 0; i < mem_dump->len; i++) {
        if((i != 0) && (i % 4 == 0))
            printf(" ");
        if((i != 0) && (i % 16 == 0))
           printf("\n");
        printf("%02x", mem_dump->buf[i]);
    }

    printf("\n");
    ioctl(fd, CHECK_FEATURE, &val);
    if (val)
        printf("X86_FEATURE_RETPOLINE is set\n");
    else
        printf("X86_FEATURE_RETPOLINE is not set\n");

    close(fd);

    if(mem_dump)
        free(mem_dump);

    return 0;

}
else
{
	wr_flag = *(char*)argv[2];
	sscanf(argv[3], "%lx", &msr_reg);

	fd = open("/dev/hello_class", O_RDWR, 0664);
	if (0 > fd) {
		printf("%s: test : open : error\n", __func__);
		return -1;
	}
	//read_msr
	if (wr_flag == 'r')
	{
		ret = read_msr(fd, msr_reg, msr_val);
		if (ret < 0) {
			printf("%s: read msr failed, ret=0x%x\n", __func__, ret);
			close(fd);
			return -1;
		}
	}
	else if(wr_flag == 'w')
	{
		sscanf(argv[4], "%lx", &msr_val);
		ret = write_msr(fd, msr_reg, msr_val);
	}

	close(fd);
    return 0;
}

}
