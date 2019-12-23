#ifndef __TEST_DRIVER_H
#define __TEST_DRIVER_H
#define MSR_IA32_ARCH_CAPABILITIES_IS_EXIST _IO('K',0)
#define GET_MSR_REG_VAL _IO('K',1)
#define SET_MSR_REG_VAL _IO('K',2)
#define READ_CPUID _IO('K',3)

typedef struct exx_reg_val{
	int eax_val;
	int ebx_val;
	int ecx_val;
	int edx_val;

	int eax_ret_val;
	int ebx_ret_val;
	int ecx_ret_val;
	int edx_ret_val;
} exx_reg_val_t;


#define DUMP_MEM _IO('k', 1)
#define CHECK_FEATURE _IO('o', 1)


typedef struct mem_dump {
    unsigned long long addr;
    unsigned int len;
    unsigned int padding;
    unsigned char buf[0];
} mem_dump_t;

typedef struct msr_reg_val{
	unsigned long reg;
	unsigned long val;
	long ret;
} msr_reg_val_t;

#endif
