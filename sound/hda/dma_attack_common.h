#ifndef _DMA_TEST_H
#define _DMA_TEST_H

#define DMA_TEST
#define PAGE_4K_SIZE 0x1000

struct security_test_mem {
	uint64_t vir_addr;
	uint64_t phy_addr;
	uint32_t size;
};

enum test_mem_type {
	MEM_TYPE_VMM = 0,
	MEM_TYPE_LK = 1,
	MEM_TYPE_LINUX = 2,
	MEM_TYPE_INVALID = 0xFFFFFFFF
};

#define BDL_TO_NO_USED				'0'
#define BDL_TO_LINUX_NOISE_MEMORY	'1'
#define BDL_TO_LINUX_ZERO_MEMORY	'2'
#define BDL_TO_VMM_MEMORY			'3'
#define BDL_TO_LK_MEMORY			'4'
#define BDL_TO_VMM_MEMORY_WAIT			'5'

//#define USE_DUMP_STACK
#ifdef USE_DUMP_STACK
#include <linux/kprobes.h>
#include <asm/traps.h>
#endif

#endif
