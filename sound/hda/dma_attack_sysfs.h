#ifndef _DMA_ATTACK_SYSFS_H
#define _DMA_ATTACK_SYSFS_H

extern struct security_test_mem *g_test_alloc;
extern struct security_test_mem *g_test_noise;
extern struct security_test_mem *dma_debug_buffer_alloc(
		struct security_test_mem *test_alloc,
		enum test_mem_type mem_type,
		uint32_t mem_size);
extern void fill_dmaarea_with_16khz(u16 *v_dma_area, u32 length);
#endif
