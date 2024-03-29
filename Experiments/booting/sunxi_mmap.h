/*
 * Copyright (c) 2017-2019, ARM Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef SUNXI_MMAP_H
#define SUNXI_MMAP_H

/* Memory regions */
#define SUNXI_ROM_BASE			0x00000000
#define SUNXI_ROM_SIZE			0x00010000
#define SUNXI_SRAM_BASE			0x00010000
#define SUNXI_SRAM_SIZE			0x00046000
#define SUNXI_SRAM_A1_BASE		0x00010000
#define SUNXI_SRAM_A1_SIZE		0x00008000
#define SUNXI_SRAM_A2_BASE		0x00040000
#define SUNXI_SRAM_A2_BL31_OFFSET	0x00004000
#define SUNXI_SRAM_A2_SIZE		0x00016000
#define SUNXI_SRAM_C_BASE		0x00018000
#define SUNXI_SRAM_C_SIZE		0x0001c000
#define SUNXI_DEV_BASE			0x01000000
#define SUNXI_DEV_SIZE			0x01000000
#define SUNXI_DRAM_BASE			0x40000000
#define SUNXI_DRAM_VIRT_BASE		0x02000000

/* Memory-mapped devices */
#define SUNXI_CPU_MBIST_BASE		0x01502000
#define SUNXI_CPUCFG_BASE		0x01700000
#define SUNXI_SYSCON_BASE		0x01c00000
#define SUNXI_DMA_BASE			0x01c02000
#define SUNXI_KEYMEM_BASE		0x01c0b000
#define SUNXI_SMHC0_BASE		0x01c0f000
#define SUNXI_SMHC1_BASE		0x01c10000
#define SUNXI_SMHC2_BASE		0x01c11000
#define SUNXI_SID_BASE			0x01c14000
#define SUNXI_MSGBOX_BASE		0x01c17000
#define SUNXI_SPINLOCK_BASE		0x01c18000
#define SUNXI_CCU_BASE			0x01c20000
#define SUNXI_PIO_BASE			0x01c20800
#define SUNXI_TIMER_BASE		0x01c20c00
#define SUNXI_WDOG_BASE			0x01c20ca0
#define SUNXI_SPC_BASE			0x01c23400
#define SUNXI_THS_BASE			0x01c25000
#define SUNXI_UART0_BASE		0x01c28000
#define SUNXI_UART1_BASE		0x01c28400
#define SUNXI_UART2_BASE		0x01c28800
#define SUNXI_UART3_BASE		0x01c28c00
#define SUNXI_I2C0_BASE			0x01c2ac00
#define SUNXI_I2C1_BASE			0x01c2b000
#define SUNXI_I2C2_BASE			0x01c2b400
#define SUNXI_DRAMCOM_BASE		0x01c62000
#define SUNXI_DRAMCTL_BASE		0x01c63000
#define SUNXI_DRAMPHY_BASE		0x01c65000
#define SUNXI_SPI0_BASE			0x01c68000
#define SUNXI_SPI1_BASE			0x01c69000
#define SUNXI_SCU_BASE			0x01c80000
#define SUNXI_GICD_BASE			0x01c81000
#define SUNXI_GICC_BASE			0x01c82000
#define SUNXI_RTC_BASE			0x01f00000
#define SUNXI_R_TIMER_BASE		0x01f00800
#define SUNXI_R_INTC_BASE		0x01f00c00
#define SUNXI_R_WDOG_BASE		0x01f01000
#define SUNXI_R_PRCM_BASE		0x01f01400
#define SUNXI_R_TWD_BASE		0x01f01800
#define SUNXI_R_CPUCFG_BASE		0x01f01c00
#define SUNXI_R_CIR_BASE		0x01f02000
#define SUNXI_R_I2C_BASE		0x01f02400
#define SUNXI_R_UART_BASE		0x01f02800
#define SUNXI_R_PIO_BASE		0x01f02c00
#define SUNXI_R_RSB_BASE		0x01f03400
#define SUNXI_R_PWM_BASE		0x01f03800

#endif /* SUNXI_MMAP_H */
