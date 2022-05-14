/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018-2019, Linaro Limited
 */
#ifndef __PTA_MEASUREMENT_H
#define __PTA_MEASUREMENT_H

#include <util.h>

/*
 * Interface to the pseudo TA, which provides remote attestation.
 */
#define MEASUREMENT_UUID \
		{ 0xa2b0b139, 0x82dc, 0x4ffc, \
			{ 0xa8, 0xa8, 0x7d, 0x7c, 0x63, 0x66, 0xe9, 0x84 } }

#define MEASUREMENT_CMD_INIT    	0
#define MEASUREMENT_CMD_ATTEST    	1

#endif /* __PTA_MEASUREMENT_H */
