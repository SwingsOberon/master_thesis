/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef __ATTESTATION_TA_H__
#define __ATTESTATION_TA_H__

/*
 * This TA implements HOTP according to:
 * https://www.ietf.org/rfc/rfc4226.txt
 */

#define TA_ATTESTATION_UUID \
	{ 0x474d4123, 0x2d81, 0x4825, \
		{ 0x68, 0x20, 0x4a, 0x6f, 0x42, 0x0b, 0x65, 0x42 } }

/* The function ID(s) implemented in this TA */
#define TA_ATTESTATION_CMD_INITIALIZE      0
#define TA_ATTESTATION_CMD_ATTEST          1

#define PAGE_SIZE 4096


#endif
