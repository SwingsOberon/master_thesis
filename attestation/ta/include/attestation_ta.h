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
#define TA_ATTESTATION_CMD_REGISTER_SHARED_KEY	0
#define TA_ATTESTATION_CMD_INITIALIZE      1
#define TA_ATTESTATION_CMD_ATTEST          2

#define PAGE_SIZE 1024 //In the paper this is 4096 but hmac_sha1 complains when this number is used so it is kept at 1024 right now.


#endif
