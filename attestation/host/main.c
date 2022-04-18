/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <err.h>
//#include <stdio.h>
//#include <string.h>

#include <dirent.h>

/* OP-TEE TEE client API (built by optee_client) */
#include "tee_client_api.h"
#include "virt_to_phys_user.h"

/* For the UUID (found in the TA's h-file(s)) */
#include <attestation_ta.h>
#include <ctype.h>
#include <stdlib.h>

struct test_value {
	size_t count;
	uint32_t expected;
};

/*
 * Test values coming from the RFC4226 specification.
 */
struct test_value rfc4226_test_values[] = {
	{ 0, 755224 },
	{ 1, 287082 },
	{ 2, 359152 },
	{ 3, 969429 },
	{ 4, 338314 },
	{ 5, 254676 },
	{ 6, 287922 },
	{ 7, 162583 },
	{ 8, 399871 },
	{ 9, 520489 }
};

int main(void)
{
	TEEC_Context ctx;
	TEEC_Operation op = { 0 };
	TEEC_Result res;
	TEEC_Session sess;
	TEEC_UUID uuid = TA_ATTESTATION_UUID;

	uint32_t err_origin;

	/*
	 * Shared key K ("12345678901234567890"), this is the key used in
	 * RFC4226 - Test Vectors.
	 */
	uint8_t K[] = {
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
		0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
		0x37, 0x38, 0x39, 0x30
	};

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);
    fprintf(stdout, "TEEC_InitializeContext \n");

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
		     res, err_origin);
    fprintf(stdout, "TEEC_OpenSession \n");

	/* 1. Register the shared key */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = K;
	op.params[0].tmpref.size = sizeof(K);

	fprintf(stdout, "Register the shared key: %s\n", K);
	res = TEEC_InvokeCommand(&sess, TA_ATTESTATION_CMD_REGISTER_SHARED_KEY,
				 &op, &err_origin);
	if (res != TEEC_SUCCESS) {
		fprintf(stderr, "TEEC_InvokeCommand failed with code 0x%x "
			"origin 0x%x\n",
			res, err_origin);
		goto exit;
	}
    fprintf(stdout, "TEEC_InvokeCommand(TA_ATTESTATION_CMD_REGISTER_SHARED_KEY)\n");

	/* 2. Get HMAC based One Time Passwords */
    /*
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	for (i = 0; i < sizeof(rfc4226_test_values) / sizeof(struct test_value);
	     i++) {
		res = TEEC_InvokeCommand(&sess, TA_ATTEST_CMD_GET_HOTP, &op,
					 &err_origin);
		if (res != TEEC_SUCCESS) {
			fprintf(stderr, "TEEC_InvokeCommand failed with code "
				"0x%x origin 0x%x\n", res, err_origin);
			goto exit;
		}

		hotp_value = op.params[0].value.a;
		fprintf(stdout, "HOTP: %d\n", hotp_value);

		if (hotp_value != rfc4226_test_values[i].expected) {
			fprintf(stderr, "Got unexpected HOTP from TEE! "
				"Expected: %d, got: %d\n",
				rfc4226_test_values[i].expected, hotp_value);
		}
	}*/

    //TODO: make function which checks whether a certain memref has already been initialized or not and test it before executing the initialize command.

    pid_t pid = get_proc_pid();
    uintptr_t vaddr = get_proc_vaddr();
    uintptr_t paddr;
    virt_to_phys_user(&paddr, pid, vaddr);
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    //op.params[0].tmpref.buffer = (void *) pagestart; //TODO: put memory pages of a program here.
    //op.params[0].tmpref.size = size;
    op.params[0].tmpref.buffer = paddr; //TODO: put memory pages of a program here.
    op.params[0].tmpref.size = sizeof(&paddr);
    fprintf(stdout, "TEEC_InvokeCommand(TA_ATTESTATION_CMD_INITIALIZE)\n");
    res = TEEC_InvokeCommand(&sess, TA_ATTESTATION_CMD_INITIALIZE, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "TEEC_InvokeCommand failed with code "
                        "0x%x origin 0x%x\n", res, err_origin);
        goto exit;
    }
    fprintf(stdout, "MAC initialization successful!");

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = K; //TODO: put memory pages of a program here.
    op.params[0].tmpref.size = sizeof(K);
    res = TEEC_InvokeCommand(&sess, TA_ATTESTATION_CMD_ATTEST, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "TEEC_InvokeCommand failed with code "
                        "0x%x origin 0x%x\n", res, err_origin);
        goto exit;
    }
    fprintf(stderr, "Attestation successful!");

exit:
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return 0;
}
