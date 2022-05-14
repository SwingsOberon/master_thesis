/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <err.h>
#include <stdio.h>
#include <string.h>

#include <dirent.h>

/* OP-TEE TEE client API (built by optee_client) */
#include "tee_client_api.h"
#include "virt_to_phys_user.h"

/* For the UUID (found in the TA's h-file(s)) */
#include <attestation_ta.h>
#include <ctype.h>
#include <stdlib.h>

int main(int argc, char** argv)
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
    fprintf(stdout, "TEEC_InvokeCommand(TA_ATTESTATION_CMD_REGISTER_SHARED_KEY)\n");
	res = TEEC_InvokeCommand(&sess, TA_ATTESTATION_CMD_REGISTER_SHARED_KEY,
				 &op, &err_origin);
	if (res != TEEC_SUCCESS) {
        fprintf(stderr, "TEEC_InvokeCommand failed with code 0x%x "
                        "origin 0x%x\n",
                res, err_origin);
        goto exit;
    }

    pid_t pid = get_proc_pid();
    uint64_t vaddr;
    size_t size;
    get_proc_vaddr(&vaddr, &size);
    fprintf(stdout, "vaddr = %lu\n", vaddr);
    uintptr_t paddr;
    virt_to_phys_user(&paddr, pid, vaddr);
    fprintf(stdout, "paddr %lu\n", paddr);
    fprintf(stdout, "sizeof(paddr) %lu\n", sizeof(paddr));

    //MAC initialization
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    op.params[0].value.a = paddr;
    op.params[0].value.b = size;
    fprintf(stdout, "op.params[0].value.a = %lu\n", op.params[0].value.a);
    fprintf(stdout, "op.params[0].value.b = %lu\n", op.params[0].value.b);
    fprintf(stdout, "TEEC_InvokeCommand(TA_ATTESTATION_CMD_INITIALIZE)\n");
    res = TEEC_InvokeCommand(&sess, TA_ATTESTATION_CMD_INITIALIZE, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "TEEC_InvokeCommand failed with code "
                        "0x%x origin 0x%x\n", res, err_origin);
        goto exit;
    }
    fprintf(stdout, "MAC initialization successful!\n");

    //MAC attestation
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    op.params[0].value.a = paddr;
    op.params[0].value.b = size;
    res = TEEC_InvokeCommand(&sess, TA_ATTESTATION_CMD_ATTEST, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "TEEC_InvokeCommand failed with code "
                        "0x%x origin 0x%x\n", res, err_origin);
        goto exit;
    }
    else {
        fprintf(stderr, "Attestation successful!\n");
    }

exit:
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return 0;
}
