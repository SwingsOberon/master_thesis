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

	// Initialize a context connecting us to the TEE
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

    pid_t pid = get_proc_pid();
    uint64_t vaddr;
    size_t size;
    get_proc_vaddr(&vaddr, &size);
    fprintf(stdout, "vaddr = %lu\n", vaddr);
    fprintf(stdout, "size = %lu\n", size);
    fprintf(stdout, "sizeof(uintptr_t) = %lu\n", sizeof(uintptr_t));
    {
        uintptr_t paddr[size];
        virt_to_phys_user(paddr, pid, vaddr, size);
        for (uint64_t i = 0; i < size; i++) fprintf(stdout, "i = %u, paddr[i] = %lu\n", i, paddr[i]);
        fprintf(stdout, "sizeof(paddr) %lu\n", sizeof(paddr));
        fprintf(stdout, "size %lu\n", size);

        //MAC initialization
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE);
        op.params[0].tmpref.buffer = paddr;
        op.params[0].tmpref.size = sizeof(paddr);
        op.params[1].value.a = size;
        //for (uint32_t i = 0; i < size; i++) fprintf(stdout, "i = %u, paddr[i] = %lu\n", i, op.params[0].tmpref.buffer[i]);
        fprintf(stdout, "op.params[0].tmpref.size = %lu\n", op.params[0].tmpref.size);
        fprintf(stdout, "op.params[0].value.b = %lu\n", op.params[1].value.a);
        fprintf(stdout, "TEEC_InvokeCommand(TA_ATTESTATION_CMD_INITIALIZE)\n");
        res = TEEC_InvokeCommand(&sess, TA_ATTESTATION_CMD_INITIALIZE, &op, &err_origin);
        if (res != TEEC_SUCCESS) {
            fprintf(stderr, "TEEC_InvokeCommand failed with code "
                            "0x%x origin 0x%x\n", res, err_origin);
            goto exit;
        }
        fprintf(stdout, "MAC initialization successful!\n");

        //MAC attestation
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE);
        op.params[0].tmpref.buffer = paddr;
        op.params[0].tmpref.size = sizeof(paddr);
        op.params[1].value.a = size;
        res = TEEC_InvokeCommand(&sess, TA_ATTESTATION_CMD_ATTEST, &op, &err_origin);
        if (res != TEEC_SUCCESS) {
            fprintf(stderr, "TEEC_InvokeCommand failed with code "
                            "0x%x origin 0x%x\n", res, err_origin);
            goto exit;
        }
        fprintf(stderr, "Attestation successful!\n");
    }
exit:
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return 0;
}
