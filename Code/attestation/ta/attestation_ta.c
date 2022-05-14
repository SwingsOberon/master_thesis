/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <attestation_ta.h>
#include <string.h>
#include <tee_internal_api_extensions.h>
#include <tee_internal_api.h>
#include <measurement.h>

/* The size of a SHA1 hash in bytes. */
#define SHA1_HASH_SIZE 24

/* GP says that for HMAC SHA-1, max is 512 bits and min 80 bits. */
#define MAX_KEY_SIZE 64 /* In bytes */
#define MIN_KEY_SIZE 10 /* In bytes */

/* Dynamic Binary Code 2 Modulo, which is 10^6 according to the spec. */
#define DBC2_MODULO 1000000

/*
 * Currently this only supports a single key, in the future this could be
 * updated to support multiple users, all with different unique keys (stored
 * using secure storage).
 */
static uint8_t K[MAX_KEY_SIZE];
static uint32_t K_len;

static TEE_Result measure_pta_call(uint32_t param_types, TEE_Param params[4], uint32_t cmd){
    // ------------ Call PTA ---------**************************************************
    DMSG("measure_pta_call started");
    TEE_Result res = TEE_SUCCESS;
    TEE_TASessionHandle pta_session = TEE_HANDLE_NULL;
    TEE_UUID uuid = MEASUREMENT_UUID;
    uint32_t ret_origin = 0;

    // ------------ Open Session to PTA ---------
    DMSG("opening session for PTA");
    res = TEE_OpenTASession(&uuid, 0, 0, NULL, &pta_session,
                            &ret_origin);
    if (res != TEE_SUCCESS)
        return res;

    // ------------ Invoke command at PTA (get_module key) ---------
    DMSG("invoking command at PTA");

    res = TEE_InvokeTACommand(pta_session, 0, cmd,
                              param_types, params, &ret_origin);
    if (res != TEE_SUCCESS)
        return res;
    DMSG("params[1].value.a = %lu", params[1].value.a);
    // ------------ Close Session to PTA ---------
    DMSG("closing session for PTA");
    TEE_CloseTASession(pta_session);
    return res;
}

static TEE_Result register_shared_key(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res = TEE_SUCCESS;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types) {
		EMSG("Expected: 0x%x, got: 0x%x", exp_param_types, param_types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[0].memref.size > sizeof(K))
		return TEE_ERROR_BAD_PARAMETERS;

	memset(K, 0, sizeof(K));
	memcpy(K, params[0].memref.buffer, params[0].memref.size);

	K_len = params[0].memref.size;
	DMSG("Got shared key %s (%u bytes).", K, params[0].memref.size);

	return res;
}

/**
 * The attest function should execute the hmac operation on the memory page(s) and compare the result with the
 * securely stored authentication tag that has been computed during the initialization phase.
 * @return TEE_SUCCESS iff the hmac is the same as the stored hmac
 */
static TEE_Result attest(uint32_t param_types, TEE_Param params[4])
{
    DMSG("attest started\n");
    TEE_Result res = TEE_SUCCESS;

    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                                               TEE_PARAM_TYPE_NONE,
                                               TEE_PARAM_TYPE_NONE,
                                               TEE_PARAM_TYPE_NONE);
    DMSG("checking param_types\n");
    if (param_types != exp_param_types) {
        EMSG("Expected: 0x%x, got: 0x%x", exp_param_types, param_types);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t paddr = params[0].value.a;
    size_t len = params[0].value.b;

    uint32_t pta_param_types = TEE_PARAM_TYPES( TEE_PARAM_TYPE_VALUE_INPUT,
                                                TEE_PARAM_TYPE_VALUE_INPUT,
                                                TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    TEE_Param pta_params[4];
    pta_params[0].value.a = K;
    pta_params[0].value.b = K_len;
    pta_params[1].value.a = params[0].value.a;
    pta_params[1].value.b = params[0].value.b;

    res = measure_pta_call(pta_param_types, pta_params, MEASUREMENT_CMD_ATTEST);
    EMSG("back in attest");
    if (res != TEE_SUCCESS) {
        EMSG("measure_pta_call didn't return TEE_SUCCES but instead the following ");
        return res;
    }

    return res;
}

/**
 * The initialize function executes the hmac operation on a memory page and stores the result in secure memory.
 * This enables the attest function to later compare this (initial, correct) result with the results during run-time.
 * It would be optimal if this is done right after installing/updating an application this way there is a minimal window
 * for possible attackers to manipulate the code of the application.
 * @return TEE_SUCCESS iff the memory was accessible and the mac tag was safely stored in secure memory
 */
static TEE_Result initialize(uint32_t param_types, TEE_Param params[4])
{
    DMSG("initialize started");
    TEE_Result res = TEE_SUCCESS;

    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                                               TEE_PARAM_TYPE_NONE,
                                               TEE_PARAM_TYPE_NONE,
                                               TEE_PARAM_TYPE_NONE);
    DMSG("checking param_types\n");
    if (param_types != exp_param_types) {
        EMSG("Expected: 0x%x, got: 0x%x", exp_param_types, param_types);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t paddr = params[0].value.a;
    size_t len = params[0].value.b;

    uint32_t pta_param_types = TEE_PARAM_TYPES( TEE_PARAM_TYPE_VALUE_INPUT,
                                                TEE_PARAM_TYPE_VALUE_INPUT,
                                                TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    TEE_Param pta_params[4];
    pta_params[0].value.a = K;
    pta_params[0].value.b = K_len;
    pta_params[1].value.a = params[0].value.a;
    pta_params[1].value.b = params[0].value.b;

    res = measure_pta_call(pta_param_types, pta_params, MEASUREMENT_CMD_INIT);
    EMSG("back in initialize");
    if (res != TEE_SUCCESS) {
        EMSG("measure_pta_call didn't return TEE_SUCCES but instead the following ");
        return res;
    }

    return res;
}

/*******************************************************************************
 * Mandatory TA functions.
 ******************************************************************************/
TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
				    TEE_Param __unused params[4],
				    void __unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __unused *sess_ctx)
{
}

TEE_Result TA_InvokeCommandEntryPoint(void __unused *sess_ctx,
				      uint32_t cmd_id,
				      uint32_t param_types, TEE_Param params[4])
{
	switch (cmd_id) {
	case TA_ATTESTATION_CMD_REGISTER_SHARED_KEY:
		return register_shared_key(param_types, params);

    case TA_ATTESTATION_CMD_INITIALIZE:
        return initialize(param_types, params);

    case TA_ATTESTATION_CMD_ATTEST:
        return attest(param_types, params);

	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
