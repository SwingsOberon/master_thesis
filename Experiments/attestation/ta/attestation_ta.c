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
    DMSG("params[0].value.a = %lu", params[0].value.a);
    // ------------ Close Session to PTA ---------
    DMSG("closing session for PTA");
    TEE_CloseTASession(pta_session);
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

    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                               TEE_PARAM_TYPE_VALUE_INPUT,
                                               TEE_PARAM_TYPE_NONE,
                                               TEE_PARAM_TYPE_NONE);
    DMSG("checking param_types\n");
    if (param_types != exp_param_types) {
        EMSG("Expected: 0x%x, got: 0x%x", exp_param_types, param_types);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    res = measure_pta_call(param_types, params, MEASUREMENT_CMD_ATTEST);
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

    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                               TEE_PARAM_TYPE_VALUE_INPUT,
                                               TEE_PARAM_TYPE_NONE,
                                               TEE_PARAM_TYPE_NONE);
    DMSG("checking param_types\n");
    if (param_types != exp_param_types) {
        EMSG("Expected: 0x%x, got: 0x%x", exp_param_types, param_types);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    res = measure_pta_call(param_types, params, MEASUREMENT_CMD_INIT);
    DMSG("back in initialize");
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

    case TA_ATTESTATION_CMD_INITIALIZE:
        return initialize(param_types, params);

    case TA_ATTESTATION_CMD_ATTEST:
        return attest(param_types, params);

	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
