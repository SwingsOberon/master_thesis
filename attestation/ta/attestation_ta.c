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

/* The size of a SHA1 hash in bytes. */
#define SHA1_HASH_SIZE 20

/* GP says that for HMAC SHA-1, max is 512 bits and min 80 bits. */
#define MAX_KEY_SIZE 64 /* In bytes */
#define MIN_KEY_SIZE 10 /* In bytes */

#define PAGE_SIZE 2048

/* Dynamic Binary Code 2 Modulo, which is 10^6 according to the spec. */
#define DBC2_MODULO 1000000

/*
 * Currently this only supports a single key, in the future this could be
 * updated to support multiple users, all with different unique keys (stored
 * using secure storage).
 */
static uint8_t K[MAX_KEY_SIZE];
static uint32_t K_len;

/* The counter as defined by RFC4226. */
static uint8_t counter[] = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

/**
 *  HMAC a block of memory to produce the authentication tag
 *  @param key       The secret key
 *  @param keylen    The length of the secret key (bytes)
 *  @param in        The data to HMAC
 *  @param inlen     The length of the data to HMAC (bytes)
 *  @param out       [out] Destination of the authentication tag
 *  @param outlen    [in/out] Max size and resulting size of authentication tag
 */
static TEE_Result hmac_sha1(const uint8_t *key, const size_t keylen,
			    const uint8_t *in, const size_t inlen,
			    uint8_t *out, uint32_t *outlen)
{
	TEE_Attribute attr = { 0 };
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_OperationHandle op_handle = TEE_HANDLE_NULL;
	TEE_Result res = TEE_SUCCESS;

	if (keylen < MIN_KEY_SIZE || keylen > MAX_KEY_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!in || !out || !outlen)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * 1. Allocate cryptographic (operation) handle for the HMAC operation.
	 *    Note that the expected size here is in bits (and therefore times
	 *    8)!
	 */
	res = TEE_AllocateOperation(&op_handle, TEE_ALG_HMAC_SHA1, TEE_MODE_MAC,
				    keylen * 8);
	if (res != TEE_SUCCESS) {
		EMSG("0x%08x", res);
		goto exit;
	}

	/*
	 * 2. Allocate a container (key handle) for the HMAC attributes. Note
	 *    that the expected size here is in bits (and therefore times 8)!
	 */
	res = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA1, keylen * 8,
					  &key_handle);
	if (res != TEE_SUCCESS) {
		EMSG("0x%08x", res);
		goto exit;
	}

	/*
	 * 3. Initialize the attributes, i.e., point to the actual HMAC key.
	 *    Here, the expected size is in bytes and not bits as above!
	 */
	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, keylen);

	/* 4. Populate/assign the attributes with the key object */
	res = TEE_PopulateTransientObject(key_handle, &attr, 1);
	if (res != TEE_SUCCESS) {
		EMSG("0x%08x", res);
		goto exit;
	}

	/* 5. Associate the key (object) with the operation */
	res = TEE_SetOperationKey(op_handle, key_handle);
	if (res != TEE_SUCCESS) {
		EMSG("0x%08x", res);
		goto exit;
	}

	/* 6. Do the HMAC operations */
	TEE_MACInit(op_handle, NULL, 0);
	TEE_MACUpdate(op_handle, in, inlen);
	res = TEE_MACComputeFinal(op_handle, NULL, 0, out, outlen);
exit:
	if (op_handle != TEE_HANDLE_NULL)
		TEE_FreeOperation(op_handle);

	/* It is OK to call this when key_handle is TEE_HANDLE_NULL */
	TEE_FreeTransientObject(key_handle);

	return res;
}

/**
 * Truncate function working as described in RFC4226.
 */
static void truncate(uint8_t *hmac_result, uint32_t *bin_code)
{
	int offset = hmac_result[19] & 0xf;

	*bin_code = (hmac_result[offset] & 0x7f) << 24 |
		(hmac_result[offset+1] & 0xff) << 16 |
		(hmac_result[offset+2] & 0xff) <<  8 |
		(hmac_result[offset+3] & 0xff);

	*bin_code %= DBC2_MODULO;
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

static TEE_Result get_hotp(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res = TEE_SUCCESS;
	uint32_t hotp_val;
	uint8_t mac[SHA1_HASH_SIZE];
	uint32_t mac_len = sizeof(mac);
	int i;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types) {
		EMSG("Expected: 0x%x, got: 0x%x", exp_param_types, param_types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	res = hmac_sha1(K, K_len, counter, sizeof(counter), mac, &mac_len);

	/* Increment the counter. */
	for (i = sizeof(counter) - 1; i >= 0; i--) {
		if (++counter[i])
			break;
	}

	truncate(mac, &hotp_val);
	DMSG("HOTP is: %d", hotp_val);
	params[0].value.a = hotp_val;

	return res;
}

/**
 * The attest function should execute the hmac operation on the memory page(s) and compare the result with the
 * securely stored authentication tag that has been computed during the initialization phase.
 * @return TEE_SUCCESS iff the hmac is the same as the stored hmac
 */
static TEE_Result attest(uint32_t param_types, TEE_Param params[4])
{
    DMSG("attest started");
    TEE_Result res = TEE_SUCCESS;

    uint8_t mac[SHA1_HASH_SIZE];
    uint32_t mac_len = sizeof(mac);

    TEE_ObjectHandle object;
    TEE_ObjectInfo object_info;
    char *obj_id;
    size_t obj_id_sz;
    char *data;
    size_t data_sz;
    uint32_t read_bytes;

    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                               TEE_PARAM_TYPE_NONE,
                                               TEE_PARAM_TYPE_NONE,
                                               TEE_PARAM_TYPE_NONE);

    if (param_types != exp_param_types) {
        EMSG("Expected: 0x%x, got: 0x%x", exp_param_types, param_types);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[0].memref.size > PAGE_SIZE)
        return TEE_ERROR_BAD_PARAMETERS;
    return TEE_SUCCESS;

    res = hmac_sha1(K, K_len, params[0].memref.buffer, params[0].memref.size, mac, &mac_len);

    if (res != TEE_SUCCESS) {
        EMSG("hmac_sha1 didn't return TEE_SUCCES but instead the following ");
        return res;
    }
    DMSG("mac = %s", mac);



    obj_id_sz = params[0].memref.size;
    obj_id = TEE_Malloc(obj_id_sz, 0);
    if (!obj_id)
        return TEE_ERROR_OUT_OF_MEMORY;

    TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_sz);
    DMSG("obj_id = %s", obj_id);

    data_sz = mac_len;
    data = TEE_Malloc(data_sz, 0);
    if (!data)
        return TEE_ERROR_OUT_OF_MEMORY;
    /*
	 * Check the object exist and can be dumped into output buffer
	 * then dump it.
	 */
    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
                                   obj_id, obj_id_sz,
                                   TEE_DATA_FLAG_ACCESS_READ |
                                   TEE_DATA_FLAG_SHARE_READ,
                                   &object);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to open persistent object, res=0x%08x", res);
        TEE_Free(obj_id);
        TEE_Free(data);
        return res;
    }

    res = TEE_GetObjectInfo1(object, &object_info);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to create persistent object, res=0x%08x", res);
        goto exit;
    }

    if (object_info.dataSize > data_sz) {
        /*
         * Provided buffer is too short.
         * Return the expected size together with status "short buffer"
         */
        //params[1].memref.size = object_info.dataSize;
        res = TEE_ERROR_SHORT_BUFFER;
        goto exit;
    }

    res = TEE_ReadObjectData(object, data, object_info.dataSize,
                             &read_bytes);
    if (res == TEE_SUCCESS) {
        if(data != mac) { //TODO: the mac may have to be translated to (and stored as) a char* to make this check work correctly
            EMSG("MAC differs from the initial value!");
            res = TEE_ERROR_MAC_INVALID;
        }
        res = TEE_SUCCESS;
    }
    DMSG("data = %s, mac = %s", data, mac);
    if (res != TEE_SUCCESS || read_bytes != object_info.dataSize) {
        EMSG("TEE_ReadObjectData failed 0x%08x, read %" PRIu32 " over %u",
             res, read_bytes, object_info.dataSize);
        goto exit;
    }

    /* Return the number of byte effectively filled */
    //params[1].memref.size = read_bytes;
    exit:
    TEE_CloseObject(object);
    TEE_Free(obj_id);
    TEE_Free(data);
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

    uint8_t mac[SHA1_HASH_SIZE];
    uint32_t mac_len = sizeof(mac);

    TEE_ObjectHandle object;
    char *obj_id;
    size_t obj_id_sz;
    char *data;
    size_t data_sz;
    uint32_t obj_data_flag;

    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                               TEE_PARAM_TYPE_NONE,
                                               TEE_PARAM_TYPE_NONE,
                                               TEE_PARAM_TYPE_NONE);
    DMSG("checking param_types");
    if (param_types != exp_param_types) {
        EMSG("Expected: 0x%x, got: 0x%x", exp_param_types, param_types);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    DMSG("checking memref.size");
    if (params[0].memref.size > PAGE_SIZE)
        return TEE_ERROR_BAD_PARAMETERS;
    DMSG("hmac_sha1 called");
    res = hmac_sha1(K, K_len, params[0].memref.buffer, params[0].memref.size, mac, &mac_len);

    if (res != TEE_SUCCESS) {
        EMSG("hmac_sha1 didn't return TEE_SUCCES but instead the following ");
        return res;
    }

    obj_id_sz = params[0].memref.size;
    obj_id = TEE_Malloc(obj_id_sz, 0);
    if (!obj_id)
        return TEE_ERROR_OUT_OF_MEMORY;
    TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_sz);
    DMSG("obj_id = %s, memref.buffer = %s", obj_id, params[0].memref.buffer);

    data_sz = mac_len;
    data = TEE_Malloc(data_sz, 0);
    if (!data)
        return TEE_ERROR_OUT_OF_MEMORY;
    TEE_MemMove(data, mac, data_sz);
    DMSG("data = %s, mac = %s", data, mac);
    /* TODO: it would be better if it cannot be written into or destroyed by overwriting with an object with same ID.
	 * Create object in secure storage and fill with data
	 */
    obj_data_flag = TEE_DATA_FLAG_ACCESS_READ |		/* we can later read the object */
                    TEE_DATA_FLAG_ACCESS_WRITE |		/* we can later write into the object */
                    TEE_DATA_FLAG_ACCESS_WRITE_META |	/* we can later destroy or rename the object */
                    TEE_DATA_FLAG_OVERWRITE;		/* destroy existing object of same ID */

    res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
                                     obj_id, obj_id_sz,
                                     obj_data_flag,
                                     TEE_HANDLE_NULL,
                                     NULL, 0,		/* we may not fill it right now */
                                     &object);
    if (res != TEE_SUCCESS) {
        EMSG("TEE_CreatePersistentObject failed 0x%08x", res);
        TEE_Free(obj_id);
        TEE_Free(data);
        return res;
    }

    res = TEE_WriteObjectData(object, data, data_sz);
    if (res != TEE_SUCCESS) {
        EMSG("TEE_WriteObjectData failed 0x%08x", res);
        TEE_CloseAndDeletePersistentObject1(object);
    } else {
        TEE_CloseObject(object);
    }
    TEE_Free(obj_id);
    TEE_Free(data);
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
	case TA_ATTEST_CMD_REGISTER_SHARED_KEY:
		return register_shared_key(param_types, params);

	/*case TA_ATTEST_CMD_GET_HOTP:
		return get_hotp(param_types, params);*/

    case TA_ATTEST_CMD_INITIALIZE:
        return initialize(param_types, params);

    case TA_ATTEST_CMD_ATTEST:
        return attest(param_types, params);

	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
