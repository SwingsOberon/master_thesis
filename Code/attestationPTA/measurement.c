#include <stdio.h>
#include <bitstring.h>
#include <kernel/pseudo_ta.h>
#include <crypto/crypto.h>
#include <string.h>
#include <stdlib.h>
#include <tee_api_types.h>
#include <measurement.h>
#include <mm/core_memprot.h>
#include <tee_internal_api_extensions.h>
#include <tee_internal_api.h>
#include <tee_api.h>
#include <tee/tadb.h>
#include <tee/tee_pobj.h>



#define PAGE_SIZE 4096

/* The size of a SHA1 hash in bytes. */
#define SHA1_HASH_SIZE 24

/* GP says that for HMAC SHA-1, max is 512 bits and min 80 bits. */
#define MAX_KEY_SIZE 64 /* In bytes */
#define MIN_KEY_SIZE 10 /* In bytes */

/* Dynamic Binary Code 2 Modulo, which is 10^6 according to the spec. */
#define DBC2_MODULO 1000000


#define TADB_MAX_BUFFER_SIZE	(64U * 1024)

#define TADB_AUTH_ENC_ALG	TEE_ALG_AES_GCM
#define TADB_IV_SIZE		TEE_AES_BLOCK_SIZE
#define TADB_TAG_SIZE		TEE_AES_BLOCK_SIZE
#define TADB_KEY_SIZE		TEE_AES_MAX_KEY_SIZE


struct tee_tadb_dir {
	const struct tee_file_operations *ops;
	struct tee_file_handle *fh;
	int nbits;
	bitstr_t *files;
};

static const char tadb_obj_id[] = "ta.db";

struct tee_tadb_dir *dir;

static TEE_Result tadb_open(struct tee_tadb_dir **db_ret)
{
	TEE_Result res;
	struct tee_tadb_dir *db = calloc(1, sizeof(*db));
	struct tee_pobj po = {
		.obj_id = (void *)tadb_obj_id,
		.obj_id_len = sizeof(tadb_obj_id)
	};

	if (!db)
		return TEE_ERROR_OUT_OF_MEMORY;

	db->ops = tee_svc_storage_file_ops(TEE_STORAGE_PRIVATE);

	res = db->ops->open(&po, NULL, &db->fh);
	if (res == TEE_ERROR_ITEM_NOT_FOUND){
    res = db->ops->create(&po, false, NULL, 0, NULL, 0, NULL, 0,
				      &db->fh);
    DMSG("tadb_open created new file\n");
    }
		

	if (res)
		free(db);
	else
		*db_ret = db;

	return res;
}

static TEE_Result hash_nw_memory(void *va, size_t size, uint8_t *hash)
{
	TEE_Result res = TEE_SUCCESS;
	void *ctx = NULL;

    DMSG("cmd_hash_nw_memory started\n");
    DMSG("va = %lu\n", va);
    DMSG("size = %lu\n", size);

	res = crypto_hash_alloc_ctx(&ctx, TEE_ALG_SHA256);
	if (res)
		return res;

	res = crypto_hash_init(ctx);
	if (res)
		goto out;

	/* Hash regions in order */
	res = crypto_hash_update(ctx, (uint8_t *)va, size);
		if (res)
			goto out;

	res = crypto_hash_final(ctx, hash, TEE_SHA256_HASH_SIZE);
    
    DMSG("hash = %hhn\n", hash);    
    DMSG("hash content = \n");    
    DMSG("%02X%02X%02X%02X%02X%02X%02X%02X", hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7]);
    DMSG("hash size = %lu", sizeof hash);

out:
	crypto_hash_free_ctx(ctx);
	return res;
}

static TEE_Result store_hash(uint8_t *hash, size_t len) 
{
    TEE_Result res = TEE_SUCCESS;
    size_t pos = 0;
    uint8_t buf[len];
    
    DMSG("store_hash started\n");
    DMSG("len = %lu", len);

    //Opening or creating the tadb_dir and a file
    DMSG("tadb_open call\n");
    res = tadb_open(&dir);
    if (res != TEE_SUCCESS) {
        EMSG("tadb_open didn't return TEE_SUCCES but instead the following ");
        return res;
    }
    DMSG("hash content = \n");    
    DMSG("%02X%02X%02X%02X%02X%02X%02X%02X", hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7]);

    //Writing to the file in the tadb_dir
    DMSG("dir->ops->write call\n");
    res = dir->ops->write(dir->fh, pos, hash, len);
    if (res != TEE_SUCCESS) {
        EMSG("dir->ops->write didn't return TEE_SUCCES but instead the following ");
        return res;
    }

    //Reading from the file in the tadb_dir
    DMSG("dir->ops->read call\n");
    res = dir->ops->read(dir->fh, pos, &buf, &len);
    if (res != TEE_SUCCESS) {
        EMSG("dir->ops->read didn't return TEE_SUCCES but instead the following ");
        return res;
    }
    DMSG("buf content = \n");    
    DMSG("%02X%02X%02X%02X%02X%02X%02X%02X", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]);

    return res;
}

static TEE_Result read_init(uint8_t *init, size_t len) 
{
    TEE_Result res = TEE_SUCCESS;
    size_t pos = 0;
    
    DMSG("read_init started\n");
    DMSG("len = %lu", len);

    //Opening or creating the tadb_dir and a file
    DMSG("tadb_open call\n");
    res = tadb_open(&dir);
    if (res != TEE_SUCCESS) {
        EMSG("tadb_open didn't return TEE_SUCCES but instead the following ");
        return res;
    }

    //Reading from the file in the tadb_dir
    DMSG("dir->ops->read call\n");
    res = dir->ops->read(dir->fh, pos, init, &len);
    if (res != TEE_SUCCESS) {
        EMSG("dir->ops->read didn't return TEE_SUCCES but instead the following ");
        return res;
    }
    

    return res;
}


static TEE_Result init(uint32_t param_types, TEE_Param params[4])
{
    TEE_Result res = TEE_SUCCESS;
    paddr_t pa = (paddr_t)params[1].value.a;
    size_t len = PAGE_SIZE;
    uint8_t mac[TEE_SHA256_HASH_SIZE];
    uint32_t mac_len = sizeof(mac);

    //Creating the memory mapping of the physical address
    core_mmu_add_mapping(MEM_AREA_RAM_NSEC, pa, len);
    DMSG("core_mmu_mapping executed\n");
    //Translating the physical address into the newly created secure world virtual address
    uint64_t* va = phys_to_virt(pa, MEM_AREA_RAM_NSEC, len);
    DMSG("phys_to_virt executed\n");
    if (va == NULL) {
        DMSG("phys_to_virt returned NULL");
        return res;
    }
    DMSG("va = %lu\n", va);
    
	//Hashing the virtual address range
    res = hash_nw_memory(va, len, mac);
    if (res != TEE_SUCCESS) {
        EMSG("hash_nw_memory didn't return TEE_SUCCES but instead the following ");
        return res;
    }

    DMSG("mac content = \n");    
    DMSG("%02X%02X%02X%02X%02X%02X%02X%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], mac[6], mac[7]);
    DMSG("mac size = %lu", sizeof mac);

    res = store_hash(mac, mac_len);

    return res;
}

static TEE_Result attest(uint32_t param_types, TEE_Param params[4])
{
    TEE_Result res = TEE_SUCCESS;
    paddr_t pa = (paddr_t)params[1].value.a;
    size_t len = PAGE_SIZE;
    uint8_t mac[TEE_SHA256_HASH_SIZE];
    uint32_t mac_len = sizeof(mac);
    uint8_t init[TEE_SHA256_HASH_SIZE];
    uint32_t init_len = sizeof(init);

    //Creating the memory mapping of the physical address
    core_mmu_add_mapping(MEM_AREA_RAM_NSEC, pa, len);
    DMSG("core_mmu_mapping executed\n");
    //Translating the physical address into the newly created secure world virtual address
    uint64_t* va = phys_to_virt(pa, MEM_AREA_RAM_NSEC, len);
    DMSG("phys_to_virt executed\n");
    if (va == NULL) {
        DMSG("phys_to_virt returned NULL");
        return res;
    }
    DMSG("va = %lu\n", va);
    
	//Hashing the virtual address range
    res = hash_nw_memory(va, len, mac);
    if (res != TEE_SUCCESS) {
        EMSG("hash_nw_memory didn't return TEE_SUCCES but instead the following ");
        return res;
    }

    DMSG("mac content = \n");    
    DMSG("%02X%02X%02X%02X%02X%02X%02X%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], mac[6], mac[7]);
    DMSG("mac size = %lu", sizeof mac);

    res = read_init(init, init_len);
    DMSG("init content = \n");    
    DMSG("%02X%02X%02X%02X%02X%02X%02X%02X", init[0], init[1], init[2], init[3], init[4], init[5], init[6], init[7]);

    bool equal = true;
    for (int i = 0; i < init_len; i++) {
        if (init[i] != mac[i]) equal = false;
    }
    if (!equal) res = TEE_ERROR_MAC_INVALID; //0xFFFF3071

    return res;
}

static TEE_Result invoke_command(void *psess __unused,
				 uint32_t cmd, uint32_t ptypes,
				 TEE_Param params[4])
{

	DMSG("Measurement-PTA got called (cmd): %d", cmd);
	switch (cmd) {
	case MEASUREMENT_CMD_INIT:
		DMSG("MEASUREMENT_CMD_INIT has been called");
		return init(ptypes, params);
    case MEASUREMENT_CMD_ATTEST:
		DMSG("MEASUREMENT_CMD_ATTEST has been called");
		return attest(ptypes, params);

	default:
		break;
	}
	return TEE_ERROR_BAD_PARAMETERS;
}

pseudo_ta_register(.uuid = MEASUREMENT_UUID, .name = "measurement.pta",
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);
