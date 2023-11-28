/* CC0 license applied, see LICENCE.md */

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>

#include "prov/err.h"
#include "prov/num.h"
#include "v_params.h"

#include "ascon128/api.h"
#include "ascon128/ascon.h"
#include "ascon128/crypto_aead.h"
#include "ascon128/permutations.h"
#include "ascon128/printstate.h"
#include "ascon128/word.h"

/*********************************************************************
 *
 *  Errors
 *
 *****/

/* The error reasons used here */
#define VIGENERE_NO_KEYLEN_SET          1
#define VIGENERE_ONGOING_OPERATION      2
#define VIGENERE_INCORRECT_KEYLEN       3
#define VIGENERE_INCORRECT_IVLEN        4
#define VIGENERE_INCORRECT_TAGLEN       5
#define VIGENERE_NO_DATA                6
static const OSSL_ITEM reason_strings[] = {
    { VIGENERE_NO_KEYLEN_SET, "no key length has been set" },
    { VIGENERE_ONGOING_OPERATION, "an operation is underway" },
    { VIGENERE_INCORRECT_KEYLEN, "incorrect key length" },
    { VIGENERE_INCORRECT_IVLEN, "incorrect iv length" },
    { VIGENERE_INCORRECT_TAGLEN, "incorrect tag length" },
    { 0, NULL }
};

/*********************************************************************
 *
 *  Provider context
 *
 *****/

struct provider_ctx_st {
    const OSSL_CORE_HANDLE *core_handle;
    struct proverr_functions_st *proverr_handle;
};

static void provider_ctx_free(struct provider_ctx_st *ctx)
{
    if (ctx != NULL)
        proverr_free_handle(ctx->proverr_handle);
    free(ctx);
}

static struct provider_ctx_st *provider_ctx_new(const OSSL_CORE_HANDLE *core,
                                                const OSSL_DISPATCH *in)
{
    struct provider_ctx_st *ctx;

    if ((ctx = malloc(sizeof(*ctx))) != NULL
        && (ctx->proverr_handle = proverr_new_handle(core, in)) != NULL) {
        ctx->core_handle = core;
    } else {
        provider_ctx_free(ctx);
        ctx = NULL;
    }
    return ctx;
}

/*********************************************************************
 *
 *  The implementation itself
 *
 *****/

/*
 * Forward declarations to ensure we get signatures right.  All the
 * OSSL_FUNC_* types come from <openssl/core_dispatch.h>
 */
static OSSL_FUNC_provider_query_operation_fn vigenere_prov_operation;
static OSSL_FUNC_provider_get_params_fn vigenere_prov_get_params;
static OSSL_FUNC_provider_get_reason_strings_fn vigenere_prov_get_reason_strings;

static OSSL_FUNC_cipher_newctx_fn vigenere_newctx;
static OSSL_FUNC_cipher_encrypt_init_fn vigenere_encrypt_init;
static OSSL_FUNC_cipher_decrypt_init_fn vigenere_decrypt_init;
static OSSL_FUNC_cipher_update_fn vigenere_update;
static OSSL_FUNC_cipher_final_fn vigenere_final;
static OSSL_FUNC_cipher_dupctx_fn vigenere_dupctx;
static OSSL_FUNC_cipher_freectx_fn vigenere_freectx;
static OSSL_FUNC_cipher_get_params_fn vigenere_get_params;
static OSSL_FUNC_cipher_gettable_params_fn vigenere_gettable_params;
static OSSL_FUNC_cipher_set_ctx_params_fn vigenere_set_ctx_params;
static OSSL_FUNC_cipher_get_ctx_params_fn vigenere_get_ctx_params;
static OSSL_FUNC_cipher_settable_ctx_params_fn vigenere_settable_ctx_params;
static OSSL_FUNC_cipher_gettable_ctx_params_fn vigenere_gettable_ctx_params;

#define DEFAULT_KEYLENGTH 16    /* amount of bytes == 128 bits */
#define BLOCKSIZE 8             /* amount of bytes */

/* Helper function to determine the key length */
static size_t keylen()
{
    /*
     * Give the user a chance to decide a default.
     * With 'openssl enc', this is the only viable way for the user
     * to set an arbitrary key length.
     * Note that the length is expressed in bytes.
     */
    const char *user_keyl = getenv("VIGENERE_KEYLEN");
    size_t keyl = DEFAULT_KEYLENGTH;

    if (user_keyl != NULL)
        keyl = strtoul(user_keyl, NULL, 0);
    return keyl;
}

/*
 * The context used throughout all these functions.
 */
struct vigenere_ctx_st {
    struct provider_ctx_st *provctx;

    size_t keyl;                /* The configured length of the key */

    unsigned char *key;         /* A copy of the key */
    size_t keysize;             /* Size of the key currently used */
    size_t keypos;              /* The current position in the key */
    int enc;                    /* 0 = decrypt, 1 = encrypt */
    int ongoing;                /* 1 = operation has started */
    ascon_state_t s;
    uint64_t K0;
    uint64_t K1;
    size_t ivl;
    size_t tagl;
    unsigned char *tag;
};
#define ERR_HANDLE(ctx) ((ctx)->provctx->proverr_handle)

static void *vigenere_newctx(void *vprovctx)
{
    struct vigenere_ctx_st *ctx = malloc(sizeof(*ctx));

    if (ctx != NULL) {
        memset(ctx, 0, sizeof(*ctx));
        ctx->provctx = vprovctx;
        ctx->keyl = keylen();
        //ascon
        ctx->ivl = CRYPTO_NPUBBYTES;
        ctx->tagl = CRYPTO_ABYTES;
        ctx->tag = malloc(ctx->tagl);

    }
    return ctx;
}

static void vigenere_cleanctx(void *vctx)
{
    struct vigenere_ctx_st *ctx = vctx;

    if (ctx == NULL)
        return;
    free(ctx->key);
    ctx->key = NULL;
    ctx->keypos = 0;
    ctx->enc = 0;
    ctx->ongoing = 0;

    // ascon
    ctx->ivl = 0;
    ctx->tagl = 0;
    free(ctx->tag);
    ctx->K0 = 0;
    ctx->K1 = 0;
    
}

static void *vigenere_dupctx(void *vctx)
{
    struct vigenere_ctx_st *src = vctx;
    struct vigenere_ctx_st *dst = NULL;

    if (src == NULL
        || (dst = vigenere_newctx(NULL)) == NULL)

    dst->provctx = src->provctx;
    dst->provctx->proverr_handle =
        proverr_dup_handle(src->provctx->proverr_handle);
    dst->keyl = src->keyl;

    if (src->key != NULL) {
        if ((dst->key = malloc(src->keyl)) == NULL) {
            vigenere_freectx(dst);
            return NULL;
        }
        memcpy(dst->key, src->key, src->keyl);
    }

    dst->keypos = src->keypos;
    dst->enc = src->enc;
    dst->ongoing = src->ongoing;
    
    //ascon
    dst->s = src->s;
    dst->K0 = src->K0;
    dst->K1 = src->K1;
    memcpy(dst->tag, src->tag, src->tagl);

    return dst;
}

static void vigenere_freectx(void *vctx)
{
    struct vigenere_ctx_st *ctx = vctx;

    ctx->provctx = NULL;
    vigenere_cleanctx(ctx);
    free(ctx);
}

static int vigenere_encrypt_init(void *vctx,
                                 const unsigned char *key,
                                 size_t keyl,
                                 const unsigned char *iv,
                                 size_t ivl,
                                 const OSSL_PARAM params[])
{
    struct vigenere_ctx_st *ctx = vctx;
    
    ctx->enc = 1;
    if (key != NULL) {
        if (keyl == (size_t)-1 || keyl == 0) {
            ERR_raise(ERR_HANDLE(ctx), VIGENERE_NO_KEYLEN_SET);
            return 0;
        }
        free(ctx->key);
        ctx->key = malloc(keyl);
        memcpy(ctx->key, key, keyl);
        ctx->keysize = keyl;
    }
    ctx->keypos = 0;
    ctx->ongoing = 0;

    //ascon
    if (key != NULL && iv != NULL) {
        if (keyl == (size_t)-1 || keyl == 0) {
            ERR_raise(ERR_HANDLE(ctx), VIGENERE_NO_KEYLEN_SET);
            return 0;
        }
        if (ivl != ctx->ivl) {
            ERR_raise(ERR_HANDLE(ctx), VIGENERE_INCORRECT_IVLEN);
            return 0;
        }

         /* load key and nonce */
        ctx->K0 = LOADBYTES(key, 8);
        ctx->K1 = LOADBYTES(key + 8, 8);
        const uint64_t N0 = LOADBYTES(iv, 8);
        const uint64_t N1 = LOADBYTES(iv + 8, 8);

            /* initialize */
        ctx->s.x[0] = ASCON_128_IV;
        ctx->s.x[1] = ctx->K0;
        ctx->s.x[2] = ctx->K1;
        ctx->s.x[3] = N0;
        ctx->s.x[4] = N1;
        printstate("init 1st key xor", &ctx->s);
        P12(&ctx->s);
        ctx->s.x[3] ^= ctx->K0;
        ctx->s.x[4] ^= ctx->K1;
        printstate("init 2nd key xor", &ctx->s);
    }
    return 1;
}

static int vigenere_decrypt_init(void *vctx,
                                 const unsigned char *key,
                                 size_t keyl,
                                 const unsigned char *iv,
                                 size_t ivl,
                                 const OSSL_PARAM params[])
{
    struct vigenere_ctx_st *ctx = vctx;
    size_t i;
    ctx->enc = 0;

    if (key != NULL && iv != NULL) {
        if (keyl == (size_t)-1 || keyl == 0) {
            ERR_raise(ERR_HANDLE(ctx), VIGENERE_NO_KEYLEN_SET);
            return 0;
        }
        free(ctx->key);
        ctx->key = malloc(keyl);
        for (i = 0; i < keyl; i++)
            ctx->key[i] = 256 - key[i];
        ctx->keysize = keyl;
    }
    ctx->keypos = 0;
    ctx->ongoing = 0;

    //ascon
   
    if (key != NULL && iv != NULL) {
        if (keyl == (size_t)-1 || keyl == 0) {
            ERR_raise(ERR_HANDLE(ctx), VIGENERE_NO_KEYLEN_SET);
            return 0;
        }
        if (ivl != ctx->ivl) {
            ERR_raise(ERR_HANDLE(ctx), VIGENERE_INCORRECT_IVLEN);
            return 0;
        }

         /* load key and nonce */
        
        ctx->K0 = LOADBYTES(key, 8);
        ctx->K1 = LOADBYTES(key + 8, 8);
        const uint64_t N0 = LOADBYTES(iv, 8);
        const uint64_t N1 = LOADBYTES(iv + 8, 8);

            /* initialize */
        ctx->s.x[0] = ASCON_128_IV;
        ctx->s.x[1] = ctx->K0;
        ctx->s.x[2] = ctx->K1;
        ctx->s.x[3] = N0;
        ctx->s.x[4] = N1;
        printstate("init 1st key xor", &ctx->s);
        P12(&ctx->s);
        ctx->s.x[3] ^= ctx->K0;
        ctx->s.x[4] ^= ctx->K1;
        printstate("init 2nd key xor", &ctx->s);
    }
    return 1;
}

static int vigenere_update(void *vctx,
                           unsigned char *out, size_t *outl, size_t outsz,
                           const unsigned char *in, size_t inl)
{
    struct vigenere_ctx_st *ctx = vctx;
    //assert(outsz >= inl);
    //assert(out != NULL);
    //assert(outl != NULL);
/*#if 0
    if (outsz < inl || out == NULL)
        return 0;
#else
    if (out == NULL)
        return 0;
#endif*/
    if (out == NULL && in == NULL) {
        ERR_raise(ERR_HANDLE(ctx), VIGENERE_NO_DATA);
    }
    ctx->ongoing = 1;
    *outl = 0;
    unsigned char *originalOut = out;

    //ascon
        /* set ciphertext size */
    unsigned long long clen = inl + CRYPTO_ABYTES;

    // check for AD
    if (out == NULL && inl > 0) {
      /* full associated data blocks */
        while (inl >= ASCON_128_RATE) {
            ctx->s.x[0] ^= LOADBYTES(in, 8);
            printstate("absorb adata", &ctx->s);
            P6(&ctx->s);
            in += ASCON_128_RATE;
            inl -= ASCON_128_RATE;
        }
      /* final associated data block */
        ctx->s.x[0] ^= LOADBYTES(in, inl);
        ctx->s.x[0] ^= PAD(inl);
        printstate("pad adata", &s);
        P6(&ctx->s);
        return 1;
    }

    /* domain separation */
    ctx->s.x[4] ^= 1;
    printstate("domain separation", &ctx->s);

    if (ctx->enc) {
         /* full plaintext blocks */
        while (inl >= ASCON_128_RATE) {
            ctx->s.x[0] ^= LOADBYTES(in, 8);
            STOREBYTES(out, ctx->s.x[0], 8);
            printstate("absorb plaintext", &ctx->s);
            P6(&ctx->s);
            in += ASCON_128_RATE;
            out += ASCON_128_RATE;
            inl -= ASCON_128_RATE;
        }
        /* final plaintext block */
        ctx->s.x[0] ^= LOADBYTES(in, inl);
        STOREBYTES(out, ctx->s.x[0], inl);
        ctx->s.x[0] ^= PAD(inl);
        out += inl;
        printstate("pad plaintext", &ctx->s);
    } else {
       
        //decryption
        while (inl >= ASCON_128_RATE) {
            uint64_t c0 = LOADBYTES(in, 8);
            STOREBYTES(out, ctx->s.x[0] ^ c0, 8);
            ctx->s.x[0] = c0;
            printstate("insert ciphertext", &ctx->s);
            P6(&ctx->s);
            in += ASCON_128_RATE;
            out += ASCON_128_RATE;
            inl -= ASCON_128_RATE;
        }
        /* final ciphertext block */
        uint64_t c0 = LOADBYTES(in, inl);
        STOREBYTES(out, ctx->s.x[0] ^ c0, inl);
        ctx->s.x[0] = CLEARBYTES(ctx->s.x[0], inl);
        ctx->s.x[0] |= c0;
        ctx->s.x[0] ^= PAD(inl);
        out += inl;
        printstate("pad ciphertext", &ctx->s);
    }

    /* finalize */
    ctx->s.x[1] ^= ctx->K0;
    ctx->s.x[2] ^= ctx->K1;
    printstate("final 1st key xor", &ctx->s);
    P12(&ctx->s);
    ctx->s.x[3] ^= ctx->K0;
    ctx->s.x[4] ^= ctx->K1;
    printstate("final 2nd key xor", &ctx->s);
    
    if (ctx->enc) {
        // set tag 
        STOREBYTES(ctx->tag, ctx->s.x[3], 8);
        STOREBYTES(ctx->tag + 8, ctx->s.x[4], 8);        
    }
    
    *outl = clen - CRYPTO_ABYTES;
    return 1;
}

static int vigenere_final(void *vctx,
                          unsigned char *out, size_t *outl, size_t outsz)
{
    struct vigenere_ctx_st *ctx = vctx;
    *outl = 0;
    ctx->ongoing = 0;

    if (!ctx->enc) {
        uint8_t t[16];
        STOREBYTES(t, ctx->s.x[3], 8);
        STOREBYTES(t + 8, ctx->s.x[4], 8);

        // verify tag (should be constant time, check compiler output) 
        int i;
        int result = 0;
        for (i = 0; i < CRYPTO_ABYTES; ++i) result |= ctx->tag[i] ^ t[i];
        result = (((result - 1) >> 8) & 1) - 1;
        
        if (result == 0) {
            return 1;
        } else {
            return -1;
        }
    }
    
    

    return 1;
}

/* Parameters that libcrypto can get from this implementation */
static const OSSL_PARAM *vigenere_gettable_params(void *provctx)
{
    static const OSSL_PARAM table[] = {
        { "blocksize", OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
        { "keylen", OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
        { "ivlen", OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
        { "aead", OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
        { NULL, 0, NULL, 0, 0 },
    };

    return table;
}

static int vigenere_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    int ok = 1;

    for (p = params; p->key != NULL; p++)
        switch (vigenere_params_parse(p->key)) {
        case V_PARAM_blocksize:
            ok &= provnum_set_size_t(p, 1) >= 0;
            break;
        case V_PARAM_keylen:
            ok &= provnum_set_size_t(p, keylen()) >= 0;
            break;
        case V_PARAM_ivlen:
            ok &= provnum_set_size_t(p, CRYPTO_NPUBBYTES) >= 0;
            break;
        case V_PARAM_aead:
            ok &= provnum_set_size_t(p, 1) >= 0;
            break;
        case V_PARAM_taglen:
            ok &= provnum_set_size_t(p, CRYPTO_ABYTES) >= 0;
            break;
        }
    return ok;
}

static const OSSL_PARAM *vigenere_gettable_ctx_params(void *cctx, void *provctx)
{
    static const OSSL_PARAM table[] = {
        { S_PARAM_keylen, OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
        { S_PARAM_ivlen, OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
        { S_PARAM_taglen, OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
        { S_PARAM_tag, OSSL_PARAM_OCTET_STRING, NULL, CRYPTO_ABYTES, 0 },
        { S_PARAM_tlsaadpad, OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
        { NULL, 0, NULL, 0, 0 },
    };

    return table;
}

static int vigenere_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    struct vigenere_ctx_st *ctx = vctx;
    int ok = 1;

    if (ctx->keyl > 0) {
        OSSL_PARAM *p;

        for (p = params; p->key != NULL; p++)
            switch (vigenere_params_parse(p->key)) {
            case V_PARAM_keylen:
                ok &= provnum_set_size_t(p, ctx->keyl) >= 0;
                break;
            case V_PARAM_ivlen:
                ok &= provnum_set_size_t(p, ctx->ivl) >= 0;
                break;
            case V_PARAM_taglen:
                ok &= provnum_set_size_t(p, ctx->tagl) >= 0;
                break;
            case V_PARAM_tag:
                unsigned char *temp_array = p->data;
                p->data = ctx->tag;
                
                for (size_t i = 0; i < CRYPTO_ABYTES; i++)
                {
                    temp_array[i] = ctx->tag[i];
                }
                p->return_size = CRYPTO_ABYTES;
                
                ok &= provnum_set_size_t(p, 1) >= 0;
                break;
            case V_PARAM_tlsaadpad:
                ok &= provnum_set_size_t(p, ctx->tagl) >= 0;
                break;
            }
    }
    return ok;
}

/* Parameters that libcrypto can send to this implementation */
static const OSSL_PARAM *vigenere_settable_ctx_params(void *cctx, void *provctx)
{
    static const OSSL_PARAM table[] = {
        //{ S_PARAM_keylen, OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
        { S_PARAM_tag, OSSL_PARAM_OCTET_STRING, NULL, CRYPTO_ABYTES, 0 },
        { NULL, 0, NULL, 0, 0 },
    };

    return table;
}

static int vigenere_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    struct vigenere_ctx_st *ctx = vctx;
    const OSSL_PARAM *p;
    int ok = 1;

    /*if (ctx->ongoing) {
        ERR_raise(ERR_HANDLE(ctx), VIGENERE_ONGOING_OPERATION);
        return 0;
    }*/

    for (p = params; p->key != NULL; p++)
        switch (vigenere_params_parse(p->key)) {
        /*case V_PARAM_keylen:
        {
            size_t keyl = 0;
            int res = provnum_get_size_t(&keyl, p) >= 0;

            ok &= res;
            if (res)
                ctx->keyl = keyl;
        }*/
        case V_PARAM_tag:
        {
            if (p->data_size != ctx->tagl) {
                ERR_raise(ERR_HANDLE(ctx), VIGENERE_INCORRECT_TAGLEN);
            }
            ctx->tag = p->data;

            //ok &= provnum_set_size_t(p, 1) >= 0;
            
        }
        }
    return ok;
}




/*********************************************************************
 *
 *  Setup
 *
 *****/

typedef void (*funcptr_t)(void);

/* The Vigenere dispatch table */
static const OSSL_DISPATCH vigenere_functions[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (funcptr_t)vigenere_newctx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (funcptr_t)vigenere_encrypt_init },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (funcptr_t)vigenere_decrypt_init },
    { OSSL_FUNC_CIPHER_UPDATE, (funcptr_t)vigenere_update },
    { OSSL_FUNC_CIPHER_FINAL, (funcptr_t)vigenere_final },
    { OSSL_FUNC_CIPHER_DUPCTX, (funcptr_t)vigenere_dupctx },
    { OSSL_FUNC_CIPHER_FREECTX, (funcptr_t)vigenere_freectx },
    { OSSL_FUNC_CIPHER_GET_PARAMS, (funcptr_t)vigenere_get_params },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (funcptr_t)vigenere_gettable_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (funcptr_t)vigenere_get_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
      (funcptr_t)vigenere_gettable_ctx_params },
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (funcptr_t)vigenere_set_ctx_params },
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
      (funcptr_t)vigenere_settable_ctx_params },
    { 0, NULL }
};

/* The table of ciphers this provider offers */
static const OSSL_ALGORITHM vigenere_ciphers[] = {
    { "ascon128:1.3.6.1.4.1.5168.4711.22087.1", "x.author='" AUTHOR "'",
      vigenere_functions },
    { NULL, NULL, NULL }
};

/* The function that returns the appropriate algorithm table per operation */
static const OSSL_ALGORITHM *vigenere_prov_operation(void *vprovctx,
                                                     int operation_id,
                                                     int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_CIPHER:
        return vigenere_ciphers;
    }
    return NULL;
}

static const OSSL_ITEM *vigenere_prov_get_reason_strings(void *provctx)
{
    return reason_strings;
}

static int vigenere_prov_get_params(void *provctx, OSSL_PARAM *params)
{
    OSSL_PARAM *p;
    int ok = 1;

    for(p = params; p->key != NULL; p++)
        switch (vigenere_params_parse(p->key)) {
        case V_PARAM_version:
            *(const void **)p->data = VERSION;
            p->return_size = strlen(VERSION);
            break;
        case V_PARAM_buildinfo:
            if (BUILDTYPE[0] != '\0') {
                *(const void **)p->data = BUILDTYPE;
                p->return_size = strlen(BUILDTYPE);
            }
            break;
        case V_PARAM_author:
            if (AUTHOR[0] != '\0') {
                *(const void **)p->data = AUTHOR;
                p->return_size = strlen(AUTHOR);
            }
            break;
        }
    return ok;
}

/* The function that tears down this provider */
static void vigenere_prov_teardown(void *vprovctx)
{
    provider_ctx_free(vprovctx);
}

/* The base dispatch table */
static const OSSL_DISPATCH provider_functions[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (funcptr_t)vigenere_prov_teardown },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (funcptr_t)vigenere_prov_operation },
    { OSSL_FUNC_PROVIDER_GET_REASON_STRINGS,
      (funcptr_t)vigenere_prov_get_reason_strings },
    { OSSL_FUNC_PROVIDER_GET_PARAMS,
      (funcptr_t)vigenere_prov_get_params },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *core,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **vprovctx)
{
    if ((*vprovctx = provider_ctx_new(core, in)) == NULL)
        return 0;
    *out = provider_functions;
    return 1;
}
