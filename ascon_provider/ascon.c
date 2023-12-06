/* CC0 license applied, see LICENCE.md */

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>

#include "prov/err.h"
#include "prov/num.h"
#include "a_params.h"

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
#define ASCON_NO_KEYLEN_SET 1
#define ASCON_ONGOING_OPERATION 2
#define ASCON_INCORRECT_KEYLEN 3
#define ASCON_INCORRECT_IVLEN 4
#define ASCON_INCORRECT_TAGLEN 5
#define ASCON_NO_DATA 6
static const OSSL_ITEM reason_strings[] = {
    {ASCON_NO_KEYLEN_SET, "no key length has been set"},
    {ASCON_ONGOING_OPERATION, "an operation is underway"},
    {ASCON_INCORRECT_KEYLEN, "incorrect key length"},
    {ASCON_INCORRECT_IVLEN, "incorrect iv length"},
    {ASCON_INCORRECT_TAGLEN, "incorrect tag length"},
    {0, NULL}};

/*********************************************************************
 *
 *  Provider context
 *
 *****/

struct provider_ctx_st
{
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

    if ((ctx = malloc(sizeof(*ctx))) != NULL && (ctx->proverr_handle = proverr_new_handle(core, in)) != NULL)
    {
        ctx->core_handle = core;
    }
    else
    {
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
static OSSL_FUNC_provider_query_operation_fn ascon_prov_operation;
static OSSL_FUNC_provider_get_params_fn ascon_prov_get_params;
static OSSL_FUNC_provider_get_reason_strings_fn ascon_prov_get_reason_strings;

static OSSL_FUNC_cipher_newctx_fn ascon_newctx;
static OSSL_FUNC_cipher_newctx_fn ascon80pq_newctx;
static OSSL_FUNC_cipher_encrypt_init_fn ascon_encrypt_init;
static OSSL_FUNC_cipher_decrypt_init_fn ascon_decrypt_init;
static OSSL_FUNC_cipher_encrypt_init_fn ascon80pq_encrypt_init;
static OSSL_FUNC_cipher_decrypt_init_fn ascon80pq_decrypt_init;
static OSSL_FUNC_cipher_update_fn ascon128a_update;
static OSSL_FUNC_cipher_update_fn ascon128_update;
static OSSL_FUNC_cipher_update_fn ascon80pq_update;
static OSSL_FUNC_cipher_final_fn ascon_final;
static OSSL_FUNC_cipher_dupctx_fn ascon_dupctx;
static OSSL_FUNC_cipher_freectx_fn ascon_freectx;
static OSSL_FUNC_cipher_get_params_fn ascon128_get_params;
static OSSL_FUNC_cipher_get_params_fn ascon128a_get_params;
static OSSL_FUNC_cipher_get_params_fn ascon80pq_get_params;
static OSSL_FUNC_cipher_gettable_params_fn ascon_gettable_params;
static OSSL_FUNC_cipher_set_ctx_params_fn ascon_set_ctx_params;
static OSSL_FUNC_cipher_get_ctx_params_fn ascon_get_ctx_params;
static OSSL_FUNC_cipher_settable_ctx_params_fn ascon_settable_ctx_params;
static OSSL_FUNC_cipher_gettable_ctx_params_fn ascon_gettable_ctx_params;

#define DEFAULT_KEYLENGTH 16 /* amount of bytes == 128 bits */
#define BLOCKSIZE 8          /* amount of bytes */

/*
 * The context used throughout all these functions.
 */

struct ascon_ctx_st
{
    struct provider_ctx_st *provctx;

    size_t keyl; /* The configured length of the key */
    int enc;     /* 0 = decrypt, 1 = encrypt */
    ascon_state_t s;
    uint64_t K0;
    uint64_t K1;
    uint64_t K2; // only used in ascon80pq
    size_t ivl;
    size_t tagl;
    unsigned char *tag;
};

#define ERR_HANDLE(ctx) ((ctx)->provctx->proverr_handle)

static void *ascon_newctx(void *vprovctx)
{
    struct ascon_ctx_st *ctx = malloc(sizeof(*ctx));
    if (ctx != NULL)
    {
        memset(ctx, 0, sizeof(*ctx));
        ctx->provctx = vprovctx;
        ctx->keyl = ASCON_128_KEYBYTES;
        // ascon
        ctx->ivl = CRYPTO_NPUBBYTES;
        ctx->tagl = CRYPTO_ABYTES;
        ctx->tag = malloc(ctx->tagl +10);
    }
    return ctx;
}

static void *ascon80pq_newctx(void *vprovctx)
{
    struct ascon_ctx_st *ctx = malloc(sizeof(*ctx));
    if (ctx != NULL)
    {
        memset(ctx, 0, sizeof(*ctx));
        ctx->provctx = vprovctx;
        ctx->keyl = ASCON_80PQ_KEYBYTES;
        // ascon
        ctx->ivl = CRYPTO_NPUBBYTES;
        ctx->tagl = CRYPTO_ABYTES;
        ctx->tag = malloc(ctx->tagl +10);
    }
    return ctx;
}

static void ascon_cleanctx(void *vctx)
{
    struct ascon_ctx_st *ctx = vctx;
    if (ctx == NULL)
        return;

    ctx->enc = 0;
    // ascon
    ctx->ivl = 0;
    ctx->tagl = 0;

    if (ctx->tag != NULL) {
    free(ctx->tag);
    }
    ctx->K0 = 0;
    ctx->K1 = 0;
}

static void *ascon_dupctx(void *vctx)
{
    struct ascon_ctx_st *src = vctx;
    struct ascon_ctx_st *dst = NULL;

    if (src == NULL || (dst = ascon_newctx(NULL)) == NULL)

        dst->provctx = src->provctx;
    dst->provctx->proverr_handle =
        proverr_dup_handle(src->provctx->proverr_handle);
    dst->keyl = src->keyl;

    dst->enc = src->enc;
    // ascon
    dst->s = src->s;
    dst->K0 = src->K0;
    dst->K1 = src->K1;
    memcpy(dst->tag, src->tag, src->tagl);

    return dst;
}

static void ascon_freectx(void *vctx)
{
    struct ascon_ctx_st *ctx = vctx;
    ctx->provctx = NULL;
    ascon_cleanctx(ctx);
    free(ctx);
}

static int ascon_encrypt_init(void *vctx,
                              const unsigned char *key,
                              size_t keyl,
                              const unsigned char *iv,
                              size_t ivl,
                              const OSSL_PARAM params[])
{
    struct ascon_ctx_st *ctx = vctx;
    ctx->enc = 1;
    if (key != NULL)
    {
        if (keyl == (size_t)-1 || keyl == 0)
        {
            ERR_raise(ERR_HANDLE(ctx), ASCON_NO_KEYLEN_SET);
            return 0;
        }
    }

    // ascon
    if (key != NULL && iv != NULL)
    {
        if (keyl == (size_t)-1 || keyl == 0)
        {
            ERR_raise(ERR_HANDLE(ctx), ASCON_NO_KEYLEN_SET);
            return 0;
        }
        if (ivl != ctx->ivl)
        {
            ERR_raise(ERR_HANDLE(ctx), ASCON_INCORRECT_IVLEN);
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

static int ascon80pq_encrypt_init(void *vctx,
                                  const unsigned char *key,
                                  size_t keyl,
                                  const unsigned char *iv,
                                  size_t ivl,
                                  const OSSL_PARAM params[])
{
    struct ascon_ctx_st *ctx = vctx;
    ctx->enc = 1;
    if (key != NULL)
    {
        if (keyl == (size_t)-1 || keyl == 0)
        {
            ERR_raise(ERR_HANDLE(ctx), ASCON_NO_KEYLEN_SET);
            return 0;
        }
    }

    // ascon
    if (key != NULL && iv != NULL)
    {
        if (keyl == (size_t)-1 || keyl == 0)
        {
            ERR_raise(ERR_HANDLE(ctx), ASCON_NO_KEYLEN_SET);
            return 0;
        }
        if (ivl != ctx->ivl)
        {
            ERR_raise(ERR_HANDLE(ctx), ASCON_INCORRECT_IVLEN);
            return 0;
        }

        /* load key and nonce */
        ctx->K0 = LOADBYTES(key + 0, 4) >> 32;
        ctx->K1 = LOADBYTES(key + 4, 8);
        ctx->K2 = LOADBYTES(key + 12, 8);
        const uint64_t N0 = LOADBYTES(iv, 8);
        const uint64_t N1 = LOADBYTES(iv + 8, 8);

        /* initialize */
        ctx->s.x[0] = ASCON_80PQ_IV | ctx->K0;
        ctx->s.x[1] = ctx->K1;
        ctx->s.x[2] = ctx->K2;
        ctx->s.x[3] = N0;
        ctx->s.x[4] = N1;
        printstate("init 1st key xor", &ctx->s);
        P12(&ctx->s);
        ctx->s.x[2] ^= ctx->K0;
        ctx->s.x[3] ^= ctx->K1;
        ctx->s.x[4] ^= ctx->K2;
        printstate("init 2nd key xor", &ctx->s);
    }
    return 1;
}

static int ascon_decrypt_init(void *vctx,
                              const unsigned char *key,
                              size_t keyl,
                              const unsigned char *iv,
                              size_t ivl,
                              const OSSL_PARAM params[])
{
    struct ascon_ctx_st *ctx = vctx;
    size_t i;
    ctx->enc = 0;
    if (key != NULL && iv != NULL)
    {
        if (keyl == (size_t)-1 || keyl == 0)
        {
            ERR_raise(ERR_HANDLE(ctx), ASCON_NO_KEYLEN_SET);
            return 0;
        }
    }

    // ascon

    if (key != NULL && iv != NULL)
    {
        if (keyl == (size_t)-1 || keyl == 0)
        {
            ERR_raise(ERR_HANDLE(ctx), ASCON_NO_KEYLEN_SET);
            return 0;
        }
        if (ivl != ctx->ivl)
        {
            ERR_raise(ERR_HANDLE(ctx), ASCON_INCORRECT_IVLEN);
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

static int ascon80pq_decrypt_init(void *vctx,
                                  const unsigned char *key,
                                  size_t keyl,
                                  const unsigned char *iv,
                                  size_t ivl,
                                  const OSSL_PARAM params[])
{
    struct ascon_ctx_st *ctx = vctx;
    size_t i;
    ctx->enc = 0;
    if (key != NULL && iv != NULL)
    {
        if (keyl == (size_t)-1 || keyl == 0)
        {
            ERR_raise(ERR_HANDLE(ctx), ASCON_NO_KEYLEN_SET);
            return 0;
        }
    }

    // ascon

    if (key != NULL && iv != NULL)
    {
        if (keyl == (size_t)-1 || keyl == 0)
        {
            ERR_raise(ERR_HANDLE(ctx), ASCON_NO_KEYLEN_SET);
            return 0;
        }
        if (ivl != ctx->ivl)
        {
            ERR_raise(ERR_HANDLE(ctx), ASCON_INCORRECT_IVLEN);
            return 0;
        }

        /* load key and nonce */

        ctx->K0 = LOADBYTES(key + 0, 4) >> 32;
        ctx->K1 = LOADBYTES(key + 4, 8);
        ctx->K2 = LOADBYTES(key + 12, 8);
        const uint64_t N0 = LOADBYTES(iv, 8);
        const uint64_t N1 = LOADBYTES(iv + 8, 8);

        /* initialize */
        ctx->s.x[0] = ASCON_80PQ_IV | ctx->K0;
        ctx->s.x[1] = ctx->K1;
        ctx->s.x[2] = ctx->K2;
        ctx->s.x[3] = N0;
        ctx->s.x[4] = N1;
        printstate("init 1st key xor", &ctx->s);
        P12(&ctx->s);
        ctx->s.x[2] ^= ctx->K0;
        ctx->s.x[3] ^= ctx->K1;
        ctx->s.x[4] ^= ctx->K2;
        printstate("init 2nd key xor", &ctx->s);
    }
    return 1;
}

static int ascon128a_update(void *vctx,
                            unsigned char *out, size_t *outl, size_t outsz,
                            const unsigned char *in, size_t inl)
{
    struct ascon_ctx_st *ctx = vctx;

    if (out == NULL && in == NULL)
    {
        ERR_raise(ERR_HANDLE(ctx), ASCON_NO_DATA);
    }
    *outl = 0;
    unsigned char *originalOut = out;
    // ascon
    /* set ciphertext size */
    unsigned long long clen = inl + CRYPTO_ABYTES;
    // check for AD
    if (out == NULL && inl > 0)
    {
        /* full associated data blocks */
        while (inl >= ASCON_128A_RATE)
        {
            ctx->s.x[0] ^= LOADBYTES(in, 8);
            ctx->s.x[1] ^= LOADBYTES(in + 8, 8);
            printstate("absorb adata", &ctx->s);
            P8(&ctx->s);
            in += ASCON_128A_RATE;
            inl -= ASCON_128A_RATE;
        }
        /* final associated data block */
        if (inl >= 8)
        {
            ctx->s.x[0] ^= LOADBYTES(in, 8);
            ctx->s.x[1] ^= LOADBYTES(in + 8, inl - 8);
            ctx->s.x[1] ^= PAD(inl - 8);
        }
        else
        {
            ctx->s.x[0] ^= LOADBYTES(in, inl);
            ctx->s.x[0] ^= PAD(inl);
        }
        printstate("pad adata", &s);
        P8(&ctx->s);
        return 1;
    }
    /* domain separation */
    ctx->s.x[4] ^= 1;
    printstate("domain separation", &ctx->s);

    if (ctx->enc)
    {
        /* full plaintext blocks */
        while (inl >= ASCON_128A_RATE)
        {
            ctx->s.x[0] ^= LOADBYTES(in, 8);
            ctx->s.x[1] ^= LOADBYTES(in + 8, 8);
            STOREBYTES(out, ctx->s.x[0], 8);
            STOREBYTES(out + 8, ctx->s.x[1], 8);
            printstate("absorb plaintext", &ctx->s);
            P8(&ctx->s);
            in += ASCON_128A_RATE;
            out += ASCON_128A_RATE;
            inl -= ASCON_128A_RATE;
        }
        /* final plaintext block */
        if (inl >= 8)
        {
            ctx->s.x[0] ^= LOADBYTES(in, 8);
            ctx->s.x[1] ^= LOADBYTES(in + 8, inl - 8);
            STOREBYTES(out, ctx->s.x[0], 8);
            STOREBYTES(out + 8, ctx->s.x[1], inl - 8);
            ctx->s.x[1] ^= PAD(inl - 8);
        }
        else
        {
            ctx->s.x[0] ^= LOADBYTES(in, inl);
            STOREBYTES(out, ctx->s.x[0], inl);
            ctx->s.x[0] ^= PAD(inl);
        }
        out += inl;
        printstate("pad plaintext", &ctx->s);
    }
    else
    {
        // decryption
        while (inl >= ASCON_128A_RATE)
        {
            uint64_t c0 = LOADBYTES(in, 8);
            uint64_t c1 = LOADBYTES(in + 8, 8);
            STOREBYTES(out, ctx->s.x[0] ^ c0, 8);
            STOREBYTES(out + 8, ctx->s.x[1] ^ c1, 8);
            ctx->s.x[0] = c0;
            ctx->s.x[1] = c1;
            printstate("insert ciphertext", &ctx->s);
            P8(&ctx->s);
            in += ASCON_128A_RATE;
            out += ASCON_128A_RATE;
            inl -= ASCON_128A_RATE;
        }
        /* final ciphertext block */
        if (inl >= 8)
        {
            uint64_t c0 = LOADBYTES(in, 8);
            uint64_t c1 = LOADBYTES(in + 8, inl - 8);
            STOREBYTES(out, ctx->s.x[0] ^ c0, 8);
            STOREBYTES(out + 8, ctx->s.x[1] ^ c1, inl - 8);
            ctx->s.x[0] = c0;
            ctx->s.x[1] = CLEARBYTES(ctx->s.x[1], inl - 8);
            ctx->s.x[1] |= c1;
            ctx->s.x[1] ^= PAD(inl - 8);
        }
        else
        {
            uint64_t c0 = LOADBYTES(in, inl);
            STOREBYTES(out, ctx->s.x[0] ^ c0, inl);
            ctx->s.x[0] = CLEARBYTES(ctx->s.x[0], inl);
            ctx->s.x[0] |= c0;
            ctx->s.x[0] ^= PAD(inl);
        }
        out += inl;
        printstate("pad ciphertext", &ctx->s);
    }
    /* finalize */
    ctx->s.x[2] ^= ctx->K0;
    ctx->s.x[3] ^= ctx->K1;
    printstate("final 1st key xor", &ctx->s);
    P12(&ctx->s);
    ctx->s.x[3] ^= ctx->K0;
    ctx->s.x[4] ^= ctx->K1;
    printstate("final 2nd key xor", &ctx->s);

    if (ctx->enc)
    {
        // set tag
        STOREBYTES(ctx->tag, ctx->s.x[3], 8);
        STOREBYTES(ctx->tag + 8, ctx->s.x[4], 8);
    }

    *outl = clen - CRYPTO_ABYTES;
    return 1;
}

static int ascon128_update(void *vctx,
                           unsigned char *out, size_t *outl, size_t outsz,
                           const unsigned char *in, size_t inl)
{
    struct ascon_ctx_st *ctx = vctx;
    if (out == NULL && in == NULL)
    {
        ERR_raise(ERR_HANDLE(ctx), ASCON_NO_DATA);
    }
    *outl = 0;
    unsigned char *originalOut = out;

    // ascon
    /* set ciphertext size */
    unsigned long long clen = inl + CRYPTO_ABYTES;

    // check for AD
    if (out == NULL && inl > 0)
    {
        /* full associated data blocks */
        while (inl >= ASCON_128_RATE)
        {
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

    if (ctx->enc)
    {
        /* full plaintext blocks */
        while (inl >= ASCON_128_RATE)
        {
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
    }
    else
    {

        // decryption
        while (inl >= ASCON_128_RATE)
        {
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

    if (ctx->enc)
    {
        // set tag
        STOREBYTES(ctx->tag, ctx->s.x[3], 8);
        STOREBYTES(ctx->tag + 8, ctx->s.x[4], 8);
    }

    *outl = clen - CRYPTO_ABYTES;
    return 1;
}

static int ascon80pq_update(void *vctx,
                            unsigned char *out, size_t *outl, size_t outsz,
                            const unsigned char *in, size_t inl)
{
    struct ascon_ctx_st *ctx = vctx;
    if (out == NULL && in == NULL)
    {
        ERR_raise(ERR_HANDLE(ctx), ASCON_NO_DATA);
    }
    *outl = 0;
    unsigned char *originalOut = out;

    // ascon
    /* set ciphertext size */
    unsigned long long clen = inl + CRYPTO_ABYTES;

    // check for AD
    if (out == NULL && inl > 0)
    {
        /* full associated data blocks */
        while (inl >= ASCON_128_RATE)
        {
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

    if (ctx->enc)
    {
        /* full plaintext blocks */
        while (inl >= ASCON_128_RATE)
        {
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
    }
    else
    {

        // decryption
        while (inl >= ASCON_128_RATE)
        {
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
    ctx->s.x[1] ^= ctx->K0 << 32 | ctx->K1 >> 32;
    ctx->s.x[2] ^= ctx->K1 << 32 | ctx->K2 >> 32;
    ctx->s.x[3] ^= ctx->K2 << 32;
    printstate("final 1st key xor", &ctx->s);
    P12(&ctx->s);
    ctx->s.x[3] ^= ctx->K1;
    ctx->s.x[4] ^= ctx->K2;
    printstate("final 2nd key xor", &ctx->s);

    if (ctx->enc)
    {
        // set tag
        STOREBYTES(ctx->tag, ctx->s.x[3], 8);
        STOREBYTES(ctx->tag + 8, ctx->s.x[4], 8);
    }

    *outl = clen - CRYPTO_ABYTES;
    return 1;
}

static int ascon_final(void *vctx,
                       unsigned char *out, size_t *outl, size_t outsz)
{
    struct ascon_ctx_st *ctx = vctx;
    *outl = 0;
    if (!ctx->enc)
    {
        uint8_t t[16];
        STOREBYTES(t, ctx->s.x[3], 8);
        STOREBYTES(t + 8, ctx->s.x[4], 8);

        // verify tag (should be constant time, check compiler output)
        int i;
        int result = 0;
        for (i = 0; i < CRYPTO_ABYTES; ++i)
            result |= ctx->tag[i] ^ t[i];
        result = (((result - 1) >> 8) & 1) - 1;

        if (result == 0)
        {
            return 1;
        }
        else
        {
            return -1;
        }
    }

    return 1;
}

/* Parameters that libcrypto can get from this implementation */
static const OSSL_PARAM *ascon_gettable_params(void *provctx)
{
    static const OSSL_PARAM table[] = {
        {"blocksize", OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0},
        {"keylen", OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0},
        {"ivlen", OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0},
        {"aead", OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0},
        {NULL, 0, NULL, 0, 0},
    };

    return table;
}

static int ascon128_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    int ok = 1;

    for (p = params; p->key != NULL; p++)
        switch (ascon_params_parse(p->key))
        {
        case V_PARAM_blocksize:
            ok &= provnum_set_size_t(p, ASCON_128_RATE) >= 0;
            break;
        case V_PARAM_keylen:
            ok &= provnum_set_size_t(p, ASCON_128_KEYBYTES) >= 0;
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

static int ascon128a_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    int ok = 1;

    for (p = params; p->key != NULL; p++)
        switch (ascon_params_parse(p->key))
        {
        case V_PARAM_blocksize:
            ok &= provnum_set_size_t(p, ASCON_128A_RATE) >= 0;
            break;
        case V_PARAM_keylen:
            ok &= provnum_set_size_t(p, ASCON_128_KEYBYTES) >= 0;
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

static int ascon80pq_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    int ok = 1;

    for (p = params; p->key != NULL; p++)
        switch (ascon_params_parse(p->key))
        {
        case V_PARAM_blocksize:
            ok &= provnum_set_size_t(p, ASCON_128_RATE) >= 0;
            break;
        case V_PARAM_keylen:
            ok &= provnum_set_size_t(p, ASCON_80PQ_KEYBYTES) >= 0;
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

static const OSSL_PARAM *ascon_gettable_ctx_params(void *cctx, void *provctx)
{
    static const OSSL_PARAM table[] = {
        {S_PARAM_keylen, OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0},
        {S_PARAM_ivlen, OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0},
        {S_PARAM_taglen, OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0},
        {S_PARAM_tag, OSSL_PARAM_OCTET_STRING, NULL, CRYPTO_ABYTES, 0},
        {S_PARAM_tlsaadpad, OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0},
        {NULL, 0, NULL, 0, 0},
    };

    return table;
}

static int ascon_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    struct ascon_ctx_st *ctx = vctx;
    int ok = 1;

    if (ctx->keyl > 0)
    {
        OSSL_PARAM *p;

        for (p = params; p->key != NULL; p++)
            switch (ascon_params_parse(p->key))
            {
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
static const OSSL_PARAM *ascon_settable_ctx_params(void *cctx, void *provctx)
{
    static const OSSL_PARAM table[] = {
        {S_PARAM_tag, OSSL_PARAM_OCTET_STRING, NULL, CRYPTO_ABYTES, 0},
        {NULL, 0, NULL, 0, 0},
    };

    return table;
}

static int ascon_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    struct ascon_ctx_st *ctx = vctx;
    const OSSL_PARAM *p;
    int ok = 1;

    for (p = params; p->key != NULL; p++)
        switch (ascon_params_parse(p->key))
        {
        case V_PARAM_tag:
        {
            if (p->data_size != ctx->tagl)
            {
                ERR_raise(ERR_HANDLE(ctx), ASCON_INCORRECT_TAGLEN);
            }
            memcpy(ctx->tag, p->data, ctx->tagl);
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

/* The Ascon80pq dispatch table */
static const OSSL_DISPATCH ascon80pq_functions[] = {
    {OSSL_FUNC_CIPHER_NEWCTX, (funcptr_t)ascon80pq_newctx},
    {OSSL_FUNC_CIPHER_ENCRYPT_INIT, (funcptr_t)ascon80pq_encrypt_init},
    {OSSL_FUNC_CIPHER_DECRYPT_INIT, (funcptr_t)ascon80pq_decrypt_init},
    {OSSL_FUNC_CIPHER_UPDATE, (funcptr_t)ascon80pq_update},
    {OSSL_FUNC_CIPHER_FINAL, (funcptr_t)ascon_final},
    {OSSL_FUNC_CIPHER_DUPCTX, (funcptr_t)ascon_dupctx},
    {OSSL_FUNC_CIPHER_FREECTX, (funcptr_t)ascon_freectx},
    {OSSL_FUNC_CIPHER_GET_PARAMS, (funcptr_t)ascon80pq_get_params},
    {OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (funcptr_t)ascon_gettable_params},
    {OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (funcptr_t)ascon_get_ctx_params},
    {OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
     (funcptr_t)ascon_gettable_ctx_params},
    {OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (funcptr_t)ascon_set_ctx_params},
    {OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
     (funcptr_t)ascon_settable_ctx_params},
    {0, NULL}};

/* The Ascon128 dispatch table */
static const OSSL_DISPATCH ascon128_functions[] = {
    {OSSL_FUNC_CIPHER_NEWCTX, (funcptr_t)ascon_newctx},
    {OSSL_FUNC_CIPHER_ENCRYPT_INIT, (funcptr_t)ascon_encrypt_init},
    {OSSL_FUNC_CIPHER_DECRYPT_INIT, (funcptr_t)ascon_decrypt_init},
    {OSSL_FUNC_CIPHER_UPDATE, (funcptr_t)ascon128_update},
    {OSSL_FUNC_CIPHER_FINAL, (funcptr_t)ascon_final},
    {OSSL_FUNC_CIPHER_DUPCTX, (funcptr_t)ascon_dupctx},
    {OSSL_FUNC_CIPHER_FREECTX, (funcptr_t)ascon_freectx},
    {OSSL_FUNC_CIPHER_GET_PARAMS, (funcptr_t)ascon128a_get_params},
    {OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (funcptr_t)ascon_gettable_params},
    {OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (funcptr_t)ascon_get_ctx_params},
    {OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
     (funcptr_t)ascon_gettable_ctx_params},
    {OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (funcptr_t)ascon_set_ctx_params},
    {OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
     (funcptr_t)ascon_settable_ctx_params},
    {0, NULL}};

/* The Ascon128a dispatch table */
static const OSSL_DISPATCH ascon128a_functions[] = {
    {OSSL_FUNC_CIPHER_NEWCTX, (funcptr_t)ascon_newctx},
    {OSSL_FUNC_CIPHER_ENCRYPT_INIT, (funcptr_t)ascon_encrypt_init},
    {OSSL_FUNC_CIPHER_DECRYPT_INIT, (funcptr_t)ascon_decrypt_init},
    {OSSL_FUNC_CIPHER_UPDATE, (funcptr_t)ascon128a_update},
    {OSSL_FUNC_CIPHER_FINAL, (funcptr_t)ascon_final},
    {OSSL_FUNC_CIPHER_DUPCTX, (funcptr_t)ascon_dupctx},
    {OSSL_FUNC_CIPHER_FREECTX, (funcptr_t)ascon_freectx},
    {OSSL_FUNC_CIPHER_GET_PARAMS, (funcptr_t)ascon128_get_params},
    {OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (funcptr_t)ascon_gettable_params},
    {OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (funcptr_t)ascon_get_ctx_params},
    {OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
     (funcptr_t)ascon_gettable_ctx_params},
    {OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (funcptr_t)ascon_set_ctx_params},
    {OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
     (funcptr_t)ascon_settable_ctx_params},
    {0, NULL}};

/* The table of ciphers this provider offers */
static const OSSL_ALGORITHM ascon_ciphers[] = {
    // { "ASCON-128:1.3.6.1.4.1.5168.4711.22087.1", "x.author='" AUTHOR "'",
    // vigenere_functions },
    {"ASCON-80PQ", "x.author='" AUTHOR "'",
     ascon80pq_functions},
    {"ASCON-128", "x.author='" AUTHOR "'",
     ascon128_functions},
    {"ASCON-128A", "x.author='" AUTHOR "'",
     ascon128a_functions},
    {NULL, NULL, NULL}};

/* The function that returns the appropriate algorithm table per operation */
static const OSSL_ALGORITHM *ascon_prov_operation(void *vprovctx,
                                                  int operation_id,
                                                  int *no_cache)
{
    *no_cache = 0;
    switch (operation_id)
    {
    case OSSL_OP_CIPHER:
        return ascon_ciphers;
    }
    return NULL;
}

static const OSSL_ITEM *ascon_prov_get_reason_strings(void *provctx)
{
    return reason_strings;
}

static int ascon_prov_get_params(void *provctx, OSSL_PARAM *params)
{
    OSSL_PARAM *p;
    int ok = 1;

    for (p = params; p->key != NULL; p++)
        switch (ascon_params_parse(p->key))
        {
        case V_PARAM_version:
            *(const void **)p->data = "1.0.0";
            p->return_size = strlen("1.0.0");
            break;
        case V_PARAM_buildinfo:
            if (BUILDTYPE[0] != '\0')
            {
                *(const void **)p->data = BUILDTYPE;
                p->return_size = strlen(BUILDTYPE);
            }
            break;
        case V_PARAM_author:
            if (AUTHOR[0] != '\0')
            {
                *(const void **)p->data = AUTHOR;
                p->return_size = strlen(AUTHOR);
            }
            break;
        case V_PARAM_status:
            *(const void **)p->data = "1";
            p->return_size = strlen("1");
            break;
        case V_PARAM_name:
            //*(const void **)p->data = "OpenSSl Ascon Provider";
            // p->return_size = strlen("OpenSSl Ascon Provider") + 1;
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
    {OSSL_FUNC_PROVIDER_TEARDOWN, (funcptr_t)vigenere_prov_teardown},
    {OSSL_FUNC_PROVIDER_QUERY_OPERATION, (funcptr_t)ascon_prov_operation},
    {OSSL_FUNC_PROVIDER_GET_REASON_STRINGS,
     (funcptr_t)ascon_prov_get_reason_strings},
    {OSSL_FUNC_PROVIDER_GET_PARAMS,
     (funcptr_t)ascon_prov_get_params},
    {0, NULL}};

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
