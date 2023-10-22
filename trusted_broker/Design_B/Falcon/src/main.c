#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "../FalconImpl/falcon.h"

typedef struct {
	unsigned logn;
	shake256_context rng;
	uint8_t *tmp;
	size_t tmp_len;
	uint8_t *pk;
	uint8_t *sk;
	uint8_t *esk;
	uint8_t *sig;
	size_t sig_len;
	uint8_t *sigct;
	size_t sigct_len;
} context;

static void *
xmalloc(size_t len)
{
	void *buf;

	if (len == 0) {
		return NULL;
	}
	buf = malloc(len);
	if (buf == NULL) {
		fprintf(stderr, "memory allocation error\n");
		exit(EXIT_FAILURE);
	}
	return buf;
}

static void
xfree(void *buf)
{
	if (buf != NULL) {
		free(buf);
	}
}

static inline size_t
maxsz(size_t a, size_t b)
{
	return a > b ? a : b;
}

static int
generate_signature_and_verify(){
    // 
    context *sc = malloc(sizeof(context));
    
    if (sc == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    size_t pk_len;
    size_t len;
    unsigned logn = 10;

	printf("Security: %4u bytes\n", 1u << logn);
	fflush(stdout);

	sc->logn = logn;

    // Creating SHAKE256 context.
    // This should be done before initialization of keys.
	if (shake256_init_prng_from_system(&sc->rng) != 0) {
		fprintf(stderr, "random seeding failed\n");
		exit(EXIT_FAILURE);
    }

    len = FALCON_TMPSIZE_KEYGEN(logn);
	len = maxsz(len, FALCON_TMPSIZE_SIGNDYN(logn));
	len = maxsz(len, FALCON_TMPSIZE_SIGNTREE(logn));
	len = maxsz(len, FALCON_TMPSIZE_EXPANDPRIV(logn));
	len = maxsz(len, FALCON_TMPSIZE_VERIFY(logn));
	sc->tmp = xmalloc(len);
	sc->tmp_len = len;
	sc->pk = xmalloc(FALCON_PUBKEY_SIZE(logn));
	sc->sk = xmalloc(FALCON_PRIVKEY_SIZE(logn));
	sc->esk = xmalloc(FALCON_EXPANDEDKEY_SIZE(logn));
	sc->sig = xmalloc(FALCON_SIG_COMPRESSED_MAXSIZE(logn));
	sc->sig_len = 0;
	sc->sigct = xmalloc(FALCON_SIG_CT_SIZE(logn));
	sc->sigct_len = 0;

    printf("Start key gen\n");
    if(falcon_keygen_make(&sc->rng, sc->logn,
			sc->sk, FALCON_PRIVKEY_SIZE(sc->logn),
			sc->pk, FALCON_PUBKEY_SIZE(sc->logn),
			sc->tmp, sc->tmp_len) != 0) {
                fprintf(stderr, "Key generation failed\n");
		        exit(EXIT_FAILURE);
            }
    printf("end key gen\n");
    

    pk_len = FALCON_PUBKEY_SIZE(sc->logn);
    int r = falcon_get_logn(sc->pk, pk_len);
    printf("Security of public key is %d, corresponding to %4u bytes security\n", r, 1u << r);
    
    printf("start sign\n");
    sc->sig_len = FALCON_SIG_COMPRESSED_MAXSIZE(sc->logn);
    falcon_sign_dyn(&sc->rng,
        sc->sig, &sc->sig_len, FALCON_SIG_COMPRESSED,
        sc->sk, FALCON_PRIVKEY_SIZE(sc->logn),
        "data", 4, sc->tmp, sc->tmp_len);
    printf("end sign\n");


    printf("start verify\n");
    int result = falcon_verify(
			sc->sig, sc->sig_len, FALCON_SIG_COMPRESSED,
			sc->pk, pk_len,
			"data", 4, sc->tmp, sc->tmp_len);
    printf("end verify with result: %d\n", result);
    fflush(stdout);
    xfree(sc->tmp);
	xfree(sc->pk);
	xfree(sc->sk);
	xfree(sc->esk);
	xfree(sc->sig);
	xfree(sc->sigct);
    free(sc);
    return 0;
}


int main() {
    printf("Falcon Signature example - Generation of keys, Creations of signature on data, Verification of signature on data.\n");
 
    generate_signature_and_verify();

    return 0;
}