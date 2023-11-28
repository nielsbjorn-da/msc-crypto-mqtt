//How to compile in cmd inside this folder: gcc demo.c aead.c printstate.c -o demo -lssl -lcrypto

#include <stdio.h>
#include <string.h>
#include "api.h"
#if defined(AVR_UART)
#include "avr_uart.h"
#endif
#define CRYPTO_AEAD
#if defined(CRYPTO_AEAD)
#include "crypto_aead.h"
#elif defined(CRYPTO_HASH)
#include "crypto_hash.h"
#elif defined(CRYPTO_AUTH)
#include "crypto_auth.h"
#endif

#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/core.h>
#include <openssl/provider.h>
#include <openssl/err.h>

void print(unsigned char c, unsigned char* x, unsigned long long xlen) {
  unsigned long long i;
  printf("%c[%d]=", c, (int)xlen);
  for (i = 0; i < xlen; ++i) printf("%02x", x[i]);
  printf("\n");
  for (i = 0; i < xlen; ++i) printf("%u", x[i]);
  printf("\n");
}

int main() {
  const char* provider_name = "vigenere";
  OSSL_LIB_CTX *ossl_ctx = OSSL_LIB_CTX_new();
  OSSL_PROVIDER *ascon_provider = OSSL_PROVIDER_load(ossl_ctx, provider_name);
  OSSL_PROVIDER *default_provider = OSSL_PROVIDER_load(ossl_ctx, "default");
  int res = OSSL_PROVIDER_available(ossl_ctx, provider_name);
  printf("Provider available: %d\n",  res);

  //based on this example: https://github.com/openssl/openssl/blob/master/demos/cipher/aesgcm.c

  EVP_CIPHER_CTX *encryption_ctx;
   /* Create a context for the encrypt operation */
  if ((encryption_ctx = EVP_CIPHER_CTX_new()) == NULL)
      printf("error asdas\n");
 
  const EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "ascon128", NULL);
  if (cipher == NULL) {
      fprintf(stderr, "cipher not available in the provider\n");
  } 

  unsigned char n[CRYPTO_NPUBBYTES] = {0, 1, 2,  3,  4,  5,  6,  7,
                                       8, 9, 10, 11, 12, 13, 14, 15};
  unsigned char k[CRYPTO_KEYBYTES] = {0, 1, 2,  3,  4,  5,  6,  7,
                                      8, 9, 10, 11, 12, 13, 14, 15};
  unsigned char a[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
  //unsigned char m[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
  unsigned char m[] = "The quick brown fox jumps over the lazy dog";
  unsigned long long mlen = strlen(m);//16;
  unsigned char c[CRYPTO_ABYTES + mlen], h[32], t[32];
  unsigned long long alen = 16;
  unsigned long long clen = CRYPTO_ABYTES;
  int result = 0;
  int outlen, tmplen;
  unsigned char outbuf[1024];
  unsigned char *outtag = (unsigned char *)malloc(CRYPTO_ABYTES);
  OSSL_PARAM params[3] = {
        OSSL_PARAM_END, OSSL_PARAM_END, OSSL_PARAM_END
    };

  if (!EVP_EncryptInit_ex2(encryption_ctx, cipher, k, n, NULL))
      printf("error init\n");

   /* AD data */
  if (!EVP_EncryptUpdate(encryption_ctx, NULL, &outlen, a, alen))
      printf("error AD data\n");

  /* Encrypt plaintext */
  if (!EVP_EncryptUpdate(encryption_ctx, outbuf, &outlen, m, mlen))
      printf("error encrypting\n");

    /* Output encrypted block */
  printf("Ciphertext:\n");
  BIO_dump_fp(stdout, outbuf, outlen);

if (!EVP_EncryptFinal_ex(encryption_ctx, outbuf, &tmplen))
        printf("error finalize\n");

/* Get tag */
  params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                                outtag, CRYPTO_ABYTES);
  params[1] = OSSL_PARAM_construct_end();


  printf("Output Tag before:\n");
  BIO_dump_fp(stdout, outtag, CRYPTO_ABYTES);

if (!EVP_CIPHER_CTX_get_params(encryption_ctx, params))
        printf("Fetch tag error \n");

    /* Output tag */
    printf("Tag:\n");
    BIO_dump_fp(stdout, outtag, CRYPTO_ABYTES);

/*** DECRYPTION ***/ 

printf("OPENSSL DECRYPTION: \n");
EVP_CIPHER_CTX *decryption_ctx;
unsigned char outbuf_decryption[1024];
int outlen_decryption, rv;
OSSL_PARAM decryption_params[3] = {
        OSSL_PARAM_END, OSSL_PARAM_END, OSSL_PARAM_END
    };
unsigned char aad_decryption[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
unsigned char aad_len_decryption = 16;

if ((decryption_ctx = EVP_CIPHER_CTX_new()) == NULL)
    printf("error ctx init\n");

/*
  * Initialise an encrypt operation with the cipher/mode, key, IV and
  * IV length parameter.
  */
if (!EVP_DecryptInit_ex2(decryption_ctx, cipher, k, n, NULL))
    printf("decrypt init fail\n");

 /* AD data */
  if (!EVP_DecryptUpdate(decryption_ctx, NULL, &outlen_decryption, aad_decryption, aad_len_decryption))
      printf("error AD data\n");

/* Decrypt plaintext */
if (!EVP_DecryptUpdate(decryption_ctx, outbuf_decryption, &outlen_decryption, outbuf, outlen))
    printf("decrypt fail\n");

/* Output decrypted block */
  printf("Plaintext:\n");
  BIO_dump_fp(stdout, outbuf_decryption, outlen_decryption);
  
  // ADD Tag verification check also
  /* Set expected tag value. */
  decryption_params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                                  outtag, CRYPTO_ABYTES);

  if (!EVP_CIPHER_CTX_set_params(decryption_ctx, decryption_params))
        printf("set param error");
  
  /* Finalise: note get no output for GCM */
  rv = EVP_DecryptFinal_ex(decryption_ctx, outbuf_decryption, &outlen_decryption);
    /*
     * Print out return value. If this is not successful authentication
     * failed and plaintext is not trustworthy.
     */
    printf("Tag Verify %s\n", rv > 0 ? "Successful!" : "Failed!");


#if defined(AVR_UART)
  avr_uart_init();
  stdout = &avr_uart_output;
  stdin = &avr_uart_input_echo;
#endif
#if defined(CRYPTO_AEAD)
  printf("\n\n *** native ASCON-C decrypt/encrypt starts ***\n\n");
  print('k', k, CRYPTO_KEYBYTES);
  printf(" ");
  print('n', n, CRYPTO_NPUBBYTES);
  printf("\n");
  print('a', a, alen);
  printf(" ");
  print('m', m, mlen);
  printf(" -> ");
  result |= crypto_aead_encrypt(c, &clen, m, mlen, a, alen, (void*)0, n, k);
  print('c', c, clen - CRYPTO_ABYTES);
  printf(" \n");
  print('t', c + clen - CRYPTO_ABYTES, CRYPTO_ABYTES);  
  printf("hej\n");
  printf(" -> ");
  result |= crypto_aead_decrypt(m, &mlen, (void*)0, c, clen, a, alen, n, k);
  print('a', a, alen);
  printf(" ");
  print('m', m, mlen);
  printf("\n");
#elif defined(CRYPTO_HASH)
  print('m', m, mlen);
  printf(" -> ");
  result |= crypto_hash(h, m, mlen);
  print('h', h, CRYPTO_BYTES);
  printf("\n");
#elif defined(CRYPTO_AUTH)
  print('k', k, CRYPTO_KEYBYTES);
  printf(" ");
  print('m', m, mlen);
  printf(" -> ");
  result |= crypto_auth(t, m, mlen, k);
  print('h', t, CRYPTO_BYTES);
  printf("\n");
#endif
  return result;
}
