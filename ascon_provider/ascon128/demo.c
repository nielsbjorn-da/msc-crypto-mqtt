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
}

int main() {
   // Initialize OpenSSL
  /*OpenSSL_add_all_algorithms();

  // Load the provider library
  OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);

  // Set the provider name (replace "your_provider_name" with the actual provider name)
  const char* provider_name = "vigenere";

  // Load the provider
  OSSL_PROVIDER* provider = OSSL_PROVIDER_load(NULL, provider_name); */
  const char* provider_name = "oqsprovider";
  OSSL_LIB_CTX *ossl_ctx = OSSL_LIB_CTX_new();
  OSSL_PROVIDER *ascon_provider = OSSL_PROVIDER_load(ossl_ctx, provider_name);
  OSSL_PROVIDER *default_provider = OSSL_PROVIDER_load(ossl_ctx, "default");
  int res = OSSL_PROVIDER_available(ossl_ctx, provider_name);
  printf("Provider available: %d\n",  res);

  //OpenSSL_add_all_algorithms();
  //based on this example: https://github.com/openssl/openssl/blob/master/demos/cipher/aesgcm.c

  EVP_CIPHER_CTX *encryption_ctx;
   /* Create a context for the encrypt operation */
  if ((encryption_ctx = EVP_CIPHER_CTX_new()) == NULL)
      printf("error asdas\n");
 
  const EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "vigenere", NULL);
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

  if (!EVP_EncryptInit_ex2(encryption_ctx, cipher, k, n, NULL))
      printf("error init\n");

  /* Encrypt plaintext */
  if (!EVP_EncryptUpdate(encryption_ctx, outbuf, &outlen, m, mlen))
      printf("error encrypting\n");

    /* Output encrypted block */
  printf("Ciphertext:\n");
  BIO_dump_fp(stdout, outbuf, outlen);

if (!EVP_EncryptFinal_ex(encryption_ctx, outbuf, &tmplen))
        printf("error finalize\n");
    
/*** DECRYPTION ***/ 

printf("OPENSSL DECRYPTION: \n");
EVP_CIPHER_CTX *decryption_ctx;
unsigned char outbuf_decryption[1024];
int outlen_decryption, rv;

if ((decryption_ctx = EVP_CIPHER_CTX_new()) == NULL)
    printf("error ctx init\n");

/*
  * Initialise an encrypt operation with the cipher/mode, key, IV and
  * IV length parameter.
  */
if (!EVP_DecryptInit_ex2(decryption_ctx, cipher, k, n, NULL))
    printf("decrypt init fail\n");

/* Decrypt plaintext */
if (!EVP_DecryptUpdate(decryption_ctx, outbuf_decryption, &outlen_decryption, outbuf, outlen))
    printf("decrypt fail\n");

/* Output decrypted block */
  printf("Plaintext:\n");
  BIO_dump_fp(stdout, outbuf_decryption, outlen_decryption);
  
  // ADD Tag verification check also

  
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
  result |= crypto_aead_encrypt(c, &clen, m, mlen, NULL, 0, (void*)0, n, k);
  print('c', c, clen - CRYPTO_ABYTES);
  printf(" \n");
  print('t', c + clen - CRYPTO_ABYTES, CRYPTO_ABYTES);
  printf("hej\n");
  printf(" -> ");
  result |= crypto_aead_decrypt(m, &mlen, (void*)0, c, clen, NULL, 0, n, k);
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
