//How to compile in cmd inside this folder: gcc test_ascon_aes.c -o test_ascon_aes -lssl -lcrypto

#include <stdio.h>
#include <string.h>


#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/core.h>
#include <openssl/provider.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <sys/time.h>

char *cipher_algos[] = {"AES-128-GCM", "ASCON-128", "ASCON-128A", "ASCON-80PQ"};

int main() {
  OSSL_LIB_CTX *ossl_ctx = OSSL_LIB_CTX_new();
  int res = OSSL_PROVIDER_available(ossl_ctx, "asconprovider");
  printf("Provider available: %d\n",  res);

  struct timeval end_time;
  struct timeval start_time;
  long time_taken;
  long decrypt_time_taken;
  long total_time;
  
  //based on this example: https://github.com/openssl/openssl/blob/master/demos/cipher/aesgcm.c
  for (size_t j = 0; j < 10; j++)
  {
  
  
    for (size_t i = 0; i < 4; i++) {

      RAND_poll();


      char *alg_name = cipher_algos[i];
      printf("\n CIPHER: %s \n", alg_name);
    // unsigned char n[CRYPTO_NPUBBYTES] = {0, 1, 2,  3,  4,  5,  6,  7,
      //                                   8, 9, 10, 11, 12, 13, 14, 15};
      //unsigned char k[CRYPTO_KEYBYTES] = {0, 1, 2,  3,  4,  5,  6,  7,
        //                                  8, 9, 10, 11, 12, 13, 14, 15};

      unsigned long long key_size = 16;
      if (strcmp(alg_name, "ASCON-80PQ") == 0) {
        key_size = 20;
      }

      unsigned long long nonce_size = 16;
      if (strcmp(alg_name, "AES-128-GCM") == 0) {
        nonce_size = 12;
      }

      unsigned long long alen = 16;
      unsigned long long mlen = 64;
      unsigned long long taglen = 16;

      unsigned char k[key_size];
      unsigned char n[nonce_size];
      unsigned char a[alen]; 
      unsigned char m[mlen];

      if (RAND_bytes(k, key_size) != 1) {
          fprintf(stderr, "Error generating random bytes for array k\n");
          return 1;
      }

      if (RAND_bytes(n, nonce_size) != 1) {
          fprintf(stderr, "Error generating random bytes for array n\n");
          return 1;
      }

      if (RAND_bytes(a, alen) != 1) {
          fprintf(stderr, "Error generating random bytes for array a\n");
          return 1;
      }

      if (RAND_bytes(m, mlen) != 1) {
          fprintf(stderr, "Error generating random bytes for array m\n");
          return 1;
      }
      gettimeofday(&start_time, NULL);
      EVP_CIPHER_CTX *encryption_ctx;
    /* Create a context for the encrypt operation */
      if ((encryption_ctx = EVP_CIPHER_CTX_new()) == NULL)
          printf("error asdas\n");
    
      const EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, alg_name, NULL);
      if (cipher == NULL) {
          fprintf(stderr, "cipher not available in the provider\n");
      } 
      //unsigned char m[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
      //unsigned char m[] = "The quick brown fox jumps over the lazy dog";
      //unsigned long long mlen = strlen(m);//16;
      //unsigned char c[CRYPTO_ABYTES + mlen], h[32], t[32];
      //unsigned long long alen = 16;
      //unsigned long long clen = CRYPTO_ABYTES;
      int result = 0;
      int outlen, tmplen;
      unsigned char outbuf[mlen+10];
      unsigned char *outtag = (unsigned char *)malloc(taglen);
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
                                                    outtag, taglen);
      params[1] = OSSL_PARAM_construct_end();

      if (!EVP_CIPHER_CTX_get_params(encryption_ctx, params))
          printf("Fetch tag error \n");
        
        /* Output tag */
      printf("Tag:\n");
      BIO_dump_fp(stdout, outtag, taglen);

      
      gettimeofday(&end_time, NULL);
      time_taken = (end_time.tv_sec * 1000000 + end_time.tv_usec) - (start_time.tv_sec * 1000000 + start_time.tv_usec);
      printf("%s encryption time: %ld micro seconds.\n", alg_name, time_taken);

      /*** DECRYPTION ***/ 
      gettimeofday(&start_time, NULL);
      printf("OPENSSL DECRYPTION: \n");
      EVP_CIPHER_CTX *decryption_ctx;
      unsigned char outbuf_decryption[1024];
      int outlen_decryption, rv;
      OSSL_PARAM decryption_params[3] = {
              OSSL_PARAM_END, OSSL_PARAM_END, OSSL_PARAM_END
          };

      if ((decryption_ctx = EVP_CIPHER_CTX_new()) == NULL)
          printf("error ctx init\n");

      /*
        * Initialise an encrypt operation with the cipher/mode, key, IV and
        * IV length parameter.
        */
      if (!EVP_DecryptInit_ex2(decryption_ctx, cipher, k, n, NULL))
          printf("decrypt init fail\n");

      /* AD data */
        if (!EVP_DecryptUpdate(decryption_ctx, NULL, &outlen_decryption, a, alen))
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
                                                      outtag, taglen);

      if (!EVP_CIPHER_CTX_set_params(decryption_ctx, decryption_params))
            printf("set param error");
      
      /* Finalise: note get no output for GCM */
      rv = EVP_DecryptFinal_ex(decryption_ctx, outbuf_decryption, &outlen_decryption);
        /*
        * Print out return value. If this is not successful authentication
        * failed and plaintext is not trustworthy.
        */
      printf("Tag Verify %s\n", rv > 0 ? "Successful!" : "Failed!");

      gettimeofday(&end_time, NULL);
      decrypt_time_taken = (end_time.tv_sec * 1000000 + end_time.tv_usec) - (start_time.tv_sec * 1000000 + start_time.tv_usec);
      total_time = time_taken + decrypt_time_taken;
      printf("%s decryption time: %ld micro seconds.\n", alg_name, decrypt_time_taken);
      printf("%s total time: %ld micro seconds.\n", alg_name, total_time);
    }
    
  }
  return 1;
}
