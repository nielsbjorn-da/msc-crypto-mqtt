#include <stdio.h>
#include <time.h>

// Dilithium import
#include "dilithium_and_falcon/dilithium/dilithium-master/ref/randombytes.h"
#include "dilithium_and_falcon/dilithium/dilithium-master/ref/sign.h"

// Falcon import
#include "dilithium_and_falcon/falcon/Falcon-impl-20211101/falcon.h"

#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#include <sys/time.h>
#else
#include <process.h>
#include <winsock2.h>
#define snprintf sprintf_s
#endif

#include <mqtt_protocol.h>
#include <mosquitto.h>
#include "client_shared.h"
#include "pub_shared.h"

#include <cjson/cJSON.h>
#include "libb64/include/b64/cencode.h"
#include "libb64/include/b64/cdecode.h"

// dilithium variables
uint8_t dilithium_pub_pk[CRYPTO_PUBLICKEYBYTES];
uint8_t dilithium_pub_sk[CRYPTO_SECRETKEYBYTES];
uint8_t dilithium_signature[CRYPTO_BYTES];
static bool dilithium = true;
//
// Falcon struct
typedef struct
{
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
} FalconContext;

// Falcon variables
unsigned logn = 10;
size_t pk_len = FALCON_PUBKEY_SIZE(10);
size_t len = FALCON_TMPSIZE_KEYGEN(10);

// Time variables
clock_t start, end;

// MQTT
/* Global variables for use in callbacks. See sub_client.c for an example of
 * using a struct to hold variables for use in callbacks. */
static bool first_publish = true;
static int last_mid = -1;
static int last_mid_sent = -1;
static char *line_buf = NULL;
static int line_buf_len = 1024;
static bool disconnect_sent = false;
static int publish_count = 0;
static bool ready_for_repeat = false;
static volatile int status = STATUS_CONNECTING;
static int connack_result = 0;

// Falcon custom functions
static void *
xmalloc(size_t len)
{
  void *buf;

  if (len == 0)
  {
    return NULL;
  }
  buf = malloc(len);
  if (buf == NULL)
  {
    fprintf(stderr, "memory allocation error\n");
    exit(EXIT_FAILURE);
  }
  return buf;
}

static void
xfree(void *buf)
{
  if (buf != NULL)
  {
    free(buf);
  }
}

static inline size_t
maxsz(size_t a, size_t b)
{
  return a > b ? a : b;
}

void pub_shared_cleanup(void)
{
  free(line_buf);
}

int pub_shared_init(void)
{
  line_buf = malloc(sizeof(size_t) * line_buf_len);
  if (!line_buf)
  {
    err_printf(&cfg, "Error: Out of memory.\n");
    return 1;
  }
  return 0;
}

static void print_version(void)
{
  int major, minor, revision;

  mosquitto_lib_version(&major, &minor, &revision);
  printf("mosquitto_pub version ");
}

static void print_usage(void)
{
  printf("print usage method");
}

void my_connect_callback(struct mosquitto *mosq, void *obj, int result, int flags, const mosquitto_property *properties)
{
  int rc = MOSQ_ERR_SUCCESS;

  /*UNUSED(obj);
  UNUSED(flags);
  UNUSED(properties);
  */
  connack_result = result;
  printf("in connect callback");
}

int my_publish(struct mosquitto *mosq, int *mid, const char *topic, int payloadlen, void *payload, int qos, bool retain)
{
  ready_for_repeat = false;
  if (cfg.protocol_version == MQTT_PROTOCOL_V5 && cfg.have_topic_alias && first_publish == false)
  {
    return mosquitto_publish_v5(mosq, mid, NULL, payloadlen, payload, qos, retain, cfg.publish_props);
  }
  else
  {
    first_publish = false;
    return mosquitto_publish_v5(mosq, mid, topic, payloadlen, payload, qos, retain, cfg.publish_props);
  }
}

/*
  Dilithium signing funciton
*/
int dilithium_sign_message(uint8_t *signature, const char *message, int message_length)
{
  size_t sig_length;

  int ret = crypto_sign_signature(signature, &sig_length, message, message_length, dilithium_pub_sk);

  if (ret)
  {
    fprintf(stderr, "Signature generation failed\n");
    return -1;
  }
  return ret;
}

/*
  Dilithium verification funciton
*/
int dilithium_verify(uint8_t *signature, char *message, int message_length, uint8_t *public_key)
{
  size_t sig_length = CRYPTO_BYTES;

  int ret = crypto_sign_verify(signature, sig_length, message, message_length, public_key);

  if (ret)
  {
    fprintf(stderr, "Verification failed\n");
    return -1;
  }
  return ret;
}

/*
  Generate secret and public key for Falcon
*/
void initialize_falcon_struct(FalconContext *fc)
{
  fflush(stdout);
  fc->logn = logn;
  //printf("Security: %4u bytes\n", 1u << logn);
  len = maxsz(len, FALCON_TMPSIZE_SIGNDYN(fc->logn));
  len = maxsz(len, FALCON_TMPSIZE_SIGNTREE(fc->logn));
  len = maxsz(len, FALCON_TMPSIZE_EXPANDPRIV(fc->logn));
  len = maxsz(len, FALCON_TMPSIZE_VERIFY(fc->logn));
  fc->tmp = xmalloc(len);
  fc->tmp_len = len;
  fc->pk = xmalloc(FALCON_PUBKEY_SIZE(fc->logn));
  fc->sk = xmalloc(FALCON_PRIVKEY_SIZE(fc->logn));
  fc->esk = xmalloc(FALCON_EXPANDEDKEY_SIZE(fc->logn));
  fc->sig = xmalloc(FALCON_SIG_PADDED_SIZE(fc->logn));
  fc->sig_len = 0;
  fc->sigct = xmalloc(FALCON_SIG_CT_SIZE(fc->logn));
  fc->sigct_len = 0;

  // Creating SHAKE256 context.
  // This should be done before initialization of keys.
  if (shake256_init_prng_from_system(&fc->rng) != 0)
  {
    fprintf(stderr, "random seeding failed\n");
    exit(EXIT_FAILURE);
  }
  
  int keygen = falcon_keygen_make(&fc->rng, fc->logn,
                         fc->sk, FALCON_PRIVKEY_SIZE(fc->logn),
                         fc->pk, FALCON_PUBKEY_SIZE(fc->logn),
                         fc->tmp, fc->tmp_len);
  
  if (keygen != 0)
  {
    fprintf(stderr, "Key generation failed\n");
    exit(EXIT_FAILURE);
  }
}

/*
  Falcon signing function
*/
int falcon_sign_message(FalconContext *fc, char *payload, int payload_len)
{
  fc->sig_len = FALCON_SIG_PADDED_SIZE(fc->logn);
  int result = falcon_sign_dyn(&fc->rng,
                               fc->sig, &fc->sig_len, FALCON_SIG_PADDED,
                               fc->sk, FALCON_PRIVKEY_SIZE(fc->logn),
                               payload, payload_len, fc->tmp, fc->tmp_len);
  return result;
}

int falcon_verify_message(FalconContext *fc, char *payload, int payload_len)
{
  int result = falcon_verify(
      fc->sig, fc->sig_len, FALCON_SIG_PADDED,
      fc->pk, pk_len,
      payload, payload_len, fc->tmp, fc->tmp_len);
  return result;
}

char *decode(const char *input, size_t size)
{
  /* set up a destination buffer large enough to hold the encoded data */

  /* keep track of our decoded position */

  /* store the number of bytes decoded by a single call */
  int cnt = 0;
  /* we need a decoder state */
  base64_decodestate s;
  base64_init_decodestate(&s);
  size_t si = base64_encode_length(size, &s);
  char *output = (char *)malloc(si);
  char *c = output;

  /*---------- START DECODING ----------*/
  /* initialise the decoder state */
  /* decode the input data */
  cnt = base64_decode_block(input, strlen(input), c, &s);
  c += cnt;
  /* note: there is no base64_decode_blockend! */
  /*---------- STOP DECODING  ----------*/

  /* we want to print the decoded data, so null-terminate it: */
  *c = 0;
  return output;
}

char* encode(uint8_t *input, size_t input_size)
{
  //int SIZE = 4;
  /* set up a destination buffer large enough to hold the encoded data */
  char *output = (char *)malloc(input_size*2);
  /* keep track of our encoded position */
  char *c = output;
  /* store the number of bytes encoded by a single call */
  int cnt = 0;
  /* we need an encoder state */
  base64_encodestate s;

  /*---------- START ENCODING ----------*/
  /* initialise the encoder state */
  base64_init_encodestate(&s);
  /* gather data from the input and send it to the output */
  cnt = base64_encode_block(input, input_size, c, &s);
  c += cnt;
  /* since we have encoded the entire input string, we know that
     there is no more input data; finalise the encoding */
  cnt = base64_encode_blockend(c, &s);
  c += cnt;
  /*---------- STOP ENCODING  ----------*/

  /* we want to print the encoded data, so null-terminate it: */
  *c = 0;

  // printf("test:");
  // printf("input: %u, %u, %u, output: %s", input[0], input[1], input[2], output);
  // printf("\n");
  return output;
}

int main(int argc, char *argv[])
{

  FalconContext *fc = malloc(sizeof(FalconContext));
  size_t sig_length;
  char current_time_str[20]; // Adjust the size based on your maximum expected time value
  int message_len;
  struct timeval timestamp;
  char clientID[23] = "publisher_client";
  struct mosquitto *mosq = NULL;
  int rc;

  if (dilithium)
  {
    // Record the start time
    start = clock();
    crypto_sign_keypair(dilithium_pub_pk, dilithium_pub_sk); // gen keys
    end = clock();
    printf("%s initialization execution time: %f seconds\n", CRYPTO_ALGNAME, ((double)(end - start)) / CLOCKS_PER_SEC);
    int i;
  }
  else
  {
    if (fc == NULL)
    {
      fprintf(stderr, "Memory allocation for Falcon failed\n");
      exit(EXIT_FAILURE);
    }
    // Record the start time
    start = clock();
    initialize_falcon_struct(fc);
    end = clock();
    printf("Falcon initialization execution time: %f seconds\n", ((double)(end - start)) / CLOCKS_PER_SEC);
  }

  mosquitto_lib_init();

  if (pub_shared_init())
    return 1;

  rc = client_config_load(&cfg, CLIENT_PUB, argc, argv);
  if (rc)
  {
    if (rc == 2)
    {
      /* --help */
      print_usage();
    }
    else if (rc == 3)
    {
      print_version();
    }
    else
    {
      fprintf(stderr, "\nUse 'mosquitto_pub --help' to see usage.\n");
    }
    goto cleanup;
  }

  if (cfg.pub_mode == MSGMODE_STDIN_FILE)
  {
    if (load_stdin())
    {
      err_printf(&cfg, "Error loading input from stdin.\n");
      goto cleanup;
    }
  }
  else if (cfg.file_input)
  {
    if (load_file(cfg.file_input))
    {
      err_printf(&cfg, "Error loading input file \"%s\".\n", cfg.file_input);
      goto cleanup;
    }
  }

  if (!cfg.topic || cfg.pub_mode == MSGMODE_NONE)
  {
    fprintf(stderr, "Error: Both topic and message must be supplied.\n");
    print_usage();
    goto cleanup;
  }

  if (client_id_generate(&cfg))
  {
    goto cleanup;
  }

  mosq = mosquitto_new(clientID, false, NULL);
  if (!mosq)
  {
    switch (errno)
    {
    case ENOMEM:
      err_printf(&cfg, "Error: Out of memory.\n");
      break;
    case EINVAL:
      err_printf(&cfg, "Error: Invalid id.\n");
      break;
    }
    goto cleanup;
  }

  mosquitto_connect_v5_callback_set(mosq, my_connect_callback);

  if (client_opts_set(mosq, &cfg))
  {
    goto cleanup;
  }

  rc = client_connect(mosq, &cfg);
  if (rc)
  {
    printf("RC client connect");
    goto cleanup;
  }
  // timestamp
  gettimeofday(&timestamp, NULL);

  // #####################################################################################
  //  Creating the message to sign
  // #####################################################################################
  // Convert int qos to string
  // Record the start time
  start = clock();
  snprintf(current_time_str, sizeof(current_time_str), "%ld", timestamp.tv_sec);

  message_len = strlen(cfg.message) + strlen(cfg.topic) + strlen(current_time_str) + strlen(clientID);
  char concatenated_message_to_sign[10000 + 1]; // +1 for the null terminator
  concatenated_message_to_sign[0] = '\0';

  strcat(concatenated_message_to_sign, cfg.message);
  strcat(concatenated_message_to_sign, cfg.topic);
  strcat(concatenated_message_to_sign, current_time_str);
  strcat(concatenated_message_to_sign, clientID);
  end = clock();
  printf("Generating message concat execution time: %f seconds\n", ((double)(end - start)) / CLOCKS_PER_SEC);
  // #####################################################################################
  //  Run the signing algorithms
  // #####################################################################################
  start = clock();
  char *sig_scheme;
  if (dilithium)
  {
    sig_scheme = "Dilithium";
    dilithium_sign_message(dilithium_signature, concatenated_message_to_sign, message_len);
  }
  else
  {
    sig_scheme = "Falcon";
    if (falcon_sign_message(fc, &concatenated_message_to_sign, message_len) != 0)
    {
      fprintf(stderr, "Signing message for Falcon failed\n");
      exit(EXIT_FAILURE);
    }
  }
  end = clock();
  printf("Signing message %s execution time: %f seconds\n", sig_scheme, ((double)(end - start)) / CLOCKS_PER_SEC);

  // #####################################################################################
  //  Create cJSON
  // #####################################################################################
  char *encoded_sig;
  char *b64_encoded_pk;
  char* alg_id;
  if (dilithium)
  {
    start = clock();
    // signature
    encoded_sig = encode(dilithium_signature, CRYPTO_BYTES);
    end = clock();
    printf("Encode signature Dilithium execution time: %f seconds\n", ((double)(end - start)) / CLOCKS_PER_SEC);

    // public key
    start = clock();
    b64_encoded_pk = encode(dilithium_pub_pk, CRYPTO_PUBLICKEYBYTES);
    end = clock();
    printf("Encode PK Dilithium execution time: %f seconds\n", ((double)(end - start)) / CLOCKS_PER_SEC);

    
    start = clock();
    if (strcmp(CRYPTO_ALGNAME, "Dilithium2") == 0) {
      alg_id = "D2";
    } else if (strcmp(CRYPTO_ALGNAME, "Dilithium3") == 0) {
      alg_id = "D3";
    } else if (strcmp(CRYPTO_ALGNAME, "Dilithium5") == 0){
      alg_id = "D5";
    }
  }
  else
  {
    start = clock();
    // signature
    encoded_sig = encode(fc->sig, fc->sig_len);
    end = clock();
    printf("Encode signature Falcon execution time: %f seconds\n", ((double)(end - start)) / CLOCKS_PER_SEC);

    // public key
    start = clock();
    b64_encoded_pk = encode(fc->pk, FALCON_PUBKEY_SIZE(fc->logn));
    end = clock();
    printf("Encode PK Falcon execution time: %f seconds\n", ((double)(end - start)) / CLOCKS_PER_SEC);
    
    start = clock();
    if (logn == 9) {
      alg_id = "F512";
    }
    else if (logn == 10) {
      alg_id = "F1024";
    }
  }

  cJSON *root = cJSON_CreateObject();
  cJSON_AddStringToObject(root, "m", cfg.message);
  cJSON_AddStringToObject(root, "id", clientID);
  cJSON_AddNumberToObject(root, "t", timestamp.tv_sec);
  cJSON_AddNumberToObject(root, "t2", timestamp.tv_usec);
  cJSON_AddStringToObject(root, "a", alg_id);
  cJSON_AddStringToObject(root, "s", encoded_sig);
  cJSON_AddStringToObject(root, "pk", b64_encoded_pk);

  char *jsonString = cJSON_PrintUnformatted(root);
  size_t allocatedSize = strlen(jsonString) + 1;
  
  rc = my_publish(mosq, &mid_sent, cfg.topic, allocatedSize, jsonString, cfg.qos, cfg.retain);

  mosquitto_destroy(mosq);
  cJSON_Delete(root);
  free(jsonString);
  free(b64_encoded_pk);
  free(encoded_sig);
  end = clock();
  printf("Generating cJSON execution time: %f seconds\n", ((double)(end - start)) / CLOCKS_PER_SEC);

cleanup:
  mosquitto_lib_cleanup();
  client_config_cleanup(&cfg);
  pub_shared_cleanup();
  return 1;
}
