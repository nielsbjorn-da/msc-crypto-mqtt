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

struct timeval timestamp;

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
unsigned logn = 9;
size_t pk_len = FALCON_PUBKEY_SIZE(9);
size_t len = FALCON_TMPSIZE_KEYGEN(9);

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

char *b64_encode_3_byte(uint8_t *input)
{
  int SIZE = 4;
  /* set up a destination buffer large enough to hold the encoded data */
  char *output = (char *)malloc(SIZE);
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
  cnt = base64_encode_block(input, 3, c, &s);
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

char *b64_encode(uint8_t *input, int input_size)
{
  int i = 0;
  char* output = (char*)malloc(input_size*1.5);
  memset(output, 0, sizeof(output));
  while (i < input_size)
  {
    uint8_t current_3_bytes[3] = {input[i], input[i + 1], input[i + 2]};
    char *encoding = b64_encode_3_byte(current_3_bytes);
    strcat(output, encoding);

    // Free the dynamically allocated encoding
    free(encoding);
    i += 3;
  }

  return output;
}

void b64decode_3_bytes()
{
  /* set up a destination buffer large enough to hold the encoded data */
  char *input = "qgun";
  int SIZE = 4;
  char *output = (char *)malloc(SIZE);
  /* keep track of our decoded position */
  char *c = output;
  /* store the number of bytes decoded by a single call */
  int cnt = 0;
  /* we need a decoder state */
  base64_decodestate s;

  /*---------- START DECODING ----------*/
  /* initialise the decoder state */
  base64_init_decodestate(&s);
  /* decode the input data */
  cnt = base64_decode_block(input, strlen(input), c, &s);
  c += cnt;
  /* note: there is no base64_decode_blockend! */
  /*---------- STOP DECODING  ----------*/

  /* we want to print the decoded data, so null-terminate it: */
  *c = 0;
  printf("output: %u, %u, %u, input: %s", (uint8_t)output[0], output[1], output[2], input);
  printf("\n");
  free(output);
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
  
  if (ret) {
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

  if(ret) {
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
  printf("Security: %4u bytes\n", 1u << logn);
  fflush(stdout);

  // Creating SHAKE256 context.
  // This should be done before initialization of keys.
  if (shake256_init_prng_from_system(&fc->rng) != 0)
  {
    fprintf(stderr, "random seeding failed\n");
    exit(EXIT_FAILURE);
  }

  fc->logn = logn;
  len = maxsz(len, FALCON_TMPSIZE_SIGNDYN(fc->logn));
  len = maxsz(len, FALCON_TMPSIZE_SIGNTREE(fc->logn));
  len = maxsz(len, FALCON_TMPSIZE_EXPANDPRIV(fc->logn));
  len = maxsz(len, FALCON_TMPSIZE_VERIFY(fc->logn));
  fc->tmp = xmalloc(len);
  fc->tmp_len = len;
  fc->pk = xmalloc(FALCON_PUBKEY_SIZE(fc->logn));
  fc->sk = xmalloc(FALCON_PRIVKEY_SIZE(fc->logn));
  fc->esk = xmalloc(FALCON_EXPANDEDKEY_SIZE(fc->logn));
  fc->sig = xmalloc(FALCON_SIG_COMPRESSED_MAXSIZE(fc->logn));
  fc->sig_len = 0;
  fc->sigct = xmalloc(FALCON_SIG_CT_SIZE(fc->logn));
  fc->sigct_len = 0;

  // printf("Start key gen\n");
  if (falcon_keygen_make(&fc->rng, fc->logn,
                         fc->sk, FALCON_PRIVKEY_SIZE(fc->logn),
                         fc->pk, FALCON_PUBKEY_SIZE(fc->logn),
                         fc->tmp, fc->tmp_len) != 0)
  {
    fprintf(stderr, "Key generation failed\n");
    exit(EXIT_FAILURE);
  }
  // printf("end key gen\n");

  int r = falcon_get_logn(fc->pk, pk_len);
  printf("Security of public key is %d, corresponding to %4u bytes security\n", r, 1u << r);
}

/*
  Falcon signing function
*/
int falcon_sign_message(FalconContext *fc, char *payload, int payload_len)
{
  printf("start sign\n");
  fc->sig_len = FALCON_SIG_COMPRESSED_MAXSIZE(fc->logn);
  int result = falcon_sign_dyn(&fc->rng,
                               fc->sig, &fc->sig_len, FALCON_SIG_COMPRESSED,
                               fc->sk, FALCON_PRIVKEY_SIZE(fc->logn),
                               payload, payload_len, fc->tmp, fc->tmp_len);
  printf("end sign with result: %d\n", result);
  return result;
}

int falcon_verify_message(FalconContext *fc, char *payload, int payload_len)
{
  printf("start verify\n");
  int result = falcon_verify(
      fc->sig, fc->sig_len, FALCON_SIG_COMPRESSED,
      fc->pk, pk_len,
      payload, payload_len, fc->tmp, fc->tmp_len);
  printf("end verify with result: %d\n", result);
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

int main(int argc, char *argv[])
{
  FalconContext *fc = malloc(sizeof(FalconContext));
  size_t sig_length;
  uint8_t signature[sig_length];
  char qos_str[10];          // Adjust the size based on your maximum expected qos value
  char current_time_str[20]; // Adjust the size based on your maximum expected qos value
  int message_len;
  

  if (dilithium == true)
  {
    printf("Signature algorithm: Dilithium\n");
    crypto_sign_keypair(dilithium_pub_pk, dilithium_pub_sk); // gen keys
    int i;
  }
  else if (dilithium == false)
  {
    printf("Signature algorithm: Falcon\n");
    if (fc == NULL)
    {
      fprintf(stderr, "Memory allocation for Falcon failed\n");
      exit(EXIT_FAILURE);
    }
    printf("initialzing Falcon \n");
    initialize_falcon_struct(fc);
  }

  // timestamp
  gettimeofday(&timestamp, NULL);
  time_t current_time = timestamp.tv_sec;

  char clientID[23] = "publisher_client";

  struct mosquitto *mosq = NULL;
  int rc;

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

  printf("Ready to connect\n");
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
  printf("after connect\n");

  // Convert int qos to string
  snprintf(qos_str, sizeof(qos_str), "%d", cfg.qos);

  // Convert int qos to string
  snprintf(current_time_str, sizeof(current_time_str), "%d", current_time);

  message_len = strlen(cfg.message) + strlen(cfg.topic) + strlen(qos_str) + strlen(current_time_str) + strlen(clientID);
  char concatenated_message_to_sign[10000 + 1]; // +1 for the null terminator
  concatenated_message_to_sign[0] = '\0';

  printf("concat string 0: %s\n", concatenated_message_to_sign);
  strcat(concatenated_message_to_sign, cfg.message);
  printf("To be added: %s\n", cfg.message);
  printf("concat string 1: %s\n", concatenated_message_to_sign);
  strcat(concatenated_message_to_sign, cfg.topic);
  printf("To be added: %s\n", cfg.topic);
  printf("concat string 2: %s\n", concatenated_message_to_sign);
  strcat(concatenated_message_to_sign, qos_str);
  printf("To be added: %s\n", qos_str);
  printf("concat string 3: %s\n", concatenated_message_to_sign);
  strcat(concatenated_message_to_sign, current_time_str);
  printf("To be added: %s\n", current_time_str);
  printf("concat string 4: %s\n", concatenated_message_to_sign);
  strcat(concatenated_message_to_sign, clientID);
  printf("To be added: %s\n", clientID);
  printf("concat string 5: %s\n", concatenated_message_to_sign);

  if (dilithium == true)
  {
    dilithium_sign_message(dilithium_signature, concatenated_message_to_sign, message_len);
    dilithium_verify(dilithium_signature, concatenated_message_to_sign, message_len, dilithium_pub_pk);
  }
  else if (dilithium == false)
  {
    if (falcon_sign_message(fc, &concatenated_message_to_sign, message_len) != 0)
    {
      fprintf(stderr, "Signing message for Falcon failed\n");
      exit(EXIT_FAILURE);
    }

    if (falcon_verify_message(fc, &concatenated_message_to_sign, message_len) != 0)
    {
      fprintf(stderr, "verifying message for Falcon failed\n");
      exit(EXIT_FAILURE);
    }
  }
  // create json to publish
  cJSON *root = cJSON_CreateObject();
  cJSON_AddStringToObject(root, "data", cfg.message);
  
  cJSON_AddStringToObject(root, "topic", cfg.topic);
  cJSON_AddStringToObject(root, "id", clientID);
  cJSON_AddNumberToObject(root, "time", current_time);
  cJSON_AddNumberToObject(root, "qos", cfg.qos);
  cJSON_AddNumberToObject(root, "sig_len", fc->sig_len);
  
  char *encoded_sig;
  char *b64_encoded_pk;
  char *decoded;

  if (dilithium == true)
  {
    // signature
    encoded_sig = b64_encode(dilithium_signature, CRYPTO_BYTES);

    printf("\nb64encoded length %u\n", strlen(encoded_sig));
    cJSON_AddStringToObject(root, "sig", encoded_sig);

    // public key
    b64_encoded_pk = b64_encode(dilithium_pub_pk, CRYPTO_PUBLICKEYBYTES);
    printf("\nb64encoded length %u\n", strlen(b64_encoded_pk));

    cJSON_AddStringToObject(root, "pk", b64_encoded_pk);
  }
  else if (dilithium == false)
  {
    // signature
    encoded_sig = b64_encode(fc->sig, fc->sig_len);

    printf("\nb64encoded length %u\n", strlen(encoded_sig));
    cJSON_AddStringToObject(root, "sig", encoded_sig);

    // public key
    b64_encoded_pk = b64_encode(fc->pk, FALCON_PUBKEY_SIZE(fc->logn));

    printf("\nb64encoded length %u\n", strlen(b64_encoded_pk));
    cJSON_AddStringToObject(root, "pk", b64_encoded_pk);

    char* decode_sig = decode(encoded_sig, fc->sig_len);
    char* decode_pk = decode(b64_encoded_pk, pk_len);

    fc->pk = decode_pk;
    fc->sig = decode_sig;
    printf("Length of encoded signature %d\n", strlen(encoded_sig));
		printf("Length of decoded signature %d\n", strlen(decode_sig));
    printf("Length of message %d\n", strlen(&concatenated_message_to_sign));

    if (falcon_verify_message(fc, &concatenated_message_to_sign, message_len) != 0)
    {
      fprintf(stderr, "verifying message for Falcon failed\n");
      exit(EXIT_FAILURE);
    }

    //printf("Encode pk: %s\n", b64_encoded_pk);
		//printf("Decode pk: %s\n", decode_pk);
		//printf("Encode sig: %s\n", encoded_sig);

		//printf("Decode sig: %s\n", decode_sig);
    printf("Length of decoded signature variable %d", strlen(decode_sig));
    printf("Length of signature %d\n", strlen(fc->sig));
		printf("Max length of signature in bytes: %d\n", fc->sig_len);
		printf("Concatinated message %s\n", concatenated_message_to_sign);
		printf("Length of concatinated message %d\n", strlen(concatenated_message_to_sign));
		printf("Length of message len %d\n", message_len);

    //printf("IT WORKED, hahaha simon\n");
    

  }

    char *jsonString = cJSON_PrintUnformatted(root);
    size_t allocatedSize = strlen(jsonString) + 1;
    //printf("Allocated size: %zu bytes\n", allocatedSize);
    //printf(jsonString);
    

    rc = my_publish(mosq, &mid_sent, cfg.topic, allocatedSize, jsonString, cfg.qos,true);

    cJSON_Delete(root);
    free(jsonString);
    free(b64_encoded_pk);
    free(encoded_sig);
    printf("after publish\n");

    mosquitto_destroy(mosq);

  cleanup:
    mosquitto_lib_cleanup();
    client_config_cleanup(&cfg);
    pub_shared_cleanup();
    return 1;
  }