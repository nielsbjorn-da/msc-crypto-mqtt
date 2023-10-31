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

// Time variables
clock_t start, end;

char clientID[23] = "publisher_client";

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

// Falcon variables //
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

int load_client_key(uint8_t *key_array, char *client_id, char *key_type)
{
  size_t key_length;
  char path[100];
  strcpy(path, "../src/keys/");
  if (dilithium)
  {
    strcat(path, CRYPTO_ALGNAME);
    strcat(path, "_");
    if (strcmp("pk", key_type) == 0)
    {
      key_length = CRYPTO_PUBLICKEYBYTES;
    }
    else
    {
      key_length = CRYPTO_SECRETKEYBYTES;
    }
  }
  else
  {
    if (logn == 9)
    {
      strcat(path, "falcon512_");
    }
    else if (logn == 10)
    {
      strcat(path, "falcon1024_");
    }

    if (strcmp("pk", key_type) == 0)
    {
      key_length = FALCON_PUBKEY_SIZE(logn);
    }
    else
    {
      key_length = FALCON_PRIVKEY_SIZE(logn);
    }
  }
  strcat(path, client_id);
  strcat(path, "_");
  strcat(path, key_type);
  strcat(path, ".bin");

  FILE *file = fopen(path, "rb");
  if (file == NULL)
  {
    perror("Failed to open file");
    return -1;
  }
  size_t bytes_read = fread(key_array, sizeof(uint8_t), key_length, file);
  if (bytes_read != key_length)
  {
    perror("Failed to read key content from file");
    fclose(file);
    return -1;
  }
  fclose(file);

  return 0;
}

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
  // printf("Security: %4u bytes\n", 1u << logn);
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
  fc->sig = xmalloc(FALCON_SIG_PADDED_SIZE(fc->logn));
  fc->sig_len = 0;
  fc->sigct = xmalloc(FALCON_SIG_CT_SIZE(fc->logn));
  fc->sigct_len = 0;

  // printf("Start key gen\n");
  /*if (falcon_keygen_make(&fc->rng, fc->logn,
                         fc->sk, FALCON_PRIVKEY_SIZE(fc->logn),
                         fc->pk, FALCON_PUBKEY_SIZE(fc->logn),
                         fc->tmp, fc->tmp_len) != 0)
  {
    fprintf(stderr, "Key generation failed\n");
    exit(EXIT_FAILURE);
  }*/
  // printf("end key gen\n");

  // int r = falcon_get_logn(fc->pk, pk_len);
  // printf("Security of public key is %d, corresponding to %4u bytes security\n", r, 1u << r);
}

/*
  Falcon signing function
*/
int falcon_sign_message(FalconContext *fc, char *payload, int payload_len)
{
  // printf("start sign: %s \n", payload);
  fc->sig_len = FALCON_SIG_PADDED_SIZE(fc->logn);
  int result = falcon_sign_dyn(&fc->rng,
                               fc->sig, &fc->sig_len, FALCON_SIG_PADDED,
                               fc->sk, FALCON_PRIVKEY_SIZE(fc->logn),
                               payload, payload_len, fc->tmp, fc->tmp_len);
  // printf("end sign with result: %d\n", result);
  return result;
}

int falcon_verify_message(FalconContext *fc, char *payload, int payload_len)
{
  // printf("start verify\n");
  int result = falcon_verify(
      fc->sig, fc->sig_len, FALCON_SIG_PADDED,
      fc->pk, pk_len,
      payload, payload_len, fc->tmp, fc->tmp_len);
  // printf("end verify with result: %d\n", result);
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

char *encode(uint8_t *input, size_t input_size)
{
  // int SIZE = 4;
  /* set up a destination buffer large enough to hold the encoded data */
  char *output = (char *)malloc(input_size * 2);
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
  // Measure total time of application
  struct timeval total_timestamp;
  gettimeofday(&total_timestamp, NULL);

  FalconContext *fc = malloc(sizeof(FalconContext));
  size_t sig_length;
  char qos_str[10];          // Adjust the size based on your maximum expected qos value
  char current_time_str[20]; // Adjust the size based on your maximum expected time value
  int message_len;

  struct timeval end_time;
  struct timeval start_time;
  double time_taken;

  // Measure time for initialization
  gettimeofday(&start_time, NULL);

  if (dilithium)
  {
    // printf("Signature algorithm: Dilithium\n");
    // crypto_sign_keypair(dilithium_pub_pk, dilithium_pub_sk); // gen keys
    int i;
  }
  else
  {
    // printf("Signature algorithm: Falcon\n");
    if (fc == NULL)
    {
      fprintf(stderr, "Memory allocation for Falcon failed\n");
      exit(EXIT_FAILURE);
    }
    // printf("initialzing Falcon \n");
    initialize_falcon_struct(fc);
  }

  gettimeofday(&end_time, NULL);
  time_taken = (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_usec - start_time.tv_usec) / 1e9;
  printf("Initialization time: %.9f seconds.\n", time_taken);

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
  // #####################################################################################
  //  Creating the message to sign
  // #####################################################################################
  // timestamp
  gettimeofday(&start_time, NULL);
  // Convert int qos to string
  snprintf(current_time_str, sizeof(current_time_str), "%d", total_timestamp.tv_sec);

  message_len = strlen(cfg.message) + strlen(cfg.topic) + strlen(current_time_str) + strlen(clientID);
  char concatenated_message_to_sign[10000 + 1]; // +1 for the null terminator
  // TODO Hvorfor ikke bare bruge message_len i stedet for 10000 ??
  concatenated_message_to_sign[0] = '\0';

  strcat(concatenated_message_to_sign, cfg.message);
  strcat(concatenated_message_to_sign, cfg.topic);
  strcat(concatenated_message_to_sign, current_time_str);
  strcat(concatenated_message_to_sign, clientID);

  gettimeofday(&end_time, NULL);
  time_taken = (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_usec - start_time.tv_usec) / 1e9;
  printf("Generating message concat execution time: %.9f seconds.\n", time_taken);
  // #####################################################################################
  //  Run the signing algorithms
  // #####################################################################################
  char *sig_scheme;
  gettimeofday(&start_time, NULL);
  if (dilithium)
  {
    sig_scheme = "Dilithium";
    load_client_key(dilithium_pub_sk, clientID, "sk");

    dilithium_sign_message(dilithium_signature, concatenated_message_to_sign, message_len);
  }
  else
  {
    sig_scheme = "Falcon";
    load_client_key(fc->sk, clientID, "sk");
    // load_client_key(fc->pk, clientID, "pk");
    if (falcon_sign_message(fc, &concatenated_message_to_sign, message_len) != 0)
    {
      fprintf(stderr, "Signing message for Falcon failed\n");
      exit(EXIT_FAILURE);
    }
  }

  gettimeofday(&end_time, NULL);
  time_taken = (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_usec - start_time.tv_usec) / 1e9;
  printf("Signing message %s execution time: %.9f seconds.\n", sig_scheme, time_taken);

  // #####################################################################################
  //  Create cJSON
  // #####################################################################################

  char *encoded_sig;
  char *b64_encoded_pk;
  char *decoded;

  gettimeofday(&start_time, NULL);
  if (dilithium)
  {
    encoded_sig = encode(dilithium_signature, CRYPTO_BYTES);
  }
  else
  {
    encoded_sig = encode(fc->sig, fc->sig_len);
  }

  gettimeofday(&end_time, NULL);
  time_taken = (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_usec - start_time.tv_usec) / 1e9;
  printf("Encode signature %s execution time: %.9f seconds.\n", sig_scheme, time_taken);

  gettimeofday(&start_time, NULL);
  char *alg_id;
  if (dilithium)
  {
    if (strcmp(CRYPTO_ALGNAME, "Dilithium2") == 0)
    {
      alg_id = "D2";
    }
    else if (strcmp(CRYPTO_ALGNAME, "Dilithium3") == 0)
    {
      alg_id = "D3";
    }
    else if (strcmp(CRYPTO_ALGNAME, "Dilithium5") == 0)
    {
      alg_id = "D5";
    }
  }
  else
  {
    if (logn == 9)
    {
      alg_id = "F512";
    }
    else if (logn == 10)
    {
      alg_id = "F1024";
    }
  }

  cJSON *root = cJSON_CreateObject();
  cJSON_AddStringToObject(root, "m", cfg.message);
  //gettimeofday(&total_timestamp, NULL); // Un commet if latency should be measured

  cJSON_AddNumberToObject(root, "t", total_timestamp.tv_sec);
  cJSON_AddNumberToObject(root, "t2", total_timestamp.tv_usec);
  cJSON_AddStringToObject(root, "a", alg_id);
  cJSON_AddStringToObject(root, "s", encoded_sig);

  char *jsonString = cJSON_PrintUnformatted(root);
  size_t allocatedSize = strlen(jsonString) + 1;

  rc = my_publish(mosq, &mid_sent, cfg.topic, allocatedSize, jsonString, cfg.qos, cfg.retain);

  cJSON_Delete(root);
  free(jsonString);
  free(b64_encoded_pk);
  free(encoded_sig);
  mosquitto_destroy(mosq);

  gettimeofday(&end_time, NULL);
  time_taken = (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_usec - start_time.tv_usec) / 1e9;
  printf("Generating cJSON execution time: %.9f seconds.\n", sig_scheme, time_taken);

cleanup:
  mosquitto_lib_cleanup();
  client_config_cleanup(&cfg);
  pub_shared_cleanup();
  return 1;
}
