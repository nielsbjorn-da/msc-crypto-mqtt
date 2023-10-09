#include <stdio.h>
#include <time.h>

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


#include "dilithium_and_falcon/dilithium/dilithium-master/ref/randombytes.h"
#include "dilithium_and_falcon/dilithium/dilithium-master/ref/sign.h"
#include <cjson/cJSON.h>
#include "libb64/include/b64/cencode.h"
#include "libb64/include/b64/cdecode.h"

#include <openssl/bio.h>

// dilithium variables
uint8_t pub_pk[CRYPTO_PUBLICKEYBYTES];
uint8_t pub_sk[CRYPTO_SECRETKEYBYTES];

struct timeval timestamp;

//
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




char* b64_encode_3_byte(uint8_t *input) {
  int SIZE = 4;
  /* set up a destination buffer large enough to hold the encoded data */
	char* output = (char*)malloc(SIZE);
	/* keep track of our encoded position */
	char* c = output;
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

  //printf("test:");
  //printf("input: %u, %u, %u, output: %s", input[0], input[1], input[2], output);
  //printf("\n");
  return output;
}

char* b64_encode(uint8_t *input, int input_size)  
{
  int i = 0;
  char* output = (char*)malloc(input_size*1.5);
  output[0] = '\0';
  while(i<input_size && i+3 < input_size) {
    uint8_t current_3_bytes[3] = {input[i], input[i+1], input[i+2]};
    char *encoding = b64_encode_3_byte(current_3_bytes);
    strcat(output, encoding);

    // Free the dynamically allocated encoding
    free(encoding);
    i+=3;
  }
  uint8_t remaining_bytes[3];
  int j = 0;
  while (i<input_size) {
    remaining_bytes[j] = input[i];
    i++;
    j++;
  }
  char *encoding = b64_encode_3_byte(remaining_bytes);
  strcat(output, encoding);
  // Free the dynamically allocated encoding
  free(encoding);

  return output;
}

void b64decode_3_bytes() {
  /* set up a destination buffer large enough to hold the encoded data */
  char *input = "qgun";
  int SIZE = 4;
	char* output = (char*)malloc(SIZE);
	/* keep track of our decoded position */
	char* c = output;
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
  printf("output: %u, %u, %u, input: %s", (uint8_t) output[0], output[1], output[2], input);
  printf("\n");
  free(output);
}

int test_dilithium() {
    printf("Hello   world\n");
    size_t i, j;
    int ret;
    size_t mlen, smlen;
    uint8_t b;

    char message[] = "Hello there my friend";
    uint8_t MLEN = sizeof(message);

    uint8_t m[MLEN + CRYPTO_BYTES];
    uint8_t m2[MLEN + CRYPTO_BYTES];
    uint8_t sm[MLEN + CRYPTO_BYTES];
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];

    uint8_t pk2[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk2[CRYPTO_SECRETKEYBYTES];
    
    
    randombytes(m, MLEN);
    clock_t start_time, end_time;
    double cpu_time_used;
    start_time = clock();
    crypto_sign_keypair(pk, sk);
    end_time = clock();
    cpu_time_used = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
    printf("Key gen time: %f\n", cpu_time_used);
    crypto_sign_keypair(pk2, sk2);
    printf("pk: %p \n", pk);
    crypto_sign(sm, &smlen, message, MLEN, sk);
    printf("signature: %p \n", sm);
    ret = crypto_sign_open(m2, &mlen, sm, smlen, pk);
    
    if(ret) {
      fprintf(stderr, "Verification failed\n");
      return -1;
    }
    if(smlen != MLEN + CRYPTO_BYTES) {
      fprintf(stderr, "Signed message lengths wrong\n");
      return -1;
    }
    if(mlen != MLEN) {
      fprintf(stderr, "Message lengths wrong\n");
      return -1;
    }
    for(j = 0; j < MLEN; ++j) {
      if(m2[j] != message[j]) {
        fprintf(stderr, "Messages don't match\n");
        return -1;
      }
    }
    printf("verify successfull \n");
    printf("CRYPTO_PUBLICKEYBYTES = %d\n", CRYPTO_PUBLICKEYBYTES);
    printf("CRYPTO_SECRETKEYBYTES = %d\n", CRYPTO_SECRETKEYBYTES);
    printf("CRYPTO_BYTES = %d\n", CRYPTO_BYTES);

    printf("printing message\n");
    for(j = 0; j < MLEN; ++j) {
      printf("%u ", message[j]);
      printf("%u ", m2[j]);
    }
    printf(m2);
    printf("\nmessage length: %lu \n", j);

    printf("printing public key\n");
    for(j = 0; j < CRYPTO_PUBLICKEYBYTES; ++j) {
      printf("%u ", pk[j]);
    }
    printf("\nPK length: %lu \n", j);

    printf("printing private key\n");
    for(j = 0; j < CRYPTO_SECRETKEYBYTES; ++j) {
      printf("%u ", sk[j]);
    }
    printf("\nSK length: %lu \n", j);


    return 0;
}

void pub_shared_cleanup(void)
{
	free(line_buf);
}

int pub_shared_init(void)
{
	line_buf = malloc((size_t )line_buf_len);
	if(!line_buf){
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
	if(cfg.protocol_version == MQTT_PROTOCOL_V5 && cfg.have_topic_alias && first_publish == false){
		return mosquitto_publish_v5(mosq, mid, NULL, payloadlen, payload, qos, retain, cfg.publish_props);
	}else{
		first_publish = false;
		return mosquitto_publish_v5(mosq, mid, topic, payloadlen, payload, qos, retain, cfg.publish_props);
	}
}

int sign_message(uint8_t *sm, const char *payload, int payloadlen) 
{

  printf(payload);
  
  size_t i, j;
  int ret;
  size_t mlen, smlen;
  uint8_t MLEN = payloadlen;
  uint8_t m[MLEN + CRYPTO_BYTES];
  uint8_t m2[MLEN + CRYPTO_BYTES];
  //uint8_t sm[MLEN + CRYPTO_BYTES];

  memcpy(m, &payload, MLEN);

  crypto_sign(sm, &smlen, m, MLEN, pub_sk);
  ret = crypto_sign_open(m2, &mlen, sm, smlen, pub_pk);

  
  if(ret) {
    fprintf(stderr, "Verification failed\n");
    return -1;
  }
  if(smlen != MLEN + CRYPTO_BYTES) {
    fprintf(stderr, "Signed message lengths wrong\n");
    return -1;
  }
  if(mlen != MLEN) {
    fprintf(stderr, "Message lengths wrong\n");
    return -1;
  }
  for(j = 0; j < MLEN; ++j) {
    if(m2[j] != m[j]) {
      fprintf(stderr, "Messages don't match\n");
      // Don't forget to free the allocated memory
      return -1;
    }
  }
  printf("verify successfull \n");
  return 0;
}

int verify(uint8_t *sig, size_t smlen, char* message, int message_len)
{
  int ret;
  size_t mlen;
  uint8_t MLEN = message_len;
  uint8_t m[MLEN + CRYPTO_BYTES];
  uint8_t m2[MLEN + CRYPTO_BYTES];

  memcpy(m, &message, MLEN);
  ret = crypto_sign_open(m2, &mlen, sig, smlen, pub_pk);
  
  if(ret) {
    fprintf(stderr, "Verification failed\n");
    return -1;
  }
  if(smlen != MLEN + CRYPTO_BYTES) {
    fprintf(stderr, "Signed message lengths wrong\n");
    return -1;
  }
  if(mlen != MLEN) {
    fprintf(stderr, "Message lengths wrong\n");
    return -1;
  }
  for(int j = 0; j < MLEN; ++j) {
    if(m2[j] != m[j]) {
      fprintf(stderr, "Messages don't match\n");
      // Don't forget to free the allocated memory
      return -1;
    }
  }
  printf("verify successfull \n");
  return 0;
}

char* encode(const char* input, size_t size)
{
  
	/* set up a destination buffer large enough to hold the encoded data */
	//char* output = (char*)malloc(size);
	/* keep track of our encoded position */
	//char* c = output;
	/* store the number of bytes encoded by a single call */
	int cnt = 0;
	/* we need an encoder state */
	base64_encodestate s;
	base64_init_encodestate(&s);
  size_t si = base64_encode_length(size, &s);
  //printf("Encode lenght %u", (int)si);
  //printf(sizeof(input));
  char* output = (char*)malloc(si);
	/* keep track of our encoded position */
	char* c = output;
	
	/*---------- START ENCODING ----------*/
	/* initialise the encoder state */
	/* gather data from the input and send it to the output */
	cnt = base64_encode_block(input, strlen(input), c, &s);
	c += cnt;
	/* since we have encoded the entire input string, we know that 
	   there is no more input data; finalise the encoding */
	cnt = base64_encode_blockend(c, &s);
	c += cnt;
	/*---------- STOP ENCODING  ----------*/
	
	/* we want to print the encoded data, so null-terminate it: */
	*c = 0;
	
	return output;
}

char* decode(const char* input, size_t size)
{
	/* set up a destination buffer large enough to hold the encoded data */
	
	/* keep track of our decoded position */
	
	/* store the number of bytes decoded by a single call */
	int cnt = 0;
	/* we need a decoder state */
	base64_decodestate s;
	base64_init_decodestate(&s);
  size_t si = base64_encode_length(size, &s);
  char* output = (char*)malloc(si);
  char* c = output;
	
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

int main(int argc, char *argv[]) {
  //"test_dilithium();

  //b64decode_3_bytes();
  crypto_sign_keypair(pub_pk, pub_sk); //gen keys
  int i;
    
    //timestamp
  gettimeofday(&timestamp,NULL);
  time_t current_time = timestamp.tv_sec;

  char* concatenated_message_to_sign = cfg.message; //should be a function that creates metadata message to be signed
  // of cfg.message, cfg.msglen, cfg.topic, cfg.qos, cfg.retain, clientID
  int message_len = sizeof(concatenated_message_to_sign);
  size_t sig_length = message_len + CRYPTO_BYTES;
  uint8_t signature[sig_length];
  
  struct mosquitto *mosq = NULL;
	int rc;
  
  mosquitto_lib_init();

	if(pub_shared_init()) return 1;

	rc = client_config_load(&cfg, CLIENT_PUB, argc, argv);
	if(rc){
		if(rc == 2){
			/* --help */
			print_usage();
		}else if(rc == 3){
			print_version();
		}else{
			fprintf(stderr, "\nUse 'mosquitto_pub --help' to see usage.\n");
		}
		goto cleanup;
	}

  if(cfg.pub_mode == MSGMODE_STDIN_FILE){
		if(load_stdin()){
			err_printf(&cfg, "Error loading input from stdin.\n");
			goto cleanup;
		}
	}else if(cfg.file_input){
		if(load_file(cfg.file_input)){
			err_printf(&cfg, "Error loading input file \"%s\".\n", cfg.file_input);
			goto cleanup;
		}
	}

	if(!cfg.topic || cfg.pub_mode == MSGMODE_NONE){
		fprintf(stderr, "Error: Both topic and message must be supplied.\n");
		print_usage();
		goto cleanup;
	}

  if(client_id_generate(&cfg)){
		goto cleanup;
	}
  char clientID[23] = "publisher_client";
  mosq = mosquitto_new(clientID, false, NULL);
	if(!mosq){
		switch(errno){
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
	//mosquitto_disconnect_v5_callback_set(mosq, my_disconnect_callback);
	//mosquitto_publish_v5_callback_set(mosq, my_publish_callback);

  if(client_opts_set(mosq, &cfg)){
		goto cleanup;
	}

	rc = client_connect(mosq, &cfg);
	if(rc){
    printf("RC client connect");
		goto cleanup;
	}
  printf("after connect\n");

  sign_message(signature, concatenated_message_to_sign, message_len);
  verify(signature, sig_length, concatenated_message_to_sign, message_len);

  //create json to publish
  cJSON *root = cJSON_CreateObject();
  cJSON_AddStringToObject(root, "data", cfg.message);
  cJSON_AddStringToObject(root, "id", clientID);
  cJSON_AddNumberToObject(root, "time", current_time);

  //signature
  char* encoded_sig = b64_encode(signature, CRYPTO_BYTES);
  //printf("b64 sig: %s \n", encoded_sig);
  printf("\nb64encoded length %u\n", strlen(encoded_sig));
  cJSON_AddStringToObject(root, "sig", encoded_sig);
  /*char* decoded_sig = decode(encoded_sig, CRYPTO_BYTES);
  for(int j = 0; j < CRYPTO_BYTES; ++j) {
    printf("%u %u \n", (uint8_t) decoded_sig[j], signature[j]);
  }
  free(decoded_sig)*/

  //public key
  char* b64_encoded_pk = b64_encode(pub_pk, CRYPTO_PUBLICKEYBYTES);
  //printf("b64: %s \n", b64_encoded_pk);
  printf("\nb64encoded length %u\n", strlen(b64_encoded_pk));
  char* decoded;
  cJSON_AddStringToObject(root, "pk", b64_encoded_pk);
/*
  decoded = decode(b64_encoded_pk, CRYPTO_PUBLICKEYBYTES);
  printf("printing public key\n");
  for(int j = 0; j < CRYPTO_PUBLICKEYBYTES; ++j) {
    printf("%u %u \n", (uint8_t) decoded[j], pub_pk[j]);
  }
  free(decoded);
*/

  /*
  char* encoded_sig = encode(signature, dilith2_sig_size);
  printf("encoded sig: %s \n", encoded_sig);
  cJSON_AddStringToObject(root, "sig", encoded_sig);
*/


  char *jsonString = cJSON_PrintUnformatted(root);
  size_t allocatedSize = strlen(jsonString) + 1;
  printf("Allocated size: %zu bytes\n", allocatedSize);
  printf(jsonString);
  //rc = my_publish(mosq, &mid_sent, cfg.topic, cfg.msglen, cfg.message, cfg.qos, cfg.retain);
  rc = my_publish(mosq, &mid_sent, cfg.topic, allocatedSize, jsonString, cfg.qos, cfg.retain);

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
//cc own_test.c -o ownTest randombytes.c sign.c packing.c polyvec.c poly.c ntt.c reduce.c rounding.c fips202.c symmetric-shake.c 