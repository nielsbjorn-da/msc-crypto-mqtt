/*
Copyright (c) 2009-2020 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

Contributors:
   Roger Light - initial implementation and documentation.
*/

#include "config.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "mosquitto_broker_internal.h"
#include "alias_mosq.h"
#include "mqtt_protocol.h"
#include "memory_mosq.h"
#include "packet_mosq.h"
#include "property_mosq.h"
#include "read_handle.h"
#include "send_mosq.h"
#include "sys_tree.h"
#include "util_mosq.h"

#include "../client/dilithium_and_falcon/dilithium/dilithium-master/ref/sign.h"
#include "../client/dilithium_and_falcon/dilithium/dilithium-master/ref/randombytes.h"
#include "../client/dilithium_and_falcon/falcon/Falcon-impl-20211101/falcon.h"
#include "../client/libb64/include/b64/cdecode.h"
#include "../client/libb64/include/b64/cencode.h"
#include <cjson/cJSON.h>

uint8_t dilithium_broker_pk[CRYPTO_PUBLICKEYBYTES];
uint8_t dilithium_broker_sk[CRYPTO_SECRETKEYBYTES];
bool dilithium;


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
size_t sk_len = FALCON_PRIVKEY_SIZE(9);
size_t len = FALCON_TMPSIZE_KEYGEN(9);
FalconContext *fc;

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

/*
  Generate secret and public key for Falcon
*/
void initialize_falcon_struct(FalconContext *fc)
{
  //printf("Security: %4u bytes\n", 1u << logn);
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

}

void falcon_keygen(FalconContext *fc) 
{
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
  //printf("Security of public key is %d, corresponding to %4u bytes security\n", r, 1u << r);
}

int generate_and_save_broker_keys(char *signature_scheme)
{
	if (strcmp(signature_scheme, "dilithium") == 0) {
		//log__printf(NULL, MOSQ_LOG_NOTICE, "GEnerate broker dilithium keys");

		crypto_sign_keypair(dilithium_broker_pk, dilithium_broker_sk);
		
		FILE *file = fopen("keys/dilithium_broker_pk.bin", "wb");
		if (file == NULL) {
			perror("Failed to open file");
			return 1;
		}
		
		
		size_t num_elements = sizeof(dilithium_broker_pk) / sizeof(dilithium_broker_pk[0]);
		size_t bytes_written = fwrite(dilithium_broker_pk, sizeof(uint8_t), num_elements, file);
		if (bytes_written != num_elements) {
			perror("Failed to write data to file");
			fclose(file);
			return 1;
		}

		
		fclose(file);
		
		FILE *sk_file = fopen("keys/dilithium_broker_sk.bin", "wb");
		if (sk_file == NULL) {
			perror("Failed to open file");
			return 1;
		}

		// Write the data array to the file
		num_elements = sizeof(dilithium_broker_sk) / sizeof(dilithium_broker_sk[0]);
		bytes_written = fwrite(dilithium_broker_sk, sizeof(uint8_t), num_elements, sk_file);

		if (bytes_written != num_elements) {
			perror("Failed to write data to file");
			fclose(sk_file);
			return 1;
		}

		// Close the file
		fclose(sk_file);
	} else {
		//falcon keygen
		falcon_keygen(fc);
		FILE *file = fopen("keys/falcon_broker_pk.bin", "wb");
		if (file == NULL) {
			perror("Failed to open file");
			return 1;
		}

		// Write the data array to the file
		size_t num_elements = pk_len / sizeof(fc->pk[0]);
		size_t bytes_written = fwrite(fc->pk, sizeof(uint8_t), num_elements, file);
		if (bytes_written != num_elements) {
			perror("Failed to write data to file");
			fclose(file);
			return 1;
		}

		// Close the file
		fclose(file);

		FILE *sk_file = fopen("keys/falcon_broker_sk.bin", "wb");
		if (sk_file == NULL) {
			perror("Failed to open file");
			return 1;
		}

		// Write the data array to the file
		num_elements = sk_len / sizeof(fc->sk[0]);
		bytes_written = fwrite(fc->sk, sizeof(uint8_t), num_elements, sk_file);
		if (bytes_written != num_elements) {
			perror("Failed to write data to file");
			fclose(sk_file);
			return 1;
		}

		fclose(sk_file);
	}
    return 0;
}

int load_broker_key(char *key_type)
{
	
	char path[100] = "";
	size_t key_length;
	uint8_t *key_array;
	strcpy(path, "keys/");

	if (dilithium) {
		strcat(path, "dilithium_broker_");
		if (strcmp("pk", key_type) == 0) {
			strcat(path, "pk.bin");
			key_length = CRYPTO_PUBLICKEYBYTES;
			key_array = dilithium_broker_pk;
		} else {
			strcat(path, "sk.bin");
			key_length = CRYPTO_SECRETKEYBYTES;
			key_array = dilithium_broker_sk;
		}
	} else {
		strcat(path, "falcon_broker_");
		if (strcmp("pk", key_type) == 0) {
			strcat(path, "pk.bin");
			key_length = pk_len;
			key_array = fc->pk;
		} else {
			strcat(path, "sk.bin");
			key_length = sk_len;
			key_array = fc->sk;
		}
	}

	FILE *file = fopen(path, "rb");
	if (file == NULL) {
		perror("Failed to open file");
		return -1;
	}
	size_t bytes_read = fread(key_array, sizeof(uint8_t), key_length, file);
	if (bytes_read != key_length) {
		perror("Failed to read key content from file");
		fclose(file);
		return -1;
	}

	fclose(file);
	return 0;
}

int load_client_pk(uint8_t *key_array, char *client_id) 
{
	char path[100];
	size_t key_length;
	if (dilithium) {
		strcpy(path, "keys/dilithium_");
		key_length = CRYPTO_PUBLICKEYBYTES;
	} else {
		strcpy(path, "keys/falcon_");
		key_length = pk_len;		
	}

	strcat(path, client_id);
	strcat(path, "_pk.bin");
	
	FILE *file = fopen(path, "rb");
	if (file == NULL) {
		perror("Failed to open file");
		return -1;
	}

	size_t bytes_read = fread(key_array, sizeof(uint8_t), key_length, file);
	if (bytes_read != key_length) {
		perror("Failed to read key content from file");
		fclose(file);
		return -1;
	}
	fclose(file);
	return 0;
}

int dilithium_sign_message(uint8_t *signature, const char *message, int message_length)
{
  size_t sig_length;

  int ret = crypto_sign_signature(signature, &sig_length, message, message_length, dilithium_broker_sk);
  
  if (ret) {
    fprintf(stderr, "Signature generation failed\n");
    return -1;
  }
  return ret;
}

int verify_dilithium_signature(uint8_t *signature, const char *message, size_t message_length, uint8_t *public_key)
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

char* create_concat_message(char *message_data_string, time_t timestamp, char *publisher_topic, char *publisher_id)
{
		// Creating the message that were signed
	//#####################################################################################
	// Calculate the length of the converted strings

	int timestamp_length = snprintf(NULL, 0, "%d", timestamp);

	// Allocate memory for the strings dynamically, including space for the null terminator

	char *current_time_str = (char *)malloc(timestamp_length + 1);
	current_time_str[0] = '\0';

	// Check if memory allocation was successful
	if (current_time_str == NULL)
	{
		// Handle memory allocation failure
		fprintf(stderr, "Error: Memory allocation failed.\n");
		// Clean up and return or exit
		free(current_time_str);
		return -1; // or handle the error appropriately
	}

	// Convert int timestamp to string
	snprintf(current_time_str, timestamp_length + 1, "%d", timestamp);

	int message_len = strlen(message_data_string) + strlen(publisher_topic) + strlen(current_time_str) + strlen(publisher_id);

	//char concatenated_message_to_verify[message_len + 1]; // +1 for the null terminator
	char *concatenated_message_to_verify = (char*)malloc((message_len + 1) * sizeof(char)); 
	concatenated_message_to_verify[0] = '\0';

	strncat(concatenated_message_to_verify, message_data_string, message_len);
	strncat(concatenated_message_to_verify, publisher_topic, message_len);
	strncat(concatenated_message_to_verify, current_time_str, message_len);
	strncat(concatenated_message_to_verify, publisher_id, message_len);
	
  	//printf("concat string 5: %s\n", concatenated_message_to_verify);

	// Ensure null termination
	concatenated_message_to_verify[message_len] = '\0';
	free(current_time_str);
	
	return concatenated_message_to_verify;
}


int falcon_verify_message(uint8_t *sig, size_t sig_len, char *payload, int payload_len, uint8_t *pk, size_t pk_len, uint8_t *tmp, size_t tmp_len)
{
	//printf("start verify\n");
	int result = falcon_verify(
		sig, sig_len, FALCON_SIG_PADDED,
		pk, pk_len,
		payload, payload_len, tmp, tmp_len);
	//printf("end verify with result: %d\n", result);
	return result;
}

/*
  Falcon signing function
*/
int falcon_sign_message(FalconContext *fc, char *payload, int payload_len)
{
  //printf("start sign \n");
  fc->sig_len = FALCON_SIG_PADDED_SIZE(fc->logn);
  int result = falcon_sign_dyn(&fc->rng,
                               fc->sig, &fc->sig_len, FALCON_SIG_PADDED,
                               fc->sk, FALCON_PRIVKEY_SIZE(fc->logn),
                               payload, payload_len, fc->tmp, fc->tmp_len);
  //printf("end sign with result: %d\n", result);
  return result;
}



int handle__publish(struct mosquitto *context)
{	
	
	fc = malloc(sizeof(FalconContext));

	if (fc == NULL)
    {
      fprintf(stderr, "Memory allocation for Falcon failed\n");
      exit(EXIT_FAILURE);
    }
	initialize_falcon_struct(fc);

	uint8_t dup;
	int rc = 0;
	int rc2;
	uint8_t header = context->in_packet.command;
	int res = 0;
	struct mosquitto_msg_store *msg, *stored = NULL;
	struct mosquitto_client_msg *cmsg_stored = NULL;
	size_t len;
	uint16_t slen;
	char *topic_mount;
	mosquitto_property *properties = NULL;
	mosquitto_property *p, *p_prev;
	mosquitto_property *msg_properties_last;
	uint32_t message_expiry_interval = 0;
	int topic_alias = -1;
	uint8_t reason_code = 0;
	uint16_t mid = 0;

	if(context->state != mosq_cs_active){
		return MOSQ_ERR_PROTOCOL;
	}

	msg = mosquitto__calloc(1, sizeof(struct mosquitto_msg_store));
	if(msg == NULL){
		return MOSQ_ERR_NOMEM;
	}

	dup = (header & 0x08)>>3;
	msg->qos = (header & 0x06)>>1;
	if(dup == 1 && msg->qos == 0){
		log__printf(NULL, MOSQ_LOG_INFO,
				"Invalid PUBLISH (QoS=0 and DUP=1) from %s, disconnecting.", context->id);
		db__msg_store_free(msg);
		return MOSQ_ERR_MALFORMED_PACKET;
	}
	if(msg->qos == 3){
		log__printf(NULL, MOSQ_LOG_INFO,
				"Invalid QoS in PUBLISH from %s, disconnecting.", context->id);
		db__msg_store_free(msg);
		return MOSQ_ERR_MALFORMED_PACKET;
	}
	if(msg->qos > context->max_qos){
		log__printf(NULL, MOSQ_LOG_INFO,
				"Too high QoS in PUBLISH from %s, disconnecting.", context->id);
		db__msg_store_free(msg);
		return MOSQ_ERR_QOS_NOT_SUPPORTED;
	}
	msg->retain = (header & 0x01);

	if(msg->retain && db.config->retain_available == false){
		db__msg_store_free(msg);
		return MOSQ_ERR_RETAIN_NOT_SUPPORTED;
	}

	if(packet__read_string(&context->in_packet, &msg->topic, &slen)){
		db__msg_store_free(msg);
		return MOSQ_ERR_MALFORMED_PACKET;
	}
	if(!slen && context->protocol != mosq_p_mqtt5){
		/* Invalid publish topic, disconnect client. */
		db__msg_store_free(msg);
		return MOSQ_ERR_MALFORMED_PACKET;
	}

	if(msg->qos > 0){
		if(packet__read_uint16(&context->in_packet, &mid)){
			db__msg_store_free(msg);
			return MOSQ_ERR_MALFORMED_PACKET;
		}
		if(mid == 0){
			db__msg_store_free(msg);
			return MOSQ_ERR_PROTOCOL;
		}
		/* It is important to have a separate copy of mid, because msg may be
		 * freed before we want to send a PUBACK/PUBREC. */
		msg->source_mid = mid;
	}

	/* Handle properties */
	if(context->protocol == mosq_p_mqtt5){
		rc = property__read_all(CMD_PUBLISH, &context->in_packet, &properties);
		if(rc){
			db__msg_store_free(msg);
			return rc;
		}

		p = properties;
		p_prev = NULL;
		msg->properties = NULL;
		msg_properties_last = NULL;
		while(p){
			switch(p->identifier){
				case MQTT_PROP_CONTENT_TYPE:
				case MQTT_PROP_CORRELATION_DATA:
				case MQTT_PROP_PAYLOAD_FORMAT_INDICATOR:
				case MQTT_PROP_RESPONSE_TOPIC:
				case MQTT_PROP_USER_PROPERTY:
					if(msg->properties){
						msg_properties_last->next = p;
						msg_properties_last = p;
					}else{
						msg->properties = p;
						msg_properties_last = p;
					}
					if(p_prev){
						p_prev->next = p->next;
						p = p_prev->next;
					}else{
						properties = p->next;
						p = properties;
					}
					msg_properties_last->next = NULL;
					break;

				case MQTT_PROP_TOPIC_ALIAS:
					topic_alias = p->value.i16;
					p_prev = p;
					p = p->next;
					break;

				case MQTT_PROP_MESSAGE_EXPIRY_INTERVAL:
					message_expiry_interval = p->value.i32;
					p_prev = p;
					p = p->next;
					break;

				case MQTT_PROP_SUBSCRIPTION_IDENTIFIER:
					p_prev = p;
					p = p->next;
					break;

				default:
					p = p->next;
					break;
			}
		}
	}
	mosquitto_property_free_all(&properties);

	if(topic_alias == 0 || (context->listener && topic_alias > context->listener->max_topic_alias)){
		db__msg_store_free(msg);
		return MOSQ_ERR_TOPIC_ALIAS_INVALID;
	}else if(topic_alias > 0){
		if(msg->topic){
			rc = alias__add(context, msg->topic, (uint16_t)topic_alias);
			if(rc){
				db__msg_store_free(msg);
				return rc;
			}
		}else{
			rc = alias__find(context, &msg->topic, (uint16_t)topic_alias);
			if(rc){
				db__msg_store_free(msg);
				return MOSQ_ERR_PROTOCOL;
			}
		}
	}

#ifdef WITH_BRIDGE
	rc = bridge__remap_topic_in(context, &msg->topic);
	if(rc){
		db__msg_store_free(msg);
		return rc;
	}

#endif
	if(mosquitto_pub_topic_check(msg->topic) != MOSQ_ERR_SUCCESS){
		/* Invalid publish topic, just swallow it. */
		db__msg_store_free(msg);
		return MOSQ_ERR_MALFORMED_PACKET;
	}

	msg->payloadlen = context->in_packet.remaining_length - context->in_packet.pos;
	G_PUB_BYTES_RECEIVED_INC(msg->payloadlen);
	if(context->listener && context->listener->mount_point){
		len = strlen(context->listener->mount_point) + strlen(msg->topic) + 1;
		topic_mount = mosquitto__malloc(len+1);
		if(!topic_mount){
			db__msg_store_free(msg);
			return MOSQ_ERR_NOMEM;
		}
		snprintf(topic_mount, len, "%s%s", context->listener->mount_point, msg->topic);
		topic_mount[len] = '\0';

		mosquitto__free(msg->topic);
		msg->topic = topic_mount;
	}

	if(msg->payloadlen){
		if(db.config->message_size_limit && msg->payloadlen > db.config->message_size_limit){
			log__printf(NULL, MOSQ_LOG_DEBUG, "Dropped too large PUBLISH from %s (d%d, q%d, r%d, m%d, '%s', ... (%ld bytes))", context->id, dup, msg->qos, msg->retain, msg->source_mid, msg->topic, (long)msg->payloadlen);
			reason_code = MQTT_RC_PACKET_TOO_LARGE;
			goto process_bad_message;
		}
		msg->payload = mosquitto__malloc(msg->payloadlen+1);
		if(msg->payload == NULL){
			db__msg_store_free(msg);
			return MOSQ_ERR_NOMEM;
		}
		/* Ensure payload is always zero terminated, this is the reason for the extra byte above */
		((uint8_t *)msg->payload)[msg->payloadlen] = 0;

		if(packet__read_bytes(&context->in_packet, msg->payload, msg->payloadlen)){
			db__msg_store_free(msg);
			return MOSQ_ERR_MALFORMED_PACKET;
		}
	}

	/* Check for topic access */
	rc = mosquitto_acl_check(context, msg->topic, msg->payloadlen, msg->payload, msg->qos, msg->retain, MOSQ_ACL_WRITE);
	if(rc == MOSQ_ERR_ACL_DENIED){
		log__printf(NULL, MOSQ_LOG_DEBUG,
				"Denied PUBLISH from %s (d%d, q%d, r%d, m%d, '%s', ... (%ld bytes))",
				context->id, dup, msg->qos, msg->retain, msg->source_mid, msg->topic,
				(long)msg->payloadlen);
		reason_code = MQTT_RC_NOT_AUTHORIZED;
		goto process_bad_message;
	}else if(rc != MOSQ_ERR_SUCCESS){
		db__msg_store_free(msg);
		return rc;
	}
	// design B start
	//log__printf(NULL, MOSQ_LOG_NOTICE, "Received PUBLISH from %s (d%d, q%d, r%d, m%d, '%s', ... (%ld bytes))", context->id, dup, msg->qos, msg->retain, msg->source_mid, msg->topic, (long)msg->payloadlen);
	
	//printf("%s \n ", msg->payload);
	cJSON *message_as_json = cJSON_Parse(msg->payload);
	
	char *payload_message = cJSON_GetObjectItem(message_as_json, "m")->valuestring;

	char *encoded_signature = cJSON_GetObjectItem(message_as_json, "s")->valuestring;

	size_t sig_len = CRYPTO_BYTES;
	dilithium = strlen(encoded_signature) > 2300;
	if (!dilithium) sig_len = FALCON_SIG_PADDED_SIZE(logn);

	char *decoded_signature = decode(encoded_signature, sig_len);

	time_t timestamp = cJSON_GetObjectItem(message_as_json, "t")->valueint;

	char *message_to_verify = create_concat_message(payload_message, timestamp, msg->topic, context->id);
	size_t message_len = strlen(message_to_verify);
	//log__printf(NULL, MOSQ_LOG_NOTICE, "concat message: %s ", message_to_verify);

	//verify and make new signature and json message
	char *encoded_broker_sig;
	int verify = 1;
	char *version = "";
	load_broker_key("pk");
	load_broker_key("sk");
	if (dilithium) {
		uint8_t publisher_pk[CRYPTO_PUBLICKEYBYTES];
		load_client_pk(publisher_pk, context->id);

		verify = verify_dilithium_signature(decoded_signature, message_to_verify, message_len, publisher_pk);

		uint8_t broker_signature[CRYPTO_BYTES];
    	dilithium_sign_message(broker_signature, message_to_verify, message_len);
		verify_dilithium_signature(broker_signature, message_to_verify, message_len, dilithium_broker_pk);

		encoded_broker_sig = b64_encode(broker_signature, CRYPTO_BYTES);
		version = "Dilithium";
	} else {
		//  Falcon variables
		size_t sig_len = FALCON_SIG_PADDED_SIZE(logn);
		uint8_t *tmp;
		size_t tmp_len;
		len = maxsz(len, FALCON_TMPSIZE_SIGNDYN(logn));
		len = maxsz(len, FALCON_TMPSIZE_SIGNTREE(logn));
		len = maxsz(len, FALCON_TMPSIZE_EXPANDPRIV(logn));
		len = maxsz(len, FALCON_TMPSIZE_VERIFY(logn));
		tmp = xmalloc(len);
		tmp_len = len;

		
		uint8_t publisher_pk[pk_len];
		load_client_pk(publisher_pk, context->id);
		
		verify = falcon_verify_message(decoded_signature, sig_len, message_to_verify,
									   message_len, publisher_pk, pk_len, tmp, tmp_len);

    	if (falcon_sign_message(fc, message_to_verify, message_len) != 0)
		{
			fprintf(stderr, "Signing message for Falcon failed\n");
			exit(EXIT_FAILURE);
		}
		
		falcon_verify_message(fc->sig, sig_len, message_to_verify,
											message_len, fc->pk, pk_len, tmp, tmp_len);
		
		encoded_broker_sig = b64_encode(fc->sig, sig_len);

		version = "Falcon";
	}
	if (!verify)
	{
		printf("Publisher %s signature verification success with result %d...\n", version, verify);
	} else {
		printf("Publisher %s signature verification failed. Stopping relay of message \n", version);
		return -1;
	}

	//printf("\nb64encoded length %u\n", strlen(encoded_broker_sig));
	cJSON_DeleteItemFromObject(message_as_json, "s");

    cJSON_AddStringToObject(message_as_json, "id", context->id); //need to add client id for subscriber to know
    cJSON_AddStringToObject(message_as_json, "s", encoded_broker_sig);

	char *jsonString = cJSON_PrintUnformatted(message_as_json);
    size_t allocatedSize = strlen(jsonString) + 1;
	msg->payloadlen = allocatedSize;

	msg->payload = mosquitto__malloc(msg->payloadlen+1);
		if(msg->payload == NULL){
			db__msg_store_free(msg);
			return MOSQ_ERR_NOMEM;
		}
	// Ensure payload is always zero terminated, this is the reason for the extra byte above 
	((uint8_t *)msg->payload)[msg->payloadlen] = 0;
	
	strcpy(msg->payload, jsonString);
	
	free(message_to_verify);
	//cJSON_Delete(message_as_json);
	free(encoded_broker_sig);
	free(decoded_signature);

	if(!strncmp(msg->topic, "$CONTROL/", 9)){
#ifdef WITH_CONTROL
		rc = control__process(context, msg);
		db__msg_store_free(msg);
		return rc;
#else
		reason_code = MQTT_RC_IMPLEMENTATION_SPECIFIC;
		goto process_bad_message;
#endif
	}

	{
		rc = plugin__handle_message(context, msg);
		if(rc == MOSQ_ERR_ACL_DENIED){
			log__printf(NULL, MOSQ_LOG_DEBUG,
					"Denied PUBLISH from %s (d%d, q%d, r%d, m%d, '%s', ... (%ld bytes))",
					context->id, dup, msg->qos, msg->retain, msg->source_mid, msg->topic,
					(long)msg->payloadlen);

			reason_code = MQTT_RC_NOT_AUTHORIZED;
			goto process_bad_message;
		}else if(rc != MOSQ_ERR_SUCCESS){
			db__msg_store_free(msg);
			return rc;
		}
	}

	if(msg->qos > 0){
		db__message_store_find(context, msg->source_mid, &cmsg_stored);
	}

	if(cmsg_stored && cmsg_stored->store && msg->source_mid != 0 &&
			(cmsg_stored->store->qos != msg->qos
			 || cmsg_stored->store->payloadlen != msg->payloadlen
			 || strcmp(cmsg_stored->store->topic, msg->topic)
			 || memcmp(cmsg_stored->store->payload, msg->payload, msg->payloadlen) )){

		log__printf(NULL, MOSQ_LOG_WARNING, "Reused message ID %u from %s detected. Clearing from storage.", msg->source_mid, context->id);
		db__message_remove_incoming(context, msg->source_mid);
		cmsg_stored = NULL;
	}

	if(!cmsg_stored){
		if(msg->qos == 0
				|| db__ready_for_flight(context, mosq_md_in, msg->qos)
				){

			dup = 0;
			rc = db__message_store(context, msg, message_expiry_interval, 0, mosq_mo_client);
			if(rc) return rc;
		}else{
			/* Client isn't allowed any more incoming messages, so fail early */
			reason_code = MQTT_RC_QUOTA_EXCEEDED;
			goto process_bad_message;
		}
		stored = msg;
		msg = NULL;
		dup = 0;
	}else{
		db__msg_store_free(msg);
		msg = NULL;
		stored = cmsg_stored->store;
		cmsg_stored->dup++;
		dup = cmsg_stored->dup;
	}

	switch(stored->qos){
		case 0:
			rc2 = sub__messages_queue(context->id, stored->topic, stored->qos, stored->retain, &stored);
			if(rc2 > 0) rc = 1;
			break;
		case 1:
			util__decrement_receive_quota(context);
			rc2 = sub__messages_queue(context->id, stored->topic, stored->qos, stored->retain, &stored);
			/* stored may now be free, so don't refer to it */
			if(rc2 == MOSQ_ERR_SUCCESS || context->protocol != mosq_p_mqtt5){
				if(send__puback(context, mid, 0, NULL)) rc = 1;
			}else if(rc2 == MOSQ_ERR_NO_SUBSCRIBERS){
				if(send__puback(context, mid, MQTT_RC_NO_MATCHING_SUBSCRIBERS, NULL)) rc = 1;
			}else{
				rc = rc2;
			}
			break;
		case 2:
			if(dup == 0){
				res = db__message_insert(context, stored->source_mid, mosq_md_in, stored->qos, stored->retain, stored, NULL, false);
			}else{
				res = 0;
			}

			/* db__message_insert() returns 2 to indicate dropped message
			 * due to queue. This isn't an error so don't disconnect them. */
			/* FIXME - this is no longer necessary due to failing early above */
			if(!res){
				if(dup == 0 || dup == 1){
					rc2 = send__pubrec(context, stored->source_mid, 0, NULL);
					if(rc2) rc = rc2;
				}else{
					return MOSQ_ERR_PROTOCOL;
				}
			}else if(res == 1){
				rc = 1;
			}
			break;
	}

	db__message_write_queued_in(context);
	return rc;
process_bad_message:
	rc = 1;
	if(msg){
		switch(msg->qos){
			case 0:
				rc = MOSQ_ERR_SUCCESS;
				break;
			case 1:
				rc = send__puback(context, msg->source_mid, reason_code, NULL);
				break;
			case 2:
				rc = send__pubrec(context, msg->source_mid, reason_code, NULL);
				break;
		}
		db__msg_store_free(msg);
	}
	if(context->out_packet_count >= db.config->max_queued_messages){
		rc = MQTT_RC_QUOTA_EXCEEDED;
	}
	return rc;
}

