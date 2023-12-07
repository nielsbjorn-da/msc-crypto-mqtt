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

#ifndef CONFIG_H

// Dilithium import
#include "dilithium_and_falcon/dilithium/dilithium-master/ref/sign.h"
#include "dilithium_and_falcon/dilithium/dilithium-master/ref/api.h"


// Falcon import
#include "dilithium_and_falcon/falcon/Falcon-impl-20211101/falcon.h"

#include "config.h"
#define CONFIG_H
/* ============================================================
 * Platform options
 * ============================================================ */

#ifdef __APPLE__
#define __DARWIN_C_SOURCE
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__SYMBIAN32__)
#define _XOPEN_SOURCE 700
#define __BSD_VISIBLE 1
#define HAVE_NETINET_IN_H
#elif defined(__QNX__)
#define _XOPEN_SOURCE 600
#define __BSD_VISIBLE 1
#define HAVE_NETINET_IN_H
#else
#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#define OPENSSL_LOAD_CONF

/* ============================================================
 * Compatibility defines
 * ============================================================ */
#if defined(_MSC_VER) && _MSC_VER < 1900
#define snprintf sprintf_s
#define EPROTO ECONNABORTED
#ifndef ECONNABORTED
#define ECONNABORTED WSAECONNABORTED
#endif
#ifndef ENOTCONN
#define ENOTCONN WSAENOTCONN
#endif
#ifndef ECONNREFUSED
#define ECONNREFUSED WSAECONNREFUSED
#endif
#endif

#ifdef WIN32
#ifndef strcasecmp
#define strcasecmp strcmpi
#endif
#define strtok_r strtok_s
#define strerror_r(e, b, l) strerror_s(b, l, e)
#endif

#define uthash_malloc(sz) mosquitto_malloc(sz)
#define uthash_free(ptr, sz) mosquitto_free(ptr)

#ifdef WITH_TLS
#include <openssl/opensslconf.h>
#if defined(WITH_TLS_PSK) && !defined(OPENSSL_NO_PSK)
#define FINAL_WITH_TLS_PSK
#endif
#endif

#ifdef __COVERITY__
#include <stdint.h>
/* These are "wrong", but we don't use them so it doesn't matter */
#define _Float32 uint32_t
#define _Float32x uint32_t
#define _Float64 uint64_t
#define _Float64x uint64_t
#define _Float128 uint64_t
#endif

#define UNUSED(A) (void)(A)

/* Android Bionic libpthread implementation doesn't have pthread_cancel */
#ifndef ANDROID
#define HAVE_PTHREAD_CANCEL
#endif

#ifdef WITH_CJSON
#include <cjson/cJSON.h>
#define CJSON_VERSION_FULL (CJSON_VERSION_MAJOR * 1000000 + CJSON_VERSION_MINOR * 1000 + CJSON_VERSION_PATCH)
#endif

#endif

#include "dilithium_and_falcon/dilithium/dilithium-master/ref/randombytes.h"
// #include "config.h"
//
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifndef WIN32
#include <unistd.h>
#include <signal.h>
#else
#include <process.h>
#include <winsock2.h>
#define snprintf sprintf_s
#endif

#include <mosquitto.h>
#include <mqtt_protocol.h>
#include "client_shared.h"
#include "sub_client_output.h"
#include "libb64/include/b64/cdecode.h"
#include "libb64/include/b64/cencode.h"
#include <cjson/cJSON.h>

struct mosq_config cfg;
bool process_messages = true;
int msg_count = 0;
struct mosquitto *g_mosq = NULL;
int last_mid = 0;
static bool timed_out = false;
static int connack_result = 0;
bool connack_received = false;

// Time variables
clock_t start, end;

uint8_t *dilithium_broker_pk;
size_t dilithium_pk_len;
size_t dilithium_sig_len;
int dilithium_version;
bool dilithium;

unsigned logn = 10;
uint8_t falcon_broker_pk[FALCON_PUBKEY_SIZE(10)];

#ifndef WIN32
static void my_signal_handler(int signum)
{
	if (signum == SIGALRM || signum == SIGTERM || signum == SIGINT)
	{
		if (connack_received)
		{
			process_messages = false;
			mosquitto_disconnect_v5(g_mosq, MQTT_RC_DISCONNECT_WITH_WILL_MSG, cfg.disconnect_props);
		}
		else
		{
			exit(-1);
		}
	}
	if (signum == SIGALRM)
	{
		timed_out = true;
	}
}
#endif

int load_broker_pk(char *signature_scheme)
{
	size_t key_length;
	uint8_t *key_array;
	char path[100];
	strcpy(path, "../src/keys/");

	if (dilithium) {
		key_array = dilithium_broker_pk;
		key_length = dilithium_pk_len;
		if (dilithium_version == 2) {
			strcat(path, "Dilithium2");
		} else if (dilithium_version == 3) {
			strcat(path, "Dilithium3");
		} else if (dilithium_version == 5) {
			strcat(path, "Dilithium5");
		}
	}
	else
	{
		key_length = FALCON_PUBKEY_SIZE(logn);
		key_array = falcon_broker_pk;
		if (logn == 9)
		{
			strcat(path, "falcon512");
		}
		else if (logn == 10)
		{
			strcat(path, "falcon1024");
		}
	}
	strcat(path, "_broker_pk.bin");
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
	char *output = (char *)calloc(si, sizeof(char));
	// memset(output, 0, sizeof(output));
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

int verify_dilithium_signature(uint8_t *signature, const char *message, size_t message_length, uint8_t *public_key)
{
	int ret = 1;
	//int ret = crypto_sign_verify(signature, dilithium_sig_len, message, message_length, public_key);
	if (dilithium_version == 2) {
		ret = pqcrystals_dilithium2_ref_verify(signature, dilithium_sig_len,
											message, message_length,
											public_key);
	} else if (dilithium_version == 3) {
		ret = pqcrystals_dilithium3_ref_verify(signature, dilithium_sig_len,
											message, message_length,
											public_key);
	} else if (dilithium_version == 5) {
		ret = pqcrystals_dilithium5_ref_verify(signature, dilithium_sig_len,
											message, message_length,
											public_key);
	}
	if (ret)
	{
		fprintf(stderr, "Verification failed\n");
		return -1;
	}
	return ret;
}

int falcon_verify_message(uint8_t *sig, size_t sig_len, char *payload, int payload_len, uint8_t *pk, size_t pk_len, uint8_t *tmp, size_t tmp_len)
{
	// printf("start verify\n");
	int result = falcon_verify(
		sig, sig_len, FALCON_SIG_PADDED,
		pk, pk_len,
		payload, payload_len, tmp, tmp_len);
	if (result)
	{
		printf("Falcon verification failed\n");
	}
	// printf("end verify with result: %d\n", result);
	return result;
}

static void my_message_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message, const mosquitto_property *properties)
{

	struct timeval receive_time;
	gettimeofday(&receive_time, NULL);

	struct timeval end_time, start_time;
	long time_taken;

	int i;
	bool res;
	UNUSED(obj);
	UNUSED(properties);

	if (process_messages == false)
		return;

	if (cfg.retained_only && !message->retain && process_messages)
	{
		process_messages = false;
		if (last_mid == 0)
		{
			mosquitto_disconnect_v5(mosq, 0, cfg.disconnect_props);
		}
		return;
	}

	if (message->retain && cfg.no_retain)
		return;
	if (cfg.filter_outs)
	{
		for (i = 0; i < cfg.filter_out_count; i++)
		{
			mosquitto_topic_matches_sub(cfg.filter_outs[i], message->topic, &res);
			if (res)
				return;
		}
	}

	if (cfg.remove_retained && message->retain)
	{
		mosquitto_publish(mosq, &last_mid, message->topic, 0, NULL, 1, true);
	}

	// #####################################################################################
	//  Retrieve the content from the MQTT payload package.
	// #####################################################################################

	// print_message(&cfg, message, properties);
	gettimeofday(&start_time, NULL);

	cJSON *message_as_json = cJSON_Parse(message->payload);

	cJSON *message_data = cJSON_GetObjectItem(message_as_json, "m");
	char *message_data_string = message_data->valuestring;

	size_t messagelen = strlen(message_data_string);

	char *publisher_id = cJSON_GetObjectItem(message_as_json, "id")->valuestring;

	char *publisher_topic = message->topic;

	int timestamp = cJSON_GetObjectItem(message_as_json, "t")->valueint;

	int time_micro = cJSON_GetObjectItem(message_as_json, "t2")->valuedouble;

	int pub_timestamp = cJSON_GetObjectItem(message_as_json, "l1")->valueint;

	int pub_time_micro = cJSON_GetObjectItem(message_as_json, "l2")->valuedouble;

	char *signature_algorithm = cJSON_GetObjectItem(message_as_json, "a")->valuestring;

	char *encoded_signature = cJSON_GetObjectItem(message_as_json, "s")->valuestring;
	//

	gettimeofday(&end_time, NULL);
	time_taken = (end_time.tv_sec * 1000000 + end_time.tv_usec) - (start_time.tv_sec * 1000000 + start_time.tv_usec);
	printf("Extracting payload from cJSON execution time: %ld micro seconds.\n", time_taken);

	// #####################################################################################
	//  Creating the message that were signed
	// #####################################################################################
	gettimeofday(&start_time, NULL);
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

	char concatenated_message_to_verify[message_len + 1]; // +1 for the null terminator
	concatenated_message_to_verify[0] = '\0';

	strncat(concatenated_message_to_verify, message_data_string, message_len);
	strncat(concatenated_message_to_verify, publisher_topic, message_len);
	strncat(concatenated_message_to_verify, current_time_str, message_len);
	strncat(concatenated_message_to_verify, publisher_id, message_len);

	// printf("concat string 5: %s\n", concatenated_message_to_verify);

	// Ensure null termination
	concatenated_message_to_verify[message_len] = '\0';
	free(current_time_str);

	gettimeofday(&end_time, NULL);
	time_taken = (end_time.tv_sec * 1000000 + end_time.tv_usec) - (start_time.tv_sec * 1000000 + start_time.tv_usec);
	printf("Generating concat message execution time: %ld micro seconds.\n", time_taken);

	// #####################################################################################
	//  Run the verifications algorithms
	// #####################################################################################

	int verify = 1;
	char *version = "";
	dilithium = strcmp(signature_algorithm, "D2") == 0 || strcmp(signature_algorithm, "D3") == 0 || strcmp(signature_algorithm, "D5") == 0;
	if (dilithium)
	{
		if (strcmp(signature_algorithm, "D2") == 0) {
			dilithium_version = 2;
			dilithium_pk_len = pqcrystals_dilithium2_PUBLICKEYBYTES;
			dilithium_sig_len = pqcrystals_dilithium2_BYTES;
		} else if (strcmp(signature_algorithm, "D3") == 0) {
			dilithium_version = 3;
			dilithium_pk_len = pqcrystals_dilithium3_PUBLICKEYBYTES;
			dilithium_sig_len = pqcrystals_dilithium3_BYTES;
		} else if (strcmp(signature_algorithm, "D5") == 0) {
			dilithium_version = 5;
			dilithium_pk_len = pqcrystals_dilithium5_PUBLICKEYBYTES;
			dilithium_sig_len = pqcrystals_dilithium5_BYTES;
		}
		dilithium_broker_pk = malloc(dilithium_pk_len);
		gettimeofday(&start_time, NULL);

		char *dilithium_decode_sig = decode(encoded_signature, dilithium_sig_len);
		gettimeofday(&end_time, NULL);
		time_taken = (end_time.tv_sec * 1000000 + end_time.tv_usec) - (start_time.tv_sec * 1000000 + start_time.tv_usec);
		printf("Decode sig Dilithium%d execution time: %ld micro seconds.\n", dilithium_version, time_taken);

		gettimeofday(&start_time, NULL);
		load_broker_pk(signature_algorithm);

		verify = verify_dilithium_signature(dilithium_decode_sig, concatenated_message_to_verify, message_len, dilithium_broker_pk);
		version = "Dilithium";

		gettimeofday(&end_time, NULL);
		time_taken = (end_time.tv_sec * 1000000 + end_time.tv_usec) - (start_time.tv_sec * 1000000 + start_time.tv_usec);
		printf("Verification Dilithium%d execution time: %ld micro seconds.\n", dilithium_version, time_taken);
		free(dilithium_decode_sig);
		free(dilithium_broker_pk);
	}
	else
	{
		//  Falcon variables
		if (strcmp(signature_algorithm, "F512") == 0)
		{
			logn = 9;
		}
		version = "Falcon-1024";
		if (logn == 9)
			version = "Falcon-512";
		gettimeofday(&start_time, NULL);
		size_t sig_len = FALCON_SIG_PADDED_SIZE(logn);
		char *falcon_decode_sig = decode(encoded_signature, sig_len);
		gettimeofday(&end_time, NULL);
		time_taken = (end_time.tv_sec * 1000000 + end_time.tv_usec) - (start_time.tv_sec * 1000000 + start_time.tv_usec);
		printf("Decode sig %s execution time: %ld micro seconds.\n", version, time_taken);

		gettimeofday(&start_time, NULL);
		size_t pk_len = FALCON_PUBKEY_SIZE(logn);
		size_t len = FALCON_TMPSIZE_KEYGEN(logn);
		uint8_t *tmp;
		size_t tmp_len;
		len = maxsz(len, FALCON_TMPSIZE_SIGNDYN(logn));
		len = maxsz(len, FALCON_TMPSIZE_SIGNTREE(logn));
		len = maxsz(len, FALCON_TMPSIZE_EXPANDPRIV(logn));
		len = maxsz(len, FALCON_TMPSIZE_VERIFY(logn));
		tmp = xmalloc(len);
		tmp_len = len;

		load_broker_pk("falcon");

		verify = falcon_verify_message(falcon_decode_sig, sig_len, concatenated_message_to_verify,
									   message_len, falcon_broker_pk, pk_len, tmp, tmp_len);

		free(falcon_decode_sig);

		gettimeofday(&end_time, NULL);
		time_taken = (end_time.tv_sec * 1000000 + end_time.tv_usec) - (start_time.tv_sec * 1000000 + start_time.tv_usec);
		printf("Verification %s execution time: %ld micro seconds.\n", version, time_taken);
	}
	if (!verify)
	{
		// Record the end time
		gettimeofday(&end_time, NULL);

		// Calculate and print the time taken for message delivery
		//printf("start time 1 = %d, start time 2 = %d, end time 1 = %d, end time 2 = %d\n", timestamp, time_micro, end_time.tv_sec, end_time.tv_usec);
		long time_taken = (end_time.tv_sec * 1000000 + end_time.tv_usec) - ((long) timestamp * 1000000 + (long) time_micro);
		printf("Total time result: %ld micro seconds.\n", time_taken);

		long latency = (receive_time.tv_sec * 1000000 + receive_time.tv_usec) - ((long) pub_timestamp * 1000000 + (long) pub_time_micro);
		printf("Latency time result: %ld micro seconds.\n", latency);

		printf("%s signature verification success with result %d...\n", version, verify);
		printf("---------------------------------------------------------\n");
	}
	cJSON_Delete(message_as_json);

	if (ferror(stdout))
	{
		mosquitto_disconnect_v5(mosq, 0, cfg.disconnect_props);
	}

	if (cfg.msg_count > 0)
	{
		msg_count++;
		if (cfg.msg_count == msg_count)
		{
			process_messages = false;
			if (last_mid == 0)
			{
				mosquitto_disconnect_v5(mosq, 0, cfg.disconnect_props);
			}
		}
	}
}

static void my_connect_callback(struct mosquitto *mosq, void *obj, int result, int flags, const mosquitto_property *properties)
{
	int i;

	UNUSED(obj);
	UNUSED(flags);
	UNUSED(properties);
	connack_received = true;

	connack_result = result;
	if (!result)
	{
		mosquitto_subscribe_multiple(mosq, NULL, cfg.topic_count, cfg.topics, cfg.qos, cfg.sub_opts, cfg.subscribe_props);

		for (i = 0; i < cfg.unsub_topic_count; i++)
		{
			mosquitto_unsubscribe_v5(mosq, NULL, cfg.unsub_topics[i], cfg.unsubscribe_props);
		}
	}
	else
	{
		if (result)
		{
			if (cfg.protocol_version == MQTT_PROTOCOL_V5)
			{
				if (result == MQTT_RC_UNSUPPORTED_PROTOCOL_VERSION)
				{
					err_printf(&cfg, "Connection error: %s. Try connecting to an MQTT v5 broker, or use MQTT v3.x mode.\n", mosquitto_reason_string(result));
				}
				else
				{
					err_printf(&cfg, "Connection error: %s\n", mosquitto_reason_string(result));
				}
			}
			else
			{
				err_printf(&cfg, "Connection error: %s\n", mosquitto_connack_string(result));
			}
		}
		mosquitto_disconnect_v5(mosq, 0, cfg.disconnect_props);
	}
}

static void my_subscribe_callback(struct mosquitto *mosq, void *obj, int mid, int qos_count, const int *granted_qos)
{
	int i;
	bool some_sub_allowed = (granted_qos[0] < 128);
	bool should_print = cfg.debug && !cfg.quiet;
	UNUSED(obj);

	if (should_print)
		printf("Subscribed (mid: %d): %d", mid, granted_qos[0]);
	for (i = 1; i < qos_count; i++)
	{
		if (should_print)
			printf(", %d", granted_qos[i]);
		some_sub_allowed |= (granted_qos[i] < 128);
	}
	if (should_print)
		printf("\n");

	if (some_sub_allowed == false)
	{
		mosquitto_disconnect_v5(mosq, 0, cfg.disconnect_props);
		err_printf(&cfg, "All subscription requests were denied.\n");
	}

	if (cfg.exit_after_sub)
	{
		mosquitto_disconnect_v5(mosq, 0, cfg.disconnect_props);
	}
}

static void my_log_callback(struct mosquitto *mosq, void *obj, int level, const char *str)
{
	UNUSED(mosq);
	UNUSED(obj);
	UNUSED(level);

	printf("%s\n", str);
}

static void print_version(void)
{
	int major, minor, revision;

	mosquitto_lib_version(&major, &minor, &revision);
	printf("mosquitto_sub version %s running on libmosquitto %d.%d.%d.\n", VERSION, major, minor, revision);
}

int main(int argc, char *argv[])
{
	int rc;
#ifndef WIN32
	struct sigaction sigact;
#endif

	mosquitto_lib_init();

	output_init();

	rc = client_config_load(&cfg, CLIENT_SUB, argc, argv);
	if (rc)
	{
		if (rc == 2)
		{
			/* --help */
			printf("print_usage() supposed to be called, removed due to space");
		}
		else if (rc == 3)
		{
			/* --version */
			print_version();
		}
		else
		{
			fprintf(stderr, "\nUse 'mosquitto_sub --help' to see usage.\n");
		}
		goto cleanup;
	}

	if (cfg.no_retain && cfg.retained_only)
	{
		fprintf(stderr, "\nError: Combining '-R' and '--retained-only' makes no sense.\n");
		goto cleanup;
	}

	if (client_id_generate(&cfg))
	{
		goto cleanup;
	}

	char clientID[23] = "subscriber_client";
	g_mosq = mosquitto_new(clientID, cfg.clean_session, &cfg);
	if (!g_mosq)
	{
		switch (errno)
		{
		case ENOMEM:
			err_printf(&cfg, "Error: Out of memory.\n");
			break;
		case EINVAL:
			err_printf(&cfg, "Error: Invalid id and/or clean_session.\n");
			break;
		}
		goto cleanup;
	}
	if (client_opts_set(g_mosq, &cfg))
	{
		goto cleanup;
	}
	if (cfg.debug)
	{
		mosquitto_log_callback_set(g_mosq, my_log_callback);
	}
	mosquitto_subscribe_callback_set(g_mosq, my_subscribe_callback);
	mosquitto_connect_v5_callback_set(g_mosq, my_connect_callback);
	mosquitto_message_v5_callback_set(g_mosq, my_message_callback);

	rc = client_connect(g_mosq, &cfg);
	if (rc)
	{
		goto cleanup;
	}

#ifndef WIN32
	sigact.sa_handler = my_signal_handler;
	sigemptyset(&sigact.sa_mask);
	sigact.sa_flags = 0;

	if (sigaction(SIGALRM, &sigact, NULL) == -1)
	{
		perror("sigaction");
		goto cleanup;
	}

	if (sigaction(SIGTERM, &sigact, NULL) == -1)
	{
		perror("sigaction");
		goto cleanup;
	}

	if (sigaction(SIGINT, &sigact, NULL) == -1)
	{
		perror("sigaction");
		goto cleanup;
	}

	if (cfg.timeout)
	{
		alarm(cfg.timeout);
	}
#endif

	rc = mosquitto_loop_forever(g_mosq, -1, 1);

	mosquitto_destroy(g_mosq);
	mosquitto_lib_cleanup();

	if (cfg.msg_count > 0 && rc == MOSQ_ERR_NO_CONN)
	{
		rc = 0;
	}
	client_config_cleanup(&cfg);
	if (timed_out)
	{
		err_printf(&cfg, "Timed out\n");
		return MOSQ_ERR_TIMEOUT;
	}
	else if (rc)
	{
		err_printf(&cfg, "Error: %s\n", mosquitto_strerror(rc));
	}
	if (connack_result)
	{
		return connack_result;
	}
	else
	{
		return rc;
	}

cleanup:
	mosquitto_destroy(g_mosq);
	mosquitto_lib_cleanup();
	client_config_cleanup(&cfg);
	return 1;
}
