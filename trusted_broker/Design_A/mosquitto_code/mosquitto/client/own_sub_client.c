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
	size_t sig_length = CRYPTO_BYTES;

	int ret = crypto_sign_verify(signature, sig_length, message, message_length, public_key);

	if (ret)
	{
		fprintf(stderr, "Verification failed\n");
		return -1;
	}
	return ret;
}

int falcon_verify_message(uint8_t *sig, size_t sig_len, char *payload, int payload_len, uint8_t *pk, size_t pk_len, uint8_t *tmp, size_t tmp_len)
{
	int result = falcon_verify(
		sig, sig_len, FALCON_SIG_PADDED,
		pk, pk_len,
		payload, payload_len, tmp, tmp_len);
	return result;
}

static void my_message_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message, const mosquitto_property *properties)
{
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
	//print_message(&cfg, message, properties);
	start = clock();
	cJSON *message_as_json = cJSON_Parse(message->payload);

	cJSON *message_data = cJSON_GetObjectItem(message_as_json, "m");
	char *message_data_string = message_data->valuestring;

	size_t messagelen = strlen(message_data_string);

	char *publisher_id = cJSON_GetObjectItem(message_as_json, "id")->valuestring;

	char *publisher_topic = message->topic;

	int timestamp = cJSON_GetObjectItem(message_as_json, "t")->valueint;

	double time_micro = cJSON_GetObjectItem(message_as_json, "t2")->valuedouble;

	char *encoded_signature = cJSON_GetObjectItem(message_as_json, "s")->valuestring;

	char *encoded_publisher_pk = cJSON_GetObjectItem(message_as_json, "pk")->valuestring;
	end = clock();
  printf("Extracting payload from cJSON execution time: %f seconds\n", ((double)(end - start)) / CLOCKS_PER_SEC);

	// #####################################################################################
	//  Creating the message that were signed
	// #####################################################################################
	start = clock();
	//  Calculate the length of the converted strings
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

	// Ensure null termination
	concatenated_message_to_verify[message_len] = '\0';
	free(current_time_str);
	end = clock();
  printf("Generating concat message execution time: %f seconds\n", ((double)(end - start)) / CLOCKS_PER_SEC);
	// #####################################################################################
	//  Run the verifications algorithms
	// #####################################################################################
	
	int verify = 1;
	char *version = "";
	struct timeval receive_time;
	if (strlen(encoded_signature) > 3000)
	{
		start = clock();
		char *dilithium_decode_sig = decode(encoded_signature, CRYPTO_BYTES);
		end = clock();
  		printf("Decode sig Dilithium execution time: %f seconds\n", ((double)(end - start)) / CLOCKS_PER_SEC);

		start = clock();
		char *dilithium_decode_pk = decode(encoded_publisher_pk, CRYPTO_PUBLICKEYBYTES);
		end = clock();
  		printf("Decode PK Dilithium execution time: %f seconds\n", ((double)(end - start)) / CLOCKS_PER_SEC);
		
		start = clock();
		verify = verify_dilithium_signature(dilithium_decode_sig, concatenated_message_to_verify, message_len, dilithium_decode_pk);
		end = clock();
  		printf("Verification Dilithium execution time: %f seconds\n", ((double)(end - start)) / CLOCKS_PER_SEC);

		free(dilithium_decode_sig);
		free(dilithium_decode_pk);
		version = CRYPTO_ALGNAME;
	}
	else
	{
		//  Falcon variables
		unsigned logn = 9;
		size_t pk_len = FALCON_PUBKEY_SIZE(logn);
		size_t len = FALCON_TMPSIZE_KEYGEN(logn);
		uint8_t *tmp;
		size_t tmp_len;
		len = maxsz(len, FALCON_TMPSIZE_SIGNDYN(logn));
		len = maxsz(len, FALCON_TMPSIZE_SIGNTREE(logn));
		len = maxsz(len, FALCON_TMPSIZE_EXPANDPRIV(logn));
		len = maxsz(len, FALCON_TMPSIZE_VERIFY(logn));
		size_t sig_len = FALCON_SIG_PADDED_SIZE(logn);
		tmp = xmalloc(len);
		tmp_len = len;

		start = clock();
		char *falcon_decode_sig = decode(encoded_signature, sig_len);
		end = clock();
		printf("Decode sig Falcon execution time: %f seconds\n", ((double)(end - start)) / CLOCKS_PER_SEC);
		
		start = clock();
		char *falcon_decode_pk = decode(encoded_publisher_pk, pk_len);
		end = clock();
  		printf("Decode PK Falcon execution time: %f seconds\n", ((double)(end - start)) / CLOCKS_PER_SEC);

		start = clock();
		verify = falcon_verify_message(falcon_decode_sig, sig_len, concatenated_message_to_verify,
									   message_len, falcon_decode_pk, pk_len, tmp, tmp_len);
		end = clock();
  		printf("Verification Falcon execution time: %f seconds\n", ((double)(end - start)) / CLOCKS_PER_SEC);

		free(falcon_decode_sig);
		free(falcon_decode_pk);
		version = "Falcon";
	}
	if (!verify)
	{
		// Record the end time
		gettimeofday(&receive_time, NULL);

		// Calculate and print the time taken for message delivery
		double time_taken = (receive_time.tv_sec - timestamp) + (receive_time.tv_usec - time_micro) / 1e9;
		printf("Time result: %.9f seconds.\n", time_taken);

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
	bool should_print = true; // cfg.debug && !cfg.quiet;
	UNUSED(obj);

	if (should_print)
		//printf("Subscribed (mid: %d): %d", mid, granted_qos[0]);
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
	// test_dilithium();
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
	//printf("Ready to connect\n");
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
