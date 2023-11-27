#!/bin/bash

# Check if sig_alg and openssl_config_path parameters are provided
if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: $0 <sig_alg> <openssl_config_path>"
    exit 1
fi

# Get the sig_alg and openssl_config_path parameters
sig_alg_value="$1"
conf_file="$2"

# Define the list of strings
replacement_strings=("kyber512" "X25519" "secp256r1" "p256_kyber512" "x25519_kyber512")

# Number of repetitions
num_repetitions=100

echo "Current signature algorithm: $sig_alg_value"
# Iterate through the list and perform the replacement for each string
for replacement_value in "${replacement_strings[@]}"; do
    sudo sed -i "/^Groups/s/.*/Groups = $replacement_value/" "$conf_file"
        
    # Read and print the "Groups" line
    groups_line=$(grep "^Groups" "$conf_file")
    echo "$groups_line"
 # Iterate through the list of signature algorithms
    src/mosquitto -c tls_mosquitto.conf & mosquitto_pid=$!
    sleep 1
    for ((i=1; i<=$num_repetitions; i++)); do
        # Start mosquitto_sub with the corresponding signature algorithm
        client/mosquitto_sub -t "test/topic" -h localhost -p 8883 --cafile "certs/$sig_alg_value/ca.crt" --cert "certs/$sig_alg_value/client.crt" --key "certs/$sig_alg_value/client.key" &
        mosquitto_sub_pid=$!
	sleep 1
    done
    kill $mosquitto_pid
    sleep 1
done

	
