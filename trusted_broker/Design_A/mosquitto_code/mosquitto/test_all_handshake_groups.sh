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
replacement_strings=("kyber512" "p256_kyber512" "x25519_kyber512" "kyber768" "p384_kyber768" "x448_kyber768" "x25519_kyber768" "p256_kyber768" "kyber1024" "p521_kyber1024" "secp256r1" "secp384r1" "secp521r1" "X25519" "X448")

# Number of repetitions
num_repetitions=10

echo "Current signature algorithm: $sig_alg_value"
# Iterate through the list and perform the replacement for each string
for replacement_value in "${replacement_strings[@]}"; do
    sudo sed -i "/^Groups/s/.*/Groups = $replacement_value/" "$conf_file"
        
    # Read and print the "Groups" line
    groups_line=$(grep "^Groups" "$conf_file")
    echo "$groups_line"

 # Iterate through the list of signature algorithms
    for ((i=1; i<=$num_repetitions; i++)); do
        # Start mosquitto_sub with the corresponding signature algorithm
        client/mosquitto_sub -t "test/topic" --cafile "certs/$sig_alg_value/ca.crt" --cert "certs/$sig_alg_value/client.crt" --key "certs/$sig_alg_value/client.key" &
        mosquitto_sub_pid=$!
	sleep 1
    done
done

	
