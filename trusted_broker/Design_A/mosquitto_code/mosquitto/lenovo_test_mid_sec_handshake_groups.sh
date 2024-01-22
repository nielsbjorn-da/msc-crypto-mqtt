#!/bin/bash

# Check if sig_alg and openssl_config_path parameters are provided
if [ -z "$1" ]; then
    echo "Usage: $0 <sig_alg> "
    exit 1
fi

# Get the sig_alg and openssl_config_path parameters
sig_alg_value="$1"
conf_file="/usr/local/ssl/openssl.cnf"

# Define the list of strings
replacement_strings=("kyber768" "X25519" "secp256r1" "p384_kyber768" "X448" "p256_kyber768" "x448_kyber768" "x25519_kyber768" "secp384r1")
replacement_strings=("secp384r1")

# Number of repetitions
num_repetitions=100

echo "Current signature algorithm: $sig_alg_value"

for ((i=1; i<=$num_repetitions; i++)); do
    echo "round $i"
    shuffled_algorithms=($(shuf -e "${replacement_strings[@]}"))

    for replacement_value in "${shuffled_algorithms[@]}"; do
        sudo sed -i "/^Groups/s/.*/Groups = $replacement_value/" "$conf_file"
            
        # Read and print the "Groups" line
        groups_line=$(grep "^Groups" "$conf_file")
        echo "$groups_line"
        client/mosquitto_sub -t "test/topic" -h 192.168.1.115 -p 8883 --cafile "certs/$sig_alg_value/ca.crt" --cert "certs/$sig_alg_value/client.crt" --key "certs/$sig_alg_value/client.key" &
        mosquitto_sub_pid=$!
        sleep 1
    done

done
