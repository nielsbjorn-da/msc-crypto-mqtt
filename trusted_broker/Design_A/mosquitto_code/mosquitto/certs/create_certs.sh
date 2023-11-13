#!/bin/bash

# Check if sig_alg_strings, config_path, and server_cn parameters are provided
if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
    echo "Usage: $0 <sig_alg_strings> <config_path> <server_cn>"
    exit 1
fi

# Get the sig_alg_strings, config_path, and server_cn parameters
sig_alg_value="$1"
config_path="$2"
server_cn="$3"

# Get the current directory
current_dir="$(pwd)"

# Iterate through the list of signature algorithms
    # Create a folder for each signature algorithm in the current directory
    sig_alg_folder="$current_dir/$sig_alg_value"
    mkdir -p "$sig_alg_folder"

    # Run OpenSSL commands with sig_alg_value and server_cn as parameters
    openssl req -x509 -new -newkey "$sig_alg_value" -keyout "$sig_alg_folder/ca.key" -out "$sig_alg_folder/ca.crt" -nodes -subj "/CN=CA" -days 365 -config "$config_path"
    openssl genpkey -algorithm "$sig_alg_value" -out "$sig_alg_folder/server.key"
    openssl req -new -newkey "$sig_alg_value" -keyout "$sig_alg_folder/server.key" -out "$sig_alg_folder/server.csr" -nodes -subj "/CN=$server_cn" -config "$config_path"
    openssl x509 -req -in "$sig_alg_folder/server.csr" -out "$sig_alg_folder/server.crt" -CA "$sig_alg_folder/ca.crt" -CAkey "$sig_alg_folder/ca.key" -CAcreateserial -days 365
    openssl genpkey -algorithm "$sig_alg_value" -out "$sig_alg_folder/client.key"
    openssl req -new -newkey "$sig_alg_value" -keyout "$sig_alg_folder/client.key" -out "$sig_alg_folder/client.csr" -nodes -subj "/CN=client" -config "$config_path"
    openssl x509 -req -in "$sig_alg_folder/client.csr" -out "$sig_alg_folder/client.crt" -CA "$sig_alg_folder/ca.crt" -CAkey "$sig_alg_folder/ca.key" -CAcreateserial -days 365

    echo "Generated files for $sig_alg_value in $sig_alg_folder"
