#!/bin/bash

# Check if sig_alg parameter is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <sig_alg>"
    exit 1
fi

# Get the sig_alg parameter
sig_alg="$1"

# Create cert_path
cert_path="$(pwd)/certs/$sig_alg"

# Update tls_mosquitto.conf and print the updated lines
sed -i "s|^certfile .*|certfile $cert_path/server.crt|" tls_mosquitto.conf
sed -i "s|^keyfile .*|keyfile $cert_path/server.key|" tls_mosquitto.conf
sed -i "s|^cafile .*|cafile $cert_path/ca.crt|" tls_mosquitto.conf

# Print the updated lines
echo "Updated lines in tls_mosquitto.conf:"
grep "certfile /\|keyfile /\|cafile /" tls_mosquitto.conf
