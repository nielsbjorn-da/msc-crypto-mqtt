#!/bin/bash

# Get the sig_alg and openssl_config_path parameters

conf_file="/usr/local/ssl/openssl.cnf"

# Define the list of strings

# Number of repetitions
num_repetitions=100


for ((i=1; i<=$num_repetitions; i++)); do
    echo "round $i"
    

    
    
            
        # Read and print the "Groups" line
    
    
    client/mosquitto_sub -t "test/topic" -h 192.168.1.115 -p 1883 &
    mosquitto_sub_pid=$!
    sleep 1
    done

done
