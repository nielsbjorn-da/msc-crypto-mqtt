#!/bin/bash

# Number of repetitions
num_repetitions=100

# Iterate through the list of signature algorithms
for ((i=1; i<=$num_repetitions; i++)); do
    # Start mosquitto_sub with the corresponding signature algorithm
        client/mosquitto_sub -t "test/topic"
done
