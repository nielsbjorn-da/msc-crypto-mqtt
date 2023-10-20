#!/bin/bash

# Number of rounds (for testing purposes)
rounds=1000

# Start subscriber and capture its output in time_results.txt
./client_own_subscriber -t "TestTopic" > time_results.txt &

# Store subscriber's process ID
subscriber_pid=$!

# Wait for subscriber to be ready (you might need to adjust the sleep duration)
sleep 2

# Loop over 10 rounds for testing purposes
for ((i=1; i<=$rounds; i++))
do
    # Generate a unique message for each round
    message="Round $i: this is test message number $i"

    # Start publisher for this round
    ./client_own_test -t "TestTopic" -m "$message"

    # Wait for a few seconds to allow subscriber to process and write the time result
done
sleep 2
# Terminate the subscriber after rounds finish
kill $subscriber_pid

echo "Measurement completed. Results are stored in time_results.txt"
