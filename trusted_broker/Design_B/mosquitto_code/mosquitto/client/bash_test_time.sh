#!/bin/bash

# Number of rounds (for testing purposes)
rounds=500

 #Start subscriber and capture its output in time_results.txt
./client_own_subscriber -t "TestTopic" -p 1884 -h 192.168.50.157 > time_results_subscriber.txt &

# Store subscriber's process ID
subscriber_pid=$!

# Wait for subscriber to be ready (you might need to adjust the sleep duration)
sleep 1

# Loop over 10 rounds for testing purposes
for ((i=1; i<=$rounds; i++))
do
    echo "Round $i"
    # Generate a unique message for each round
    message="Round $i: this is test message number $i"

    # Start publisher for this round
    ./client_own_test -t "TestTopic" -m "$message" -p 1884 -h 192.168.50.157 >> time_results_publisher.txt

    # Add separator to indicate start of a new round in both files
    echo "---------------------------------------------------------" >> time_results_publisher.txt

    # Wait for a few seconds to allow subscriber to process and write the time result
    sleep 0  
done
# Terminate the subscriber after rounds finish
kill $subscriber_pid

echo "Measurement completed. Results are stored in time_results.txt"
