#!/bin/bash

# Start MQTT broker (mosquitto) from src directory
echo "Starting MQTT broker (mosquitto)..."
cd src
./mosquitto -d

# Wait for the broker to start (add more sleep time if needed)
sleep 2

# Start subscriber script with argument -t "TestTopic" from client folder
echo "Starting subscriber script..."
cd ../client
./subscriber_script.sh -t "TestTopic" &

# Wait for the subscriber script to run (add more sleep time if needed)
sleep 2

# Start publisher client script x times with arguments -t "TestTopic" and -m "message"
# where message grows in size for each iteration
x=5  # Change this to the desired number of iterations
for ((i=1; i<=$x; i++)); do
    message="message"
    for ((j=1; j<=$i; j++)); do
        message+="X"  # Message grows in size with each iteration
    done
    echo "Running client_own_test iteration $i with message: $message"
    ./client_own_test.sh -t "TestTopic" -m "$message"
    sleep 1  # Add a delay between iterations if needed
done

# Optionally, stop the MQTT broker after all operations are done
# echo "Stopping MQTT broker (mosquitto)..."
# pkill mosquitto

echo "All operations completed."
