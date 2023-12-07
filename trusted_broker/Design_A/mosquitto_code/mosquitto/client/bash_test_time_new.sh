#!/bin/bash
design_b=false

# Check if "b" is passed as an argument
if [[ "$#" -gt 0 && "$1" == "b" ]]; then
    design_b=true
fi

# Number of rounds (for testing purposes)
rounds=500
signature_algorithms=("D2" "F512" "D3" "F1024" "D5")

if [ "$design_b" = true ]; then
    ./../src/mosquitto_b &
    mosquitto_broker_pid=$!
else 
    ./../src/mosquitto &
    mosquitto_broker_pid=$!
fi

sleep 1
 #Start subscriber and capture its output in time_results.txt
#./client_own_subscriber -t "TestTopic" -p 1884 -h 192.168.50.157 >> time_results_subscriber.txt &
if [ "$design_b" = true ]; then
    ./client_own_subscriber_b -t "test/topic" &
    # Store subscriber's process ID
    subscriber_pid=$!
else 
    ./client_own_subscriber -t "test/topic" &
    # Store subscriber's process ID
    subscriber_pid=$!
fi


# Wait for subscriber to be ready (you might need to adjust the sleep duration)
sleep 1

# Loop over 10 rounds for testing purposes
for ((i=1; i<=$rounds; i++))
do
    echo "round $i"

    # Shuffle the signature_algorithms array
    shuffled_algorithms=($(shuf -e "${signature_algorithms[@]}"))

    for sig_alg in "${shuffled_algorithms[@]}"; do

        # Start publisher for this round
        #./client_own_test -t "TestTopic" -m "$message" -p 1884 -h 192.168.50.157 >> time_results_publisher.txt
        if [ "$design_b" = true ]; then
            ./client_own_test_b -t "test/topic" -m $sig_alg
        else
            ./client_own_test -t "test/topic" -m $sig_alg
        fi
        # Add separator to indicate start of a new round in both files
        echo "---------------------------------------------------------" #>> time_results_publisher.txt

        # Wait for a few seconds to allow subscriber to process and write the time result
        sleep 2
    done
done
# Terminate the subscriber after rounds finish
kill $subscriber_pid
kill $mosquitto_broker_pid

echo "Measurement completed. Results are stored in time_results.txt"
