#!/bin/bash

# Number of rounds (for testing purposes)
rounds=0
signature_algorithms=("D2" "F512" "D3" "D5" "F1024")
signature_algorithms=("D3" "D5"  "F1024")

 #Start subscriber and capture its output in time_results.txt
#./client_own_subscriber -t "TestTopic" -p 1884 -h 192.168.50.157 >> time_results_subscriber.txt &
#./client_own_subscriber_b -t "test/topic" -p 1884 -h 192.168.1.115 -i subscriber_client >> lan_test/time_results_subscriber_b.txt &
    # Store subscriber's process ID
#subscriber_b_pid=$!
#./client_own_subscriber -t "test/topic" -p 1883 -h 192.168.1.115 -i subscriber_client >> lenovo_test/time_results_subscriber_a.txt &
    #./client_own_subscriber -t "test/topic"
# Store subscriber's process ID
#subscriber_a_pid=$!


#./client_own_subscriber -i subscriber_client_tls -t "test/topic" -p 8883 -h 192.168.1.115 --key ../certs/p256_remote/client.key --cert ../certs/p256_remote/client.crt --cafile ../certs/p256_remote/ca.crt --tls-version tlsv1.3 >> lan_test/time_results_subscriber_tls_a.txt &
#subscriber_tls_a_pid=$!


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
        #./client_own_test_b -t "test/topic" -m $sig_alg -p 1884 -h 192.168.1.115 >> lan_test/time_results_publisher_b.txt
        
        #sleep 2
        ./client_own_test -t "test/topic" -m $sig_alg -p 1883 -h 192.168.1.115 >> lenovo_test/time_results_publisher_a.txt
        sleep 2

        
        #./client_own_test -t "test/topic" -m $sig_alg -p 8883 -h 192.168.1.115 --key ../certs/p256_remote/client.key --cert ../certs/p256_remote/client.crt --cafile ../certs/p256_remote/ca.crt --tls-version tlsv1.3 >> lan_test/time_results_publisher_tls_a.txt
        #sleep 2
           # ./client_own_test -t "test/topic" -m $sig_alg
	 
        # Add separator to indicate start of a new round in both files
       # echo "---------------------------------------------------------" #>> time_results_publisher.txt

        # Wait for a few seconds to allow subscriber to process and write the time result
    
    done
done
kill $subscriber_a_pid

./client_own_subscriber_b -t "test/topic" -p 1884 -h 192.168.1.115 -i subscriber_client >> lenovo_test/time_results_subscriber_b_avx2.txt &
subscriber_b_pid=$!

sleep 1

rounds=150
for ((i=1; i<=$rounds; i++))
do
    echo "round $i"

    # Shuffle the signature_algorithms array
    shuffled_algorithms=($(shuf -e "${signature_algorithms[@]}"))

    for sig_alg in "${shuffled_algorithms[@]}"; do


        # Start publisher for this round
        #./client_own_test -t "TestTopic" -m "$message" -p 1884 -h 192.168.50.157 >> time_results_publisher.txt
        ./client_own_test_b -t "test/topic" -m $sig_alg -p 1884 -h 192.168.1.115 >> lenovo_test/time_results_publisher_b_avx2.txt
        
        #sleep 2
        #./client_own_test -t "test/topic" -m $sig_alg -p 1883 -h 192.168.1.115 >> lan_test/time_results_publisher_a.txt
        #sleep 2

        #./client_own_test_b -t "test/topic" -m $sig_alg -p 8884 -h 192.168.1.115 --key ../certs/p256_remote/client.key --cert ../certs/p256_remote/client.crt --cafile ../certs/p256_remote/ca.crt --tls-version tlsv1.3 >> lan_test/time_results_publisher_tls_b.txt

        sleep 2
           # ./client_own_test -t "test/topic" -m $sig_alg
	 
        # Add separator to indicate start of a new round in both files
       # echo "---------------------------------------------------------" #>> time_results_publisher.txt

        # Wait for a few seconds to allow subscriber to process and write the time result
    
    done
done
# Terminate the subscriber after rounds finish
kill $subscriber_b_pid
#kill $subscriber_tls_a_pid
#kill $subscriber_tls_b_pid
#kill $mosquitto_broker_pid

echo "Measurement completed. Results are stored in time_results.txt"
