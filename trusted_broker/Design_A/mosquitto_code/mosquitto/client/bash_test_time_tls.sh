#!/bin/bash
design_b=false

# Check if "b" is passed as an argument
if [[ "$#" -gt 0 && "$1" == "b" ]]; then
    design_b=true
fi

# Number of rounds (for testing purposes)
rounds=2000
signature_algorithms=("D2" "F512" "D3" "F1024" "D5")
signature_algorithms=("D2" "F512")

ciphers=("TLS_ASCON_80PQ_SHA256" "TLS_ASCON_128_SHA256" "TLS_ASCON_128A_SHA256" "TLS_AES_128_GCM_SHA256")

#if [ "$design_b" = true ]; then
 #   ./../src/mosquitto_b &
  #  mosquitto_broker_pid=$!
#else 
#    ./../src/mosquitto &
#    mosquitto_broker_pid=$!
#fi
 #Start subscriber and capture its output in time_results.txt
#./client_own_subscriber -t "TestTopic" -p 1884 -h 192.168.50.157 >> time_results_subscriber.txt &
if [ "$design_b" = true ]; then
    ./client_own_subscriber_b -t "test/topic" -p 8884 -h 192.168.1.115 --key ../certs/dilithium2/client.key --cert ../certs/dilithium2/client.crt --cafile ../certs/dilithium2/ca.crt --tls-version tlsv1.3 & #>> lenovo_test/ascon128/time_results_subscriber_b_tls.txt &
    # Store subscriber's process ID
    subscriber_pid=$!
else 
    #./client_own_subscriber -t "test/topic" -p 8883 -h 192.168.1.115 --key ../certs/dilithium2/client.key --cert ../certs/dilithium2/client.crt --cafile ../certs/dilithium2/ca.crt --tls-version tlsv1.3  >> lenovo_test/latency/time_results_subscriber_a_tls.txt &
    ./client_own_subscriber -t "test/topic" -p 8883 -h 185.187.145.40 --key ../certs/dilithium2/client.key --cert ../certs/dilithium2/client.crt --cafile ../certs/dilithium2/ca.crt --tls-version tlsv1.3  >> lenovo_test/latency/time_results_subscriber_a_tls.txt &

    #./client_own_subscriber -t "test/topic"
# Store subscriber's process ID
    subscriber_pid=$!
#    ./client_own_subscriber_b -t "test/topic" -p 8884 -h 192.168.1.115 --key ../certs/dilithium2/client.key --cert ../certs/dilithium2/client.crt --cafile ../certs/dilithium2/ca.crt --tls-version tlsv1.3 >> lenovo_test/latency/time_results_subscriber_b_tls.txt &
    ./client_own_subscriber_b -t "test/topic" -p 8884 -h 185.187.145.40 --key ../certs/dilithium2/client.key --cert ../certs/dilithium2/client.crt --cafile ../certs/dilithium2/ca.crt --tls-version tlsv1.3 >> lenovo_test/latency/time_results_subscriber_b_tls.txt &

    subscriber_b_pid=$!
fi


# Wait for subscriber to be ready (you might need to adjust the sleep duration)
sleep 2

# Loop over 10 rounds for testing purposes
for ((i=1; i<=$rounds; i++))
do
    echo "round $i"

    # Shuffle the signature_algorithms array
    shuffled_algorithms=($(shuf -e "${signature_algorithms[@]}"))

    ran1=$((RANDOM % 2))
    ran2=$((RANDOM % 2))

    if [ $ran1 -eq 0 ]; then
        if [ $ran2 -eq 0 ]; then
            ./client_own_test_a -t "test/topic" -m "D2" -p 8883 -h 185.187.145.40 --key ../certs/dilithium2/client.key --cert ../certs/dilithium2/client.crt --cafile ../certs/dilithium2/ca.crt --tls-version tlsv1.3 >> lenovo_test/latency/time_results_publisher_a_tls.txt
            sleep 2
            ./client_own_test_b -t "test/topic" -m "F512" -p 8884 -h 185.187.145.40 --key ../certs/dilithium2/client.key --cert ../certs/dilithium2/client.crt --cafile ../certs/dilithium2/ca.crt --tls-version tlsv1.3 >> lenovo_test/latency/time_results_publisher_b_tls.txt
            sleep 2
        else 
            ./client_own_test_a -t "test/topic" -m "F512" -p 8883 -h 185.187.145.40 --key ../certs/dilithium2/client.key --cert ../certs/dilithium2/client.crt --cafile ../certs/dilithium2/ca.crt --tls-version tlsv1.3 >> lenovo_test/latency/time_results_publisher_a_tls.txt
            sleep 2
            ./client_own_test_b -t "test/topic" -m "D2" -p 8884 -h 185.187.145.40 --key ../certs/dilithium2/client.key --cert ../certs/dilithium2/client.crt --cafile ../certs/dilithium2/ca.crt --tls-version tlsv1.3 >> lenovo_test/latency/time_results_publisher_b_tls.txt
            sleep 2
        fi
    else
        if [ $ran2 -eq 0 ]; then
            ./client_own_test_b -t "test/topic" -m "F512" -p 8884 -h 185.187.145.40 --key ../certs/dilithium2/client.key --cert ../certs/dilithium2/client.crt --cafile ../certs/dilithium2/ca.crt --tls-version tlsv1.3 >> lenovo_test/latency/time_results_publisher_b_tls.txt
            sleep 2
            ./client_own_test_a -t "test/topic" -m "D2" -p 8883 -h 185.187.145.40 --key ../certs/dilithium2/client.key --cert ../certs/dilithium2/client.crt --cafile ../certs/dilithium2/ca.crt --tls-version tlsv1.3 >> lenovo_test/latency/time_results_publisher_a_tls.txt
            sleep 2
        else
            ./client_own_test_b -t "test/topic" -m "D2" -p 8884 -h 185.187.145.40 --key ../certs/dilithium2/client.key --cert ../certs/dilithium2/client.crt --cafile ../certs/dilithium2/ca.crt --tls-version tlsv1.3 >> lenovo_test/latency/time_results_publisher_b_tls.txt
            sleep 2 
            ./client_own_test_a -t "test/topic" -m "F512" -p 8883 -h 185.187.145.40 --key ../certs/dilithium2/client.key --cert ../certs/dilithium2/client.crt --cafile ../certs/dilithium2/ca.crt --tls-version tlsv1.3 >> lenovo_test/latency/time_results_publisher_a_tls.txt
            sleep 2
        fi        
    fi
#    for sig_alg in "${shuffled_algorithms[@]}"; do
 #       if [$(( RANDOM % 2)) == 0]; do

  #      else

   #     fi 
        # Start publisher for this round
        #./client_own_test -t "TestTopic" -m "$message" -p 1884 -h 192.168.50.157 >> time_results_publisher.txt
    #    if [ "$design_b" = true ]; then
     #       ./client_own_test_b -t "test/topic" -m $sig_alg -p 8884 -h 192.168.1.115 --key ../certs/dilithium2/client.key --cert ../certs/dilithium2/client.crt --cafile ../certs/dilithium2/ca.crt --tls-version tlsv1.3 #>> lenovo_test/ascon128/time_results_publisher_b_tls.txt
      #  else
           # ./client_own_test_b -t "test/topic" -m $sig_alg -p 8884 -h 192.168.1.115 --key ../certs/dilithium2/client.key --cert ../certs/dilithium2/client.crt --cafile ../certs/dilithium2/ca.crt --tls-version tlsv1.3 >> lenovo_test/latency/time_results_publisher_b_tls.txt
 #           ./client_own_test_b -t "test/topic" -m $sig_alg -p 8884 -h 185.187.145.40 --key ../certs/dilithium2/client.key --cert ../certs/dilithium2/client.crt --cafile ../certs/dilithium2/ca.crt --tls-version tlsv1.3 >> lenovo_test/latency/time_results_publisher_b_tls.txt

  #          sleep 2
    #        ./client_own_test -t "test/topic" -m $sig_alg -p 8883 -h 192.168.1.115 --key ../certs/dilithium2/client.key --cert ../certs/dilithium2/client.crt --cafile ../certs/dilithium2/ca.crt --tls-version tlsv1.3 #>> lenovo_test/latency/time_results_publisher_a_tls.txt
   #         ./client_own_test -t "test/topic" -m $sig_alg -p 8883 -h 185.187.145.40 --key ../certs/dilithium2/client.key --cert ../certs/dilithium2/client.crt --cafile ../certs/dilithium2/ca.crt --tls-version tlsv1.3 >> lenovo_test/latency/time_results_publisher_a_tls.txt
    #        sleep 2
	              # ./client_own_test -t "test/topic" -m $sig_alg
	 #   fi
        # Add separator to indicate start of a new round in both files
       # echo "---------------------------------------------------------" #>> time_results_publisher.txt

        # Wait for a few seconds to allow subscriber to process and write the time result
        
    #done
done
# Terminate the subscriber after rounds finish
kill $subscriber_pid
kill $subscriber_b_pid
#kill $mosquitto_broker_pid

echo "Measurement completed. Results are stored in time_results.txt"
