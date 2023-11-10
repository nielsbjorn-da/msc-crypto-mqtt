#!/bin/bash

# Function to run Python script in the background
function run_script {
    python3 "$1" &
}

# Run each Python script in the background
run_script "Design_A/mosquitto_code/mosquitto/client/test_results_rpi_32_local_network_2/plot_publisher.py"
run_script "Design_A/mosquitto_code/mosquitto/client/test_results_rpi_32_local_network_2/plot_subscriber.py"
run_script "Design_A/mosquitto_code/mosquitto/client/test_results_rpi_32_remote/plot_publisher.py"
run_script "Design_A/mosquitto_code/mosquitto/client/test_results_rpi_32_remote/plot_subscriber.py"
run_script "Design_B/mosquitto_code/mosquitto/client/test_results_rpi_32_local/plot_publisher.py"
run_script "Design_B/mosquitto_code/mosquitto/client/test_results_rpi_32_local/plot_subscriber.py"
run_script "Design_B/mosquitto_code/mosquitto/client/test_results_rpi_32_remote/plot_publisher.py"
run_script "Design_B/mosquitto_code/mosquitto/client/test_results_rpi_32_remote/plot_subscriber.py"
