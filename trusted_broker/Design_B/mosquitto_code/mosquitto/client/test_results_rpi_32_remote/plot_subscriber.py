import re
import numpy as np
import matplotlib.pyplot as plt

path = 'Design_B/mosquitto_code/mosquitto/client/test_results_rpi_32_remote/'

# List of file names
file_names = [
    path + "time_results_subscriber_d2_remote.txt",
    path + "time_results_subscriber_d3_remote.txt",
    path + "time_results_subscriber_d5_remote.txt",
    path + "time_results_subscriber_f512_remote.txt",
    path + "time_results_subscriber_f1024_remote.txt"
]

# Dictionary to store average time results for each algorithm
data = {}
counter = 0
# Loop through each file
for file_name in file_names:
    with open(file_name, 'r') as file:
        lines = file.readlines()
        extracting_payload = []
        decode_sig = []
        verification_result = []
        for line in lines:
            # Extract values using regular expression
            match1 = re.search(r'Extracting payload from cJSON execution time: (\d+\.\d+) seconds', line)
            match2 = re.search(r'Decode sig (Dilithium|Falcon) execution time: (\d+\.\d+) seconds', line)
            match3 = re.search(r'Verification (Dilithium|Falcon) execution time: (\d+\.\d+) seconds', line)
            if match1:
                result = float(match1.group(1))
                extracting_payload.append(result)
            if match2:
                result = float(match2.group(2))
                decode_sig.append(result)
            if match3:
                result = float(match3.group(2))
                verification_result.append(result)

        # Calculate average time result for the current algorithm
        average_cjson = np.mean(extracting_payload)
        average_decode_sig = np.mean(decode_sig)
        average_verify = np.mean(verification_result)

        # Extract algorithm name from file name
        algorithm_name = re.search(r'_subscriber_(\w+)_remote', file_name).group(1)
        # Store average time result in the dictionary
        data[algorithm_name  + "-Extract cJSON"] = average_cjson
        data[algorithm_name  + "-Decode signature"] = average_decode_sig
        data[algorithm_name  + "-Verification"] = average_verify
print(data)


# Extracting data for each category and algorithm
categories = ['Extract cJSON', 'Decode signature', 'Verification']
algorithms = ['d2', 'd3', 'd5', 'f512', 'f1024']

values = [[data[f'{algorithm}-{category}'] for category in categories] for algorithm in algorithms]
bar_width = 0.15
r = np.arange(len(categories))

for i, algorithm in enumerate(algorithms):
    plt.bar(r + i * bar_width, values[i], width=bar_width, edgecolor='grey', label=f'{algorithm}')

plt.xlabel('Categories')
plt.ylabel('Time')
plt.yscale('log')  # Set y-axis to logarithmic scale
plt.title('Subscriber 32-bit - Design B Network')
plt.xticks(r + bar_width * 2, categories)
plt.legend(algorithms)

plt.show()