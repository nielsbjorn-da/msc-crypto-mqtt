import re
import numpy as np
import matplotlib.pyplot as plt

# List of file names
file_names = [
    "time_results_subscriber_d2.txt",
    "time_results_subscriber_d3.txt",
    "time_results_subscriber_d5.txt",
    "time_results_subscriber_f512.txt",
    "time_results_subscriber_f1024.txt"
]


'''# List of file names
file_names = [
    "../test_results_rpi_64/time_results_publisher_d2.txt",
    "../test_results_rpi_64/time_results_publisher_d3.txt",
    "../test_results_rpi_64/time_results_publisher_d5.txt",
    "../test_results_rpi_64/time_results_publisher_f512.txt",
    "../test_results_rpi_64/time_results_publisher_f1024.txt"
]'''

# Dictionary to store average time results for each algorithm
data = {}
counter = 0
# Loop through each file
for file_name in file_names:
    with open(file_name, 'r') as file:
        lines = file.readlines()
        initialization_results = []
        signing_results = []
        encode_sig = []
        encode_pk = []
        for line in lines:
            # Extract values using regular expression
            match1 = re.search(r'Extracting payload from cJSON execution time: (\d+\.\d+) seconds', line)
            match2 = re.search(r'Decode sig (Dilithium|Falcon) execution time: (\d+\.\d+) seconds', line)
            match3 = re.search(r'Decode PK (Dilithium|Falcon) execution time: (\d+\.\d+) seconds', line)
            match4 = re.search(r'Verification (Dilithium|Falcon) execution time: (\d+\.\d+) seconds', line)
            if match1:
                result = float(match1.group(1))
                initialization_results.append(result)
            if match2:
                result = float(match2.group(2))
                signing_results.append(result)
            if match3:
                result = float(match3.group(2))
                encode_sig.append(result)
            if match4:
                result = float(match4.group(2))
                encode_pk.append(result)

        # Calculate average time result for the current algorithm
        average_parse_json = np.mean(initialization_results)
        average_signing_results = np.mean(signing_results)
        average_decode = np.mean(encode_sig + signing_results)
        average_verify = np.mean(encode_pk)
        #print(counter)
        # Extract algorithm name from file name
        algorithm_name = re.search(r'_subscriber_(\w+)', file_name).group(1)
        # Store average time result in the dictionary
        data[algorithm_name  + "-parse json"] = average_parse_json
        data[algorithm_name  + "-decode sig & pk"] = average_decode
        data[algorithm_name  + "-verify"] = average_verify
print(data)


# Extracting data for each category and algorithm
categories = ['parse json', 'decode sig & pk', 'verify']
#categories = ['sign', 'encsig', 'encpk', 'cjson']
algorithms = ['d2', 'd3', 'd5', 'f512', 'f1024']

values = [[data[f'{algorithm}-{category}'] for category in categories] for algorithm in algorithms]
bar_width = 0.15
r = np.arange(len(categories))

for i, algorithm in enumerate(algorithms):
    plt.bar(r + i * bar_width, values[i], width=bar_width, edgecolor='grey', label=f'{algorithm}')

plt.xlabel('Categories')
plt.ylabel('Time')
plt.title('Subscriber 32 bit  bits')
plt.xticks(r + bar_width * 2, categories)
plt.legend(algorithms)

plt.show()