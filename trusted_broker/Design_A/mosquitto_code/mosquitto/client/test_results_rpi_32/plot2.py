import re
import numpy as np
import matplotlib.pyplot as plt

# List of file names
file_names = [
    "time_results_publisher_d2.txt",
    "time_results_publisher_d3.txt",
    "time_results_publisher_d5.txt",
    "time_results_publisher_f512.txt",
    "time_results_publisher_f1024.txt"
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
        cjson_results = []
        for line in lines:
            # Extract values using regular expression
            match1 = re.search(r'(Dilithium2|Dilithium|Falcon|Dilithium3|Dilithium5) initialization execution time: (\d+\.\d+) seconds', line)
            match2 = re.search(r'Signing message (Dilithium|Falcon) execution time: (\d+\.\d+) seconds', line)
            match3 = re.search(r'Encode signature (Dilithium|Falcon) execution time: (\d+\.\d+) seconds', line)
            match4 = re.search(r'Encode PK (Dilithium|Falcon) execution time: (\d+\.\d+) seconds', line)
            match5 = re.search(r'Generating cJSON execution time: (\d+\.\d+) seconds', line)
            if match1:
                result = float(match1.group(2))
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
            if match5:
                result = float(match5.group(1))
                cjson_results.append(result)

        # Calculate average time result for the current algorithm
        average_initialization_results = np.mean(initialization_results)
        average_signing_results = np.mean(signing_results)
        average_encode_sig = np.mean(encode_sig)
        average_encode_pk = np.mean(encode_pk)
        average_cjson_results = np.mean(cjson_results)
        #print(counter)
        # Extract algorithm name from file name
        algorithm_name = re.search(r'_publisher_(\w+)', file_name).group(1)
        # Store average time result in the dictionary
        data[algorithm_name  + "-keygen"] = average_initialization_results
        data[algorithm_name  + "-sign"] = average_signing_results
        data[algorithm_name  + "-encsig"] = average_encode_sig
        data[algorithm_name  + "-encpk"] = average_encode_pk
        data[algorithm_name  + "-cjson"] = average_cjson_results
print(data)


# Extracting data for each category and algorithm
#categories = ['keygen', 'sign', 'encsig', 'encpk', 'cjson']
categories = ['sign', 'encsig', 'encpk', 'cjson']
algorithms = ['d2', 'd3', 'd5', 'f512', 'f1024']

values = [[data[f'{algorithm}-{category}'] for category in categories] for algorithm in algorithms]
bar_width = 0.15
r = np.arange(len(categories))

for i, algorithm in enumerate(algorithms):
    plt.bar(r + i * bar_width, values[i], width=bar_width, edgecolor='grey', label=f'{algorithm}')

plt.xlabel('Categories')
plt.ylabel('Values')
plt.title('publisher 32 bits without keygen')
plt.xticks(r + bar_width * 2, categories)
plt.legend(algorithms)

plt.show()