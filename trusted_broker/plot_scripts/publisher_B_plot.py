import re
import numpy as np
import matplotlib.pyplot as plt

path_design_b = '../Design_B/mosquitto_code/mosquitto/client/test_results/Iteration_1/' 

# List of file names
file_names = [
    path_design_b + "time_results_publisher_d2.txt",
    path_design_b + "time_results_publisher_d3.txt",
    path_design_b + "time_results_publisher_d5.txt",
    path_design_b + "time_results_publisher_f512.txt",
    path_design_b + "time_results_publisher_f1024.txt"
]

# Dictionary to store average time results for each algorithm
data = {}
counter = 0
# Loop through each file
for file_name in file_names:
    with open(file_name, 'r') as file:
        lines = file.readlines()
        gen_cjson = []
        sign_msg = []
        encode_sig = []
#        init_time = []
#        encode_pk = []
        
        for line in lines:
            # Extract values using regular expression
            match1 = re.search(r'Generating cJSON execution time: (\d+) micro seconds.', line)
            match2 = re.search(r'Encode signature (Dilithium2|Dilithium3|Dilithium5|Falcon-512|Falcon-1024) execution time: (\d+) micro seconds.', line)
            match3 = re.search(r'Signing message (Dilithium2|Dilithium3|Dilithium5|Falcon-512|Falcon-1024) execution time: (\d+) micro seconds.', line)
#            match4 = re.search(r'Initialization time: (\d+) micro seconds.', line)
#            match5 = re.search(r'Encode PK (Dilithium2|Dilithium3|Dilithium5|Falcon-512|Falcon-1024) execution time: (\d+) micro seconds.', line)
            
            if match1:
                result = float(match1.group(1))
                #if result < 0.0001:
                gen_cjson.append(result)
            if match2:
                result = float(match2.group(2))
                #if result < 0.0001:
                encode_sig.append(result)
            if match3:
                result = float(match3.group(2))
                #if result < 0.0001:
                sign_msg.append(result)
#            if match4:
#                result = float(match4.group(1))
#                #if result < 0.0001:
#                init_time.append(result)
#            if match5:
#                result = float(match5.group(2))
#                #if result < 0.0001:
#                encode_pk.append(result)

        # Calculate average time result for the current algorithm
        average_gen_cjson = np.mean(gen_cjson)
        average_encode_sig = np.mean(encode_sig)
        average_sig_msg = np.mean(sign_msg)
#        average_init_time = np.mean(init_time)
#        average_encode_pk = np.mean(encode_pk)
        #print(counter)
        # Extract algorithm name from file name
        algorithm_name = re.search(r'_publisher_(\w+)', file_name).group(1)
        # Store average time result in the dictionary
#        data[algorithm_name  + "-Initialization time"] = average_init_time
        data[algorithm_name  + "-Generating cJSON"] = average_gen_cjson
        data[algorithm_name  + "-Encode signature"] = average_encode_sig
        data[algorithm_name  + "-Sign message"] = average_sig_msg
        
        
print(data)


# Extracting data for each category and algorithm
#categories = ['Initialization time', 'Generating cJSON', 'Encode signature & PK', 'Sign message']
categories = ['Sign message', 'Encode signature', 'Generating cJSON']
algorithms = ['d2', 'd3', 'd5', 'f512', 'f1024']

values = [[data[f'{algorithm}-{category}'] for category in categories] for algorithm in algorithms]
bar_width = 0.15
r = np.arange(len(categories))

for i, algorithm in enumerate(algorithms):
    plt.bar(r + i * bar_width, values[i], width=bar_width, edgecolor='grey', label=f'{algorithm}')

plt.xlabel('Phases')
plt.ylabel('Time Log(ms)')
plt.ylim(1, 10**5)  # Set y-axis limits from 1 to 10^5
plt.yscale('log')  # Set y-axis to logarithmic scale
plt.title('Phases publisher - Design B')
plt.xticks(r + bar_width * 2, categories)
algs = ["Dilithium2", "Dilithium3", "Dilithium5", "Falcon-512", "Falcon-1024"]
plt.legend(algs)

plt.show()