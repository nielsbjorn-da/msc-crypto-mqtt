import re
import numpy as np
import matplotlib.pyplot as plt

#path_design_a = '../Design_A/mosquitto_code/mosquitto/client/test_results/Iteration_1/'
path_design = "lan_data/designs/no_tls1/"
path_design2 = "lan_data/designs/no_tls2/"
path_design3 = "lan_data/designs/no_tls2/"
path_design4 = "lan_data/designs/no_tls2/"
path_d2_f512 = "lan_data/lenovo_design_tests/d2_f512/"
path_d3_d5_f1024 = 'lan_data/lenovo_design_tests/d3_d5_f1024/'
pub_filename_a = "time_results_publisher_a.txt"
pub_filename_b = "time_results_publisher_b.txt"
pub_filename_b_avx = "time_results_publisher_b_avx2.txt"

# List of file names
file_names_a = [
    path_design + pub_filename_a,
    path_design2 + pub_filename_a,
    path_design3 + pub_filename_a,
    path_design4 + pub_filename_a,
]
file_names_a = [
    path_d2_f512 + pub_filename_a,
    path_d3_d5_f1024 + pub_filename_a
]
file_names_b = [
    path_design + pub_filename_b,
    path_design2 + pub_filename_b,
    path_design3 + pub_filename_b,
    path_design4 + pub_filename_b,
]
file_names_b = [
    path_d2_f512 + pub_filename_b_avx,
    path_d3_d5_f1024 + pub_filename_b_avx
]
# Dictionary to store average time results for each algorithm
data = {}
counter = 0
# Loop through each file
for file_name in file_names_a:
    print(file_name)
    with open(file_name, 'r') as file:
        lines = file.readlines()
        gen_cjson = []
        sign_msg = []
        encode_sig = []
#        init_time = []
        encode_pk = []
        
        for line in lines:
            line_content = line.split()
            if "---" in line_content[0]:
                continue
            algorithm = line_content[0]
            operation = line_content[1] + " " + line_content[2]
            microsecond_time = int(line_content[-3])
            
            if algorithm + "-" + operation not in data:
                data[algorithm  + "-" + operation] = []
            data[algorithm + "-" + operation].append(microsecond_time)


        # Calculate average time result for the current algorithm
        #average_gen_cjson = np.mean(gen_cjson)
        #average_encode_sig = np.mean(encode_sig)
        #average_sig_msg = np.mean(sign_msg)
#        average_init_time = np.mean(init_time)
        #average_encode_pk = np.mean(encode_pk)
        #print(counter)
        # Extract algorithm name from file name
        #algorithm_name = re.search(r'_publisher_(\w+)', file_name).group(1)
        # Store average time result in the dictionary
#        data[algorithm_name  + "-Initialization time"] = average_init_time
        #data[algorithm_name  + "-Generating cJSON"] = average_gen_cjson
        #data[algorithm_name  + "-Encode signature & PK"] = average_encode_sig + average_encode_pk
        #data[algorithm_name  + "-Sign message"] = average_sig_msg
        
# take averages
data = {key: np.mean(values) for key, values in sorted(data.items())}
for key, value in data.items():
    bla = key.split("-")
    alg = bla[0]
    op = bla[1]
    if op == "Encode PK":
        data[alg + "-Encode signature"] += value
print(data)

data_b = {}
for file_name in file_names_b:
    with open(file_name, 'r') as file:
        lines = file.readlines()
        gen_cjson = []
        sign_msg = []
        encode_sig = []
#        init_time = []
        encode_pk = []
        
        for line in lines:
            line_content = line.split()
            if "---" in line_content[0]:
                continue
            algorithm = line_content[0]
            operation = line_content[1] + " " + line_content[2]
            microsecond_time = int(line_content[-3])
            
            if algorithm + "-" + operation not in data_b:
                data_b[algorithm  + "-" + operation] = []
            data_b[algorithm + "-" + operation].append(microsecond_time)

data_b = {key: np.mean(values) for key, values in sorted(data_b.items())}
data_b["Falcon-512-Signing message"] -= 0    
print("\n\n", data_b)
# Extracting data for each category and algorithm
#categories = ['Initialization time', 'Generating cJSON', 'Encode signature & PK', 'Sign message']
#categories = ['Generating cJSON', 'Encode signature & PK', 'Sign message']
categories = ['Signing message', 'Encode signature', 'Generating cJSON']
algorithms = ['Dilithium2', 'Dilithium3', 'Dilithium5', 'Falcon-512', 'Falcon-1024']

values = [[data[f'{algorithm}-{category}'] for category in categories] for algorithm in algorithms]
print("Here")
bar_width = 0.15
r = np.arange(len(categories))

tab10 = plt.cm.get_cmap('tab10')

# Exclude the first two colors
colors = tab10.colors

for i, algorithm in enumerate(algorithms):
    plt.bar(r + i * bar_width, values[i], width=bar_width, edgecolor='grey', label=f'{algorithm}', color=colors[-i])

plt.ylabel('Logarithmic time (μs)')
plt.yscale('log')  # Set y-axis to logarithmic scale
plt.ylim(1, 10**5)  # Set y-axis limits from 1 to 10^5
plt.title('Publisher phases - unmodified broker')
shown_categories = ['Sign message', 'Encode signature & pk', 'Generate cJSON']

plt.xticks(r + bar_width * 2, shown_categories)
algs = ["Dilithium2", "Dilithium3", "Dilithium5", "Falcon-512", "Falcon-1024"]
plt.legend(algs)

plt.show()
plt.clf()

values = [[data_b[f'{algorithm}-{category}'] for category in categories] for algorithm in algorithms]
bar_width = 0.15
r = np.arange(len(categories))

tab10 = plt.cm.get_cmap('tab10')

# Exclude the first two colors
colors = tab10.colors

for i, algorithm in enumerate(algorithms):
    plt.bar(r + i * bar_width, values[i], width=bar_width, edgecolor='grey', label=f'{algorithm}', color=colors[-i])

plt.ylabel('Logarithmic time (μs)')
plt.yscale('log')  # Set y-axis to logarithmic scale
plt.ylim(1, 10**5)  # Set y-axis limits from 1 to 10^5
plt.title('Publisher phases - modified broker')
shown_categories = ['Sign message', 'Encode signature', 'Generate cJSON']

plt.xticks(r + bar_width * 2, shown_categories)
plt.legend(algs)

plt.show()


