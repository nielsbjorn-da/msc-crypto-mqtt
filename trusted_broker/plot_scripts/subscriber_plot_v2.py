import re
import numpy as np
import matplotlib.pyplot as plt


path_design = "lan_data/designs/no_tls1/"
path_design2 = "lan_data/designs/no_tls2/"
path_design3 = "lan_data/designs/no_tls2/"
path_design4 = "lan_data/designs/no_tls2/"

path_d2_f512 = "lan_data/lenovo_design_tests/d2_f512/"
path_d3_d5_f1024 = 'lan_data/lenovo_design_tests/d3_d5_f1024/'
sub_filename_a = "time_results_subscriber_a.txt"
sub_filename_b = "time_results_subscriber_b.txt"
sub_filename_b_avx2 = "time_results_subscriber_b_avx2.txt"

# List of file names
file_names_a = [
    path_d2_f512 + sub_filename_a,
    path_d3_d5_f1024 + sub_filename_a,
]

file_names_b = [
    path_d2_f512 + sub_filename_b_avx2,
    path_d3_d5_f1024 + sub_filename_b_avx2
]

# Dictionary to store average time results for each algorithm
data = {}
counter = 0



# Loop through each file
for file_name in file_names_a:
    # Extract algorithm name from file name
    algorithm_name = re.search(r'_subscriber_(\w+)', file_name).group(1)
    with open(file_name, 'r') as file:
        lines = file.readlines()
        for line in lines:
            line_content = line.split()
            if len(line_content) < 1 or "---" in line_content[0]:
                continue
            algorithm = line_content[0]
            operation = line_content[1] + " " + line_content[2]
            microsecond_time = int(line_content[-3])
            
            if algorithm + "-" + operation not in data:
                data[algorithm  + "-" + operation] = []
            data[algorithm + "-" + operation].append(microsecond_time)
data = {key: np.mean(values) for key, values in sorted(data.items())}   
for key, value in data.items():
    bla = key.split("-")
    alg = bla[0]
    op = bla[1]
    if op == "Decode PK":
        data[alg + "-Decode sig"] += value
print(data)


data_b = {}
for file_name in file_names_b:
    # Extract algorithm name from file name
    algorithm_name = re.search(r'_subscriber_(\w+)', file_name).group(1)
    with open(file_name, 'r') as file:
        lines = file.readlines()
        for line in lines:
            line_content = line.split()
            if len(line_content) < 1 or "---" in line_content[0]:
                continue
            algorithm = line_content[0]
            operation = line_content[1] + " " + line_content[2]
            microsecond_time = int(line_content[-3])
            
            if algorithm + "-" + operation not in data_b:
                data_b[algorithm  + "-" + operation] = []
            data_b[algorithm + "-" + operation].append(microsecond_time)
data_b = {key: np.mean(values) for key, values in sorted(data_b.items())}  
print("\n\n", data_b)

# Extracting data for each category and algorithm
categories = ['Extracting payload', 'Decode sig', 'Verification execution']
algorithms = ['Dilithium2', 'Dilithium3', 'Dilithium5', 'Falcon-512', 'Falcon-1024']

values = [[data[f'{algorithm}-{category}'] for category in categories] for algorithm in algorithms]
bar_width = 0.15
r = np.arange(len(categories))


tab10 = plt.cm.get_cmap('tab10')
# Exclude the first two colors

for i, algorithm in enumerate(algorithms):
    plt.bar(r + i * bar_width, values[i], width=bar_width, edgecolor='grey', label=f'{algorithm}', color=tab10.colors[-i])

plt.ylabel('Logarithmic time (μs)')
plt.yscale('log')  # Set y-axis to logarithmic scale
plt.ylim(1, 10**5)  # Set y-axis limits from 1 to 10^5
plt.title('Subscriber phases - unmodified broker')
shown_categories = ["Extract cJSON", "Decode signature & pk", "Verify"]
plt.xticks(r + bar_width * 2, shown_categories)
algs = ["Dilithium2", "Dilithium3", "Dilithium5", "Falcon-512", "Falcon-1024"]
plt.legend(algs)

plt.show()
plt.clf()

values = [[data_b[f'{algorithm}-{category}'] for category in categories] for algorithm in algorithms]
for i, algorithm in enumerate(algorithms):
    plt.bar(r + i * bar_width, values[i], width=bar_width, edgecolor='grey', label=f'{algorithm}', color=tab10.colors[-i])

plt.ylabel('Logarithmic time (μs)')
plt.yscale('log')  # Set y-axis to logarithmic scale
plt.ylim(1, 10**5)  # Set y-axis limits from 1 to 10^5
plt.title('Subscriber phases - modified broker')
shown_categories = ["Extract cJSON", "Decode signature", "Verify"]
plt.xticks(r + bar_width * 2, shown_categories)
algs = ["Dilithium2", "Dilithium3", "Dilithium5", "Falcon-512", "Falcon-1024"]
plt.legend(algs)

plt.show()