import re
import numpy as np
import matplotlib.pyplot as plt
import sys

algorithms = ["AES-128-GCM", "ASCON-128", "ASCON-128A", "ASCON-80PQ"]
message_sizes = [32, 64, 128, 256, 512, 1024]

    # Define a regular expression pattern to extract relevant information
pattern = re.compile(r'(\w+-\d+[A-Za-z-]*) (\d+ bytes) (\w+ time): (\d+) micro seconds.')

# Initialize a nested dictionary
result_dict = {}

data_path = 'test_results1.txt'
data_path = 'o2_optimization_test.txt'
#data_path = 'o3_optimization_test.txt'

with open(data_path, 'r') as data:


    # Iterate through the lines of the data
    for line in data:
        # Use regular expression to extract information
        match = pattern.match(line)
        
        if match:
            algorithm_name = match.group(1)
            message_size = match.group(2).split()[0]
            time_type = match.group(3).split()[0]
            time_value = int(match.group(4))

            # Create nested dictionaries if not present
            if message_size not in result_dict:
                result_dict[message_size] = {}
            if algorithm_name not in result_dict[message_size]:
                result_dict[message_size][algorithm_name] = {'encryption': [], 'decryption': [], 'total': []}
            
            # Append time value to the corresponding key
            result_dict[message_size][algorithm_name][time_type].append(time_value)

# Calculate averages for each array
for size, algorithms in result_dict.items():
    for algorithm, times in algorithms.items():
        for time_type, values in times.items():
            result_dict[size][algorithm][time_type] = np.average(values)

values_to_plot = {}
# Iterate through outer keys
for message_size, algo_dict in result_dict.items():
    # Iterate through inner keys and values
    print(values_to_plot)
    print("message size", message_size)
    for algo, time_dict in algo_dict.items():
        total_time = algo_dict[algo]["total"]
        if algo not in values_to_plot:
            values_to_plot[algo] = [total_time]
        else:
            values_to_plot[algo].append(total_time)
print(values_to_plot)

x = np.arange(len(message_sizes))  # the label locations
width = 0.15  # the width of the bars
multiplier = 0

fig, ax = plt.subplots(layout='constrained')

for attribute, measurement in values_to_plot.items():
    offset = width * multiplier
    rects = ax.bar(x + offset, measurement, width, label=attribute)
    multiplier += 1


# Add some text for labels, title and custom x-axis tick labels, etc.
ax.set_ylabel('Time (μs)')
ax.set_title('Encryption + Decryption time in OpenSSL on Raspberry Pi')
ax.set_xticks(x + width, message_sizes)
ax.legend()
plt.xlabel('Plaintext size (bytes)')

plt.show()