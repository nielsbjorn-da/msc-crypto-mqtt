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
file_names2 = [
    "../test_results_rpi_64/time_results_subscriber_d2.txt",
    "../test_results_rpi_64/time_results_subscriber_d3.txt",
    "../test_results_rpi_64/time_results_subscriber_d5.txt",
    "../test_results_rpi_64/time_results_subscriber_f512.txt",
    "../test_results_rpi_64/time_results_subscriber_f1024.txt"
]
# Dictionary to store average time results for each algorithm
average_results = {}
counter = 0
# Loop through each file
for file_name in file_names:
    with open(file_name, 'r') as file:
        lines = file.readlines()
        time_results = []
        for line in lines:
            # Extract 'Time result' values using regular expression
            match = re.search(r'Time result: (\d+\.\d+) seconds', line)
            if match:
                time_result = float(match.group(1))
                time_results.append(time_result)
                counter += 1
        # Calculate average time result for the current algorithm
        average_time_result = np.mean(time_results)
        #print(counter)
        # Extract algorithm name from file name
        algorithm_name = re.search(r'_subscriber_(\w+)', file_name).group(1)
        # Store average time result in the dictionary
        average_results[algorithm_name  + "-32"] = average_time_result
print(average_results)


#----------------------------------------------------------------------------------------

# Dictionary to store average time results for each algorithm
average_results2 = {}
counter2 = 0
# Loop through each file
for file_name2 in file_names2:
    with open(file_name2, 'r') as file:
        lines = file.readlines()
        time_results2 = []
        for line in lines:
            # Extract 'Time result' values using regular expression
            match2 = re.search(r'Time result: (\d+\.\d+) seconds', line)
            if match2:
                time_result2 = float(match2.group(1))
                time_results2.append(time_result2)
                counter2 += 1
        # Calculate average time result for the current algorithm
        average_time_result2 = np.mean(time_results2)
        #print(counter2)
        # Extract algorithm name from file name
        algorithm_name2 = re.search(r'_subscriber_(\w+)', file_name2).group(1)
        # Store average time result in the dictionary
        average_results2[algorithm_name2 + "-64"] = average_time_result2
print(average_results2)

'''# Combine 32-bit and 64-bit results for each algorithm
combined_results = {}
for key, value in average_results.items():
    if key in average_results2:
        combined_results[key] = (value, average_results2[key])
    else:
        combined_results[key] = (value, average_results[key])  # Set the value to 0 or handle it appropriately

# Extract algorithm names and average times for plotting
algorithm_names = list(combined_results.keys())
average_times_32 = [value[0] for value in combined_results.values()]
average_times_64 = [value[1] for value in combined_results.values()]
print(average_times_32)
print(average_times_64)'''

# Create a bar plot to compare average time results
bar_width = 0.35
index = np.arange(len(average_results.keys()))
plt.bar(index, average_results.values(), bar_width, label='32-bit')
plt.bar(index + bar_width, average_results2.values(), bar_width, label='64-bit')
plt.xlabel('Algorithms')
plt.ylabel('Average Time Result (seconds)')
plt.title('Average Time Results for Different Algorithms')
an = []
for i in range(len(average_results)):
    an.append(list(average_results.keys())[i].split("-")[0])
plt.xticks(index + bar_width / 2, an)
#plt.yscale('log')  # Set y-axis to logarithmic scale
plt.legend()
plt.tight_layout()  # Ensures labels are not cut off
plt.show()


'''# Create a bar plot to compare average time results
plt.bar(average_results.keys(), average_results.values())
plt.xlabel('Algorithms')
plt.ylabel('Average Time Result (seconds)')
plt.title('Average Time Results for Different Algorithms')
plt.show()
'''