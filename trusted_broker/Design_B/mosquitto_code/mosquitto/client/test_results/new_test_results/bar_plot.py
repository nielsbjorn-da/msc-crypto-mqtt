import re
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd

path_design_b = 'Design_B/mosquitto_code/mosquitto/client/new_test_results/'
path_design_a = '../../../../../Design_A/mosquitto_code/mosquitto/client/new_test_results/'

# List of file names
design_a = [
    path_design_b + path_design_a + "time_results_subscriber_d2.txt",
    path_design_b + path_design_a + "time_results_subscriber_d3.txt",
    path_design_b + path_design_a + "time_results_subscriber_d5.txt",
    path_design_b + path_design_a + "time_results_subscriber_f512.txt",
    path_design_b + path_design_a + "time_results_subscriber_f1024.txt"
]

design_b = [
    path_design_b + "time_results_subscriber_d2.txt",
    path_design_b + "time_results_subscriber_d3.txt",
    path_design_b + "time_results_subscriber_d5.txt",
    path_design_b + "time_results_subscriber_f512.txt",
    path_design_b + "time_results_subscriber_f1024.txt"
]

element_number = 3561
upper_bound = 20

# Dictionary to store total time results for each algorithm in design a
data_a = {}
counter_a = 0

# Loop through each file in design_b
for file_name in design_a:
    with open(file_name, 'r') as file:
        # Extract algorithm name from file name
        algorithm_name = re.search(r'_subscriber_(\w+)', file_name).group(1)
        total_time_a = []
        
        # Read all this lines of the file
        lines = file.readlines()
        #print(len(lines))
        for line in lines:
            # Extract values using regular expression
            match = re.search(r'Total time result: (\d+\.\d+) seconds', line)
            if match:
                result = float(match.group(1))
                if result < upper_bound:
                    total_time_a.append(result)
                    counter_a += 1
        print(counter_a, "number of elements in", algorithm_name, "in design A")
        counter_a = 0

        # Store result in the dictionary with algorithm as key
        data_a[algorithm_name] = total_time_a

# Create data for design b
new_data_a = {}
for i in data_a:
    temp = []
    for j in range(0, element_number):
        temp.append(data_a[i][j])
    #print(len(data_a[i]))
    new_data_a[i] = temp


#######################################################################################

# Dictionary to store total time results for each algorithm in design b
data_b = {}
counter_b = 0

# Loop through each file in design_b
for file_name in design_b:
    with open(file_name, 'r') as file:
        # Extract algorithm name from file name
        algorithm_name = re.search(r'_subscriber_(\w+)', file_name).group(1)
        total_time_b= []
        
        # Read all this lines of the file
        lines = file.readlines()
        #print(len(lines))
        for line in lines:
            # Extract values using regular expression
            match = re.search(r'Total time result: (\d+\.\d+) seconds', line)
            if match:
                result = float(match.group(1))
                if result < upper_bound:
                    total_time_b.append(result)
                    counter_b += 1
        print(counter_b, "number of elements in", algorithm_name, "in design B")
        counter_b = 0


        # Store result in the dictionary with algorithm as key
        data_b[algorithm_name] = total_time_b


# fetch the names of the algorithms
algorithm_names = list(data_a.keys())


# Create data for design b
new_data_b = {}
for i in data_b:
    temp = []
    for j in range(0, element_number):
        temp.append(data_b[i][j])
    print(len(data_b[i]))
    new_data_b[i] = temp
    # Define the width of the bars
width = 0.35

# Plotting
plt.figure(figsize=(12, 8))

# Plotting bars for design A
bars_a = plt.bar(np.arange(len(algorithm_names)), [np.median(new_data_a[algorithm]) for algorithm in algorithm_names], width, label='Design A')

# Plotting bars for design B
bars_b = plt.bar(np.arange(len(algorithm_names)) + width, [np.median(new_data_b[algorithm]) for algorithm in algorithm_names], width, label='Design B')

# Scatter individual data points for design A
for i, algorithm in enumerate(algorithm_names):
    plt.scatter([i] * len(new_data_a[algorithm]), new_data_a[algorithm], color='blue', s=10, alpha=0.5)

# Scatter individual data points for design B
for i, algorithm in enumerate(algorithm_names):
    plt.scatter([i + width] * len(new_data_b[algorithm]), new_data_b[algorithm], color='orange', s=10, alpha=0.5)

# Plot box plots for design A (lower quartile, median, and upper quartile)
plt.boxplot([new_data_a[algorithm] for algorithm in algorithm_names], positions=np.arange(len(algorithm_names)), widths=0.3, showfliers=False)

# Plot box plots for design B (lower quartile, median, and upper quartile)
plt.boxplot([new_data_b[algorithm] for algorithm in algorithm_names], positions=np.arange(len(algorithm_names)) + width, widths=0.3, showfliers=False)

# Plotting differences as line plots on top of the bars
for i, algorithm in enumerate(algorithm_names):
    plt.plot([i, i + width], [np.median(new_data_a[algorithm]), np.median(new_data_b[algorithm])], color='black', linewidth=2)

plt.xlabel('Algorithms')
plt.ylabel('Time (seconds)')
plt.title('Difference between Design A and Design B with Data Point Overlap and Quartiles')
plt.xticks(np.arange(len(algorithm_names)) + width / 2, algorithm_names, rotation='vertical')
plt.legend()
plt.tight_layout()
plt.show()



'''# Calculate the differences between design A and design B for each algorithm
differences = {}
for algorithm in algorithm_names:
    differences[algorithm] = [a - b for a, b in zip(new_data_a[algorithm], new_data_b[algorithm])]

# Plotting
plt.figure(figsize=(10, 6))
width = 0.35  # Width of the bars

# Plotting bars for design A
bars_a = plt.bar(np.arange(len(algorithm_names)), [np.mean(new_data_a[algorithm]) for algorithm in algorithm_names], width, label='Design A')

# Plotting bars for design B
bars_b = plt.bar(np.arange(len(algorithm_names)) + width, [np.mean(new_data_b[algorithm]) for algorithm in algorithm_names], width, label='Design B')

# Plotting differences as line plots on top of the bars
for i, algorithm in enumerate(algorithm_names):
    plt.plot([i, i + width], [np.mean(new_data_a[algorithm]), np.mean(new_data_b[algorithm])], color='black', linewidth=2)

plt.xlabel('Algorithms')
plt.ylabel('Average Time (seconds)')
plt.title('Difference between Design A and Design B for Each Algorithm')
plt.xticks(np.arange(len(algorithm_names)) + width / 2, algorithm_names, rotation='vertical')
plt.legend()
plt.tight_layout()
plt.show()'''
