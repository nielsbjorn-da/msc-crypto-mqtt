import re
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd

path_design_b = 'Design_B/mosquitto_code/mosquitto/client/test_results_rpi_32_remote/'
path_design_a = '../../../../../Design_A/mosquitto_code/mosquitto/client/test_results_rpi_32_remote/'


def convert_sym_to_name(sym):
    if sym == 'f512':
        return'Falcon-512'
    if sym == 'f1024':
        return'Falcon-1024'
    if sym == 'd2':
        return'Dilithium2'
    if sym == 'd3':
        return'Dilithium3'
    if sym == 'd5':
        return 'Dilithium5'


# List of file names
design_a = [
    path_design_b + path_design_a + "time_results_subscriber_d2_remote.txt",
    path_design_b + path_design_a + "time_results_subscriber_d3_remote.txt",
    path_design_b + path_design_a + "time_results_subscriber_d5_remote.txt",
    path_design_b + path_design_a + "time_results_subscriber_f512_remote.txt",
    path_design_b + path_design_a + "time_results_subscriber_f1024_remote.txt"
]

design_b = [
    path_design_b + "time_results_subscriber_d2_remote.txt",
    path_design_b + "time_results_subscriber_d3_remote.txt",
    path_design_b + "time_results_subscriber_d5_remote.txt",
    path_design_b + "time_results_subscriber_f512_remote.txt",
    path_design_b + "time_results_subscriber_f1024_remote.txt"
]


# Dictionary to store total time results for each algorithm in design a
data_a = {}

# Loop through each file in design_b
for file_name in design_a:
    with open(file_name, 'r') as file:
        # Extract algorithm name from file name
        algorithm_name = re.search(r'_subscriber_(\w+)_remote', file_name).group(1)
        total_time_a = []
        
        # Read all this lines of the file
        lines = file.readlines()
        #print(len(lines))
        for line in lines:
            # Extract values using regular expression
            match = re.search(r'Total time result: (\d+\.\d+) seconds', line)
            if match:
                result = float(match.group(1))
                if result < 0.0004:
                    total_time_a.append(result)


        # Store result in the dictionary with algorithm as key
        data_a[convert_sym_to_name(algorithm_name)] = total_time_a
#print(data)

#######################################################################################

# Dictionary to store total time results for each algorithm in design b
data_b = {}

# Loop through each file in design_b
for file_name in design_b:
    with open(file_name, 'r') as file:
        # Extract algorithm name from file name
        algorithm_name = re.search(r'_subscriber_(\w+)_remote', file_name).group(1)
        total_time_b= []
        
        # Read all this lines of the file
        lines = file.readlines()
        #print(len(lines))
        for line in lines:
            # Extract values using regular expression
            match = re.search(r'Total time result: (\d+\.\d+) seconds', line)
            if match:
                result = float(match.group(1))
                if result < 0.0004:
                    total_time_b.append(result)


        # Store result in the dictionary with algorithm as key
        data_b[convert_sym_to_name(algorithm_name)] = total_time_b
#print(data)

# Create a list of algorithm names and corresponding total times
algorithm_names = list(data_a.keys())

new_data_a = {}
for i in data_a:
    temp = []
    for j in range(0, 38):
        temp.append(data_a[i][j])
    print(len(data_a[i]))
    new_data_a[i] = temp

# Create data for dataframe for design b
new_data_b = {}
for i in data_b:
    temp = []
    for j in range(0, 38):
        temp.append(data_b[i][j])
    print(len(data_b[i]))
    new_data_b[i] = temp

# Convert the dictionary to a DataFrame
df_a = pd.DataFrame(new_data_a)
df_b = pd.DataFrame(new_data_b)

# Print the DataFrame
print("------------------------------------------------------------------------------------------------------------")

# Concatenate the DataFrames along the rows
combined_df = pd.concat([df_a, df_b], keys=['Design A', 'Design B'])

# Reshape the DataFrame for plotting
combined_df = combined_df.reset_index().melt(id_vars=['level_0'], value_vars=algorithm_names,
                                             var_name='Variable', value_name='Value')

print(combined_df)


# Set style and color palettelevel_0'
sns.set(style="whitegrid")
sns.set_palette("Set2")

# Create a violin plot with variance (inner='stick')
plt.figure(figsize=(10, 6))
sns.violinplot(x='Variable', y='Value', data=combined_df, hue='level_0', split=True)
#sns.violinplot(data=df_a)
plt.ylabel("Total Time (seconds)", fontsize=14)
plt.title("Round-trip time for Post-Quantum signature algorithms", fontsize=16)
plt.xticks(rotation=45)
plt.yticks(fontsize=12)
plt.grid(axis='y')
plt.legend(title="")
plt.tight_layout()
plt.show()
