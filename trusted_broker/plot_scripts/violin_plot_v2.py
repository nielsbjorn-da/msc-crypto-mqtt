import re
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd

path_design_b = '../Design_A/mosquitto_code/mosquitto/client/testtesttest/' 
path_design_a = '../Design_A/mosquitto_code/mosquitto/client/lan_test/'
path_design_b = '../Design_A/mosquitto_code/mosquitto/client/lan_test/' 

path_d2_f512 = "lan_data/lenovo_design_tests/d2_f512/"

path_d3_d5_f1024 = "lan_data/lenovo_design_tests/d3_d5_f1024/"

subscriber_a = "time_results_subscriber_a.txt"
subscriber_b = "time_results_subscriber_b.txt"
subscriber_b_avx2 = "time_results_subscriber_b_avx2.txt"

# List of file names
design_a = [
    path_d2_f512 + subscriber_a,
    path_d3_d5_f1024 + subscriber_a
]

design_b = [
    path_d2_f512 + subscriber_b_avx2,
    path_d3_d5_f1024 + subscriber_b_avx2
]

element_number = 1000
upper_bound = 150000

# Dictionary to store total time results for each algorithm in design a
data_a = {}

# Loop through each file in design_b
for file_name in design_a:
    with open(file_name, 'r') as file:
        
        # Read all this lines of the file
        lines = file.readlines()
        #print(len(lines))
        for i in range(len(lines)):
            line = lines[i]
            if "Total time" in line:
                algorithm_name = line.split()[0]
                # Extract values using regular expression
                time = int(line.split()[-3])
                if lines[i+1] and "Latency" in lines[i+1]:
                    
                    latency = int(lines[i+1].split()[-3])
                    if latency > 80000:
                        
                        print("skipped a, latency", algorithm_name, time, latency)
                        continue
                if (time < upper_bound):
                    if algorithm_name in data_a:
                        data_a[algorithm_name].append(time)
                    else:
                        data_a[algorithm_name] = [time]


#######################################################################################

# Dictionary to store total time results for each algorithm in design b
data_b = {}

# Loop through each file in design_b
for file_name in design_b:
    with open(file_name, 'r') as file:
        
        # Read all this lines of the file
        lines = file.readlines()
        #print(len(lines))
        for i in range(len(lines)):
            line = lines[i]
            if "Total time" in line:
                algorithm_name = line.split()[0]
                # Extract values using regular expression
                time = int(line.split()[-3])
                if lines[i+1] and "Latency" in lines[i+1]:
                    
                    latency = int(lines[i+1].split()[-3])
                    
                    if latency > 80000:
                        print("skipped b, latency", algorithm_name, time, latency)
                        continue
                if (time < upper_bound):
                    if algorithm_name in data_b:
                        data_b[algorithm_name].append(time)
                    else:
                        data_b[algorithm_name] = [time]
# Create a list of algorithm names and corresponding total times
algorithm_names = sorted(list(data_a.keys()))

new_data_a = {}
length_a = len(min(data_a.values(), key=len))
print("len ", length_a)
for key, value in data_a.items():
    updated_list = [num / 1000. for num in value][:length_a]
    new_data_a[key] = updated_list

# Create data for dataframe for design b
new_data_b = {}

length_b = len(min(data_b.values(), key=len))
for key, value in data_b.items():
    updated_list = [num / 1000. for num in value][:length_b]
    new_data_b[key] = updated_list

# Convert the dictionary to a DataFrame
print("data points a ", length_a)
print("data points b", length_b)
df_a = pd.DataFrame(new_data_a)
df_b = pd.DataFrame(new_data_b)

# Print the DataFrame
print("------------------------------------------------------------------------------------------------------------")

# Concatenate the DataFrames along the rows
combined_df = pd.concat([df_a, df_b], keys=['Unmodified broker', 'Modified broker'])

# Reshape the DataFrame for plotting
combined_df = combined_df.reset_index().melt(id_vars=['level_0'], value_vars=algorithm_names,
                                             var_name='Variable', value_name='Value')


# Set style and color palettelevel_0'
sns.set(style="whitegrid")
sns.set_palette(["tab:blue", "tab:orange"])  # Set the color palette to blue and orange


# Create a violin plot with variance (inner='stick')
plt.figure(figsize=(10, 6))
sns.violinplot(x='Variable', y='Value', data=combined_df, hue='level_0', split=True)
#sns.violinplot(data=df_a)
plt.ylabel("Time (ms)", fontsize=10)
plt.xlabel("Digital signature", fontsize=10)
plt.title("Distribution of MQTT PUBLISH times for trusted broker architectures", fontsize=14)
plt.xticks(rotation=45)
plt.yticks(fontsize=12)
plt.grid(axis='y')
plt.legend(title="")
plt.tight_layout()
plt.show()
