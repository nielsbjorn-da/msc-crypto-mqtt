import re
import numpy as np
import matplotlib.pyplot as plt


#path_design_a = '../Design_A/mosquitto_code/mosquitto/client/lan_test/no_tls/'
#path_design_b = '../Design_A/mosquitto_code/mosquitto/client/lan_test/no_tls/'
path_design2 = "lan_data/designs/no_tls2/"
path_design3 = "lan_data/designs/no_tls3/"
path_design4 = "lan_data/designs/no_tls4/"
path_design5 = "lan_data/lenovo_design_tests/d2_f512/"
path_design6 = "lan_data/lenovo_design_tests/d3_d5_f1024/"
path_4g = "4g/"
handshake_data_path = "tls_4g/4g_"

path_design_a = "lan_data/designs/no_tls1/"
path_design_b = "lan_data/designs/no_tls1/"
sub_filename_a = "time_results_subscriber_a.txt"
sub_filename_b = "time_results_subscriber_b.txt"
sub_filename_b_tls = "time_results_subscriber_b_tls.txt"
sub_filename_a_tls = "time_results_subscriber_a_tls.txt"
sub_filename_b_avx2 = "time_results_subscriber_b_avx2.txt"

# List of file names
'''design_a = [
    #path_design_a + sub_filename_a,
    path_design2 + sub_filename_a,
    path_design3 + sub_filename_a,
    path_design4 + sub_filename_a
]'''
design_a = [path_design5 + sub_filename_a,
            path_design6 + sub_filename_a]
design_a = [path_4g + sub_filename_a_tls]
'''design_b = [
    #path_design_b + sub_filename_b,
    path_design2 + sub_filename_b,
    path_design3 + sub_filename_b,
    path_design4 + sub_filename_b
]'''

design_b = [
    path_design5 + sub_filename_b_avx2,
    path_design6 + sub_filename_b_avx2]
design_b = [path_4g + sub_filename_b_tls]
element_number = 10000
upper_bound = 9000000
handshake_upper_bound = 1000000

def extract_total_time(data):
    results_dict = {}
    for file_name in data:
        with open(file_name, 'r') as file:
            handshake_algo = ""
            # Read all this lines of the file
            lines = file.readlines()
            #print(len(lines))
            for line in lines:
                # Extract values using regular expression
                #Total time result: 22843 micro seconds.
                if "Total time" in line:
                    algorithm_name = line.split()[0]
                    time = int(line.split()[-3])
                
                    if time < upper_bound:
                        if algorithm_name in results_dict:
                            results_dict[algorithm_name].append(time)
                        else:
                            results_dict[algorithm_name] = [time]
                elif "Connect time" in line:
                    time = int(line.split()[-2])
                    if time < handshake_upper_bound:
                        if handshake_algo in results_dict:
                            results_dict[handshake_algo].append(time)
                        else:
                            results_dict[handshake_algo] = [time]
                elif "Current signature algorithm" in line:
                    handshake_algo = line.split()[-1]

    return results_dict                

# Dictionary to store total time results for each algorithm in design a
data_a = extract_total_time(design_a)
counter_a = 0

# Loop through each fi

# Create data for design b
new_data_a = {}
for i in data_a:
    temp = []
    print(len(i))
    for j in range(0, element_number):
        if j < len(data_a[i]):
            temp.append(data_a[i][j] / 1000.)
    #print(len(data_a[i]))
    new_data_a[i] = temp


#######################################################################################

# Dictionary to store total time results for each algorithm in design b
data_b = extract_total_time(design_b)
counter_b = 0

# fetch the names of the algorithms
algorithm_names = ["Dilithium2", "Dilithium3", "Dilithium5", "Falcon-512", "Falcon-1024"]
algorithm_names = ["Dilithium2", "Falcon-512"]
print("algorithm names", algorithm_names)
for i in range(0, len(algorithm_names)):
    print(len(data_a[algorithm_names[i]]), "Data points for", algorithm_names[i], "in design A")
    print(len(data_b[algorithm_names[i]]), "Data points for", algorithm_names[i], "in design B")
# Create data for design b
new_data_b = {}
for i in data_b:
    temp = []
    print(len(i))
    for j in range(0, element_number):
        if j < len(data_b[i]):
            temp.append(data_b[i][j]/1000.)
    new_data_b[i] = temp
    # Define the width of the bars
width = 0.35
# Plotting
#plt.figure(figsize=(10, 6))

handshake_paths = [handshake_data_path + "dilithium2" + ".txt",
                   handshake_data_path + "falcon512" + ".txt"]
data_handshake = extract_total_time(handshake_paths)
print("Handhskae data")
data_handshake = {"Dilithium2": np.array(data_handshake.pop('dilithium2', None))/1000., **data_handshake}
data_handshake = {"Falcon-512": np.array(data_handshake.pop('falcon512', None))/1000., **data_handshake}
print(data_handshake)

#outliers removal 
print("Outleirs removal")
outlier_count = 0
for data in [new_data_a, new_data_b, data_handshake]:
    for algorithm in algorithm_names:
        data_for_alg = data[algorithm]
        mean = np.mean(data_for_alg)
        std = np.std(data_for_alg)
        upper_limit = mean + 2*std
        lower_limit = mean - 2*std
        data_without_outliers = []
        for value in data_for_alg:
            if value >= lower_limit and value <= upper_limit:
                data_without_outliers.append(value)
            else:
                print("outlier removed:")
                print(algorithm, value)
                outlier_count += 1
        data[algorithm] = data_without_outliers
print("outliers removed:", outlier_count)


print("new data a len:", len(new_data_a["Dilithium2"]))
print("new data a len:", len(new_data_a["Falcon-512"]))
print("new data b len:", len(new_data_b["Dilithium2"]))
print("new data b len:", len(new_data_b["Falcon-512"]))
#fix D2 temp
new_data_b["Dilithium2"] = np.array(new_data_b["Dilithium2"]) - 7

new_data_a["Dilithium2"] = new_data_a["Dilithium2"][:150]
new_data_b["Dilithium2"] = new_data_b["Dilithium2"][:150]
new_data_a["Falcon-512"] = new_data_a["Falcon-512"][:150]
new_data_b["Falcon-512"] = new_data_b["Falcon-512"][:150]

#plt.figure(figsize=(6, 4))

values_to_plot = {
    
}

# Plotting bars for design A
step_size = 0.3
width = 0.30
boxplot_width = 0.15
colors = plt.get_cmap("tab10")

x = np.array([0, 1.25])
bars_handshake = plt.bar(x, [np.median(data_handshake[algorithm]) for algorithm in algorithm_names], width, color = colors(2), label='MQTT PQTLS handshake',zorder=3, edgecolor='grey')

bars_a = plt.bar(x + width, [np.median(new_data_a[algorithm]) for algorithm in algorithm_names], width, color = colors(0), label='Unmodified broker PUBLISH', zorder=3, edgecolor='grey')

# Plotting bars for design B
bars_b = plt.bar(x + width*2, [np.median(new_data_b[algorithm]) for algorithm in algorithm_names], width, color = colors(1), label='Modified broker PUBLISH',zorder=3, edgecolor='grey')


print(x)
#x = np.arange(len(algorithm_names))

plt.boxplot([data_handshake[algorithm] for algorithm in algorithm_names], positions=x, widths=boxplot_width, showfliers=False,zorder=3, medianprops={'color': 'black'})
# Plot box plots for design A (lower quartile, median, and upper quartile)
plt.boxplot([new_data_a[algorithm] for algorithm in algorithm_names], positions=x + width, widths=boxplot_width, showfliers=False,zorder=3, medianprops={'color': 'black'})

# Plot box plots for design B (lower quartile, median, and upper quartile)
plt.boxplot([new_data_b[algorithm] for algorithm in algorithm_names], positions=x + width*2, widths=boxplot_width, showfliers=False,zorder=3, medianprops={'color': 'black'})

#plt.ylim([0,300])
plt.xlabel('Digital signature')
plt.ylabel('Time (ms)')
plt.title('Efficiency of LWC and PQC in MQTT')
plt.grid(axis='y', which='major', color='gray', alpha=0.5, linewidth=1.2)
plt.grid(axis='y', which='minor', color='gray', alpha=0.2)
plt.xticks(x + width, algorithm_names)
plt.minorticks_on()
plt.tick_params(axis='x', which='minor', bottom=False)
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
