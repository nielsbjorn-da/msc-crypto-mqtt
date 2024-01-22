import numpy as np
import matplotlib.pyplot as plt

path_design_a = '../Design_A/mosquitto_code/mosquitto/client/lan_test1/no_tls/d2_f512/'
path_design_b = '../Design_A/mosquitto_code/mosquitto/client/lan_test1/no_tls/d2_f512/'
path_ascon128 = "lan_data/lenovo_design_tests/ascon128/"
path_ascon128a = "lan_data/lenovo_design_tests/ascon128a/"
path_aes = "lan_data/lenovo_design_tests/aes128/"
path_ascon80pq = "lan_data/lenovo_design_tests/ascon80pq/"
path_d3_d5_f1024 = 'lan_data/lenovo_design_tests/d3_d5_f1024/'
path_d2_f512 = "lan_data/lenovo_design_tests/d2_f512/"

path_design_a = "lan_data/designs/no_tls"
path_design_b = "lan_data/designs/no_tls"

sub_filename_a = "time_results_subscriber_a.txt"
sub_filename_b = "time_results_subscriber_b.txt"
sub_filename_b_avx2 = "time_results_subscriber_b_avx2.txt"
sub_filename_a_tls = "time_results_subscriber_a_tls.txt"
sub_filename_b_tls = "time_results_subscriber_b_tls.txt" 

tls_plot = True

#design_a_data = [path_design_a + "1/" + sub_filename_a, path_design_a + "2/" + sub_filename_a, 
  #                  path_design_a + "3/" + sub_filename_a, path_design_a + "4/" + sub_filename_a]
design_a_data = [
    path_d2_f512 + sub_filename_a,
    path_d3_d5_f1024 + sub_filename_a
]
#design_b_data =[path_design_b + "1/" + sub_filename_b, path_design_b + "2/" + sub_filename_b, 
 #                   path_design_b + "3/" + sub_filename_b, path_design_b + "4/" + sub_filename_b]
design_b_data = [
    path_d2_f512 + sub_filename_b_avx2,
    path_d3_d5_f1024 + sub_filename_b_avx2
]


design_a_aes_data = [path_aes + sub_filename_a_tls]
design_b_aes_data = [path_aes + sub_filename_b_tls]
design_a_ascon128_data = [path_ascon128 + sub_filename_a_tls]
design_b_ascon128_data = [path_ascon128 + sub_filename_b_tls]
design_a_ascon128a_data = [path_ascon128a + sub_filename_a_tls]
design_b_ascon128a_data = [path_ascon128a + sub_filename_b_tls]
design_a_ascon80pq_data = [path_ascon80pq + sub_filename_a_tls]#, path_ascon80pq + "2/" +  sub_filename_a_tls]
design_b_ascon80pq_data = [path_ascon80pq +  sub_filename_b_tls]#, path_ascon80pq + "2/" +  sub_filename_b_tls]


upper_bound = 60000

def extract_latency(data_list):
    results_dict = {}
    for f in data_list:
        with open(f, 'r') as file:        
            # Read all this lines of the file
            lines = file.readlines()
            #print(len(lines))
            for i in range(len(lines)):
                line = lines[i]
                if "Latency" in line:
                    algorithm_name = line.split()[0]
                    # Extract values using regular expression
                    latency = int(line.split()[-3])

                    if (latency < upper_bound):
                        if algorithm_name in results_dict:
                            results_dict[algorithm_name].append(latency)
                        else:
                            results_dict[algorithm_name] = [latency]
    return results_dict
    


data_a = extract_latency(design_a_data)

#print(data_a)


data_b = extract_latency(design_b_data)

data_a_aes = extract_latency(design_a_aes_data)
#data_a_aes = {key: [x + 1500 for x in value] for key, value in data_a_aes.items()}
data_b_aes = extract_latency(design_b_aes_data)

#REMEBER TO FIX THE DATA HARDCODING
data_a_ascon128 = extract_latency(design_a_ascon128_data)
#data_a_ascon128 = {key: [x + 1500 for x in value] for key, value in data_a_ascon128.items()}
data_b_ascon128 = extract_latency(design_b_ascon128_data)

data_a_ascon128a = extract_latency(design_a_ascon128a_data)
#data_a_ascon128a = {key: [x + 1500 for x in value] for key, value in data_a_ascon128a.items()}
data_b_ascon128a = extract_latency(design_b_ascon128a_data)

data_a_ascon80pq = extract_latency(design_a_ascon80pq_data)
#data_a_ascon80pq = {key: [x + 1500 for x in value] for key, value in data_a_ascon80pq.items()}
data_b_ascon80pq = extract_latency(design_b_ascon80pq_data)
print("asdasd", data_b_ascon80pq)

dicts = [data_a, data_b, data_a_aes, data_b_aes, data_a_ascon128, data_b_ascon128, data_a_ascon128a, data_b_ascon128a, data_a_ascon80pq, data_b_ascon80pq]


for i in range(len(dicts)):
    d2_avg = np.mean(dicts[i]["Dilithium2"])
    f512_avg = np.mean(dicts[i]["Falcon-512"])
    print("d2 avg", d2_avg)
    print("f512 avg", f512_avg)

    '''d3_avg = np.mean(dicts[i]["Dilithium3"])
    d5_avg = np.mean(dicts[i]["Dilithium5"])
    f1024_avg = np.mean(dicts[i]["Falcon-1024"])
    print("d3 avg", d3_avg)
    print("d5 avg", d5_avg)
    print("f1024 avg", f1024_avg)
    '''
    '''d2_avg = np.median(dicts[i]["Dilithium2"])
    f512_avg = np.median(dicts[i]["Falcon-512"])
    print("d2 med", d2_avg)
    print("f512 med", f512_avg)'''
    print()
algorithms = ["Dilithium2 - TUB", "Dilithium2 - TMB", "Falcon-512 - TUB", "Falcon-512 - TMB"]
print("Algos:", algorithms)
values_to_plot = {
    'No TLS' : (np.median(data_a["Dilithium2"]), np.median(data_b["Dilithium2"]), np.median(data_a["Falcon-512"]), np.median(data_b["Falcon-512"])), 
    'AES-128-GCM' : (np.median(data_a_aes["Dilithium2"]), np.median(data_b_aes["Dilithium2"]), np.median(data_a_aes["Falcon-512"]), np.median(data_b_aes["Falcon-512"])),
    'Ascon-128' : (np.median(data_a_ascon128["Dilithium2"]), np.median(data_b_ascon128["Dilithium2"]), np.median(data_a_ascon128["Falcon-512"]), np.median(data_b_ascon128["Falcon-512"])),
    'Ascon-128a' : (np.median(data_a_ascon128a["Dilithium2"]), np.median(data_b_ascon128a["Dilithium2"]), np.median(data_a_ascon128a["Falcon-512"]), np.median(data_b_ascon128a["Falcon-512"])),
    'Ascon-80pq' : (np.median(data_a_ascon80pq["Dilithium2"]), np.median(data_b_ascon80pq["Dilithium2"]), np.median(data_a_ascon80pq["Falcon-512"]), np.median(data_b_ascon80pq["Falcon-512"]))
}
x = np.arange(len(algorithms))  # the label locations
width = 0.15  # the width of the bars
multiplier = 0

fig, ax = plt.subplots(layout='constrained')
cmap = plt.get_cmap("tab10")
for attribute, measurement in values_to_plot.items():
    offset = width * multiplier
    color = cmap(multiplier+1)
    if multiplier == 0:
        color = plt.get_cmap("tab20c")(17)
    rects = ax.bar(x + offset, np.array(measurement) / 1000., width, label=attribute, color=color, edgecolor="gray", zorder=3)
    print(attribute)
    multiplier += 1

# Add some text for labels, title and custom x-axis tick labels, etc.
ax.yaxis.grid(True, which='major', color='gray', alpha=0.5)

ax.set_ylabel('Time (ms)')
ax.set_ylim([0,5])
ax.set_title('PUBLISH latency with TLS symmetric encryption')
ax.set_xticks(x + width*2, algorithms)
ax.legend()

if tls_plot:
    plt.show()
else:
    plt.clf()

#latency plot for designs without tls
#path_design_a = '../Design_A/mosquitto_code/mosquitto/client/lan_test/no_tls/'
#path_design_b = '../Design_A/mosquitto_code/mosquitto/client/lan_test/no_tls/'
#design_a_data = [path_design_a + sub_filename_a]
#design_b_data = [path_design_b + sub_filename_b]
#design_a_data.append(path_d3_d5_f1024 + sub_filename_a)
#design_b_data.append(path_d3_d5_f1024 + sub_filename_b)
data_a = extract_latency(design_a_data)
data_b = extract_latency(design_b_data)
print(data_b)
algorithms = ["Dilithium2", "Dilithium3", "Dilithium5", "Falcon-512", "Falcon-1024"]
#outliers removal
outlier_count = 0
for data in [data_a, data_b]:
    for algorithm in algorithms:
        data_for_alg = data[algorithm]
        mean = np.median(data_for_alg)
        std = np.std(data_for_alg)
        upper_limit = mean + 3*std
        lower_limit = mean - 3*std
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
values_to_plot = {
    'Unmodified broker': [np.median(data_a[name]) for name in algorithms],
    'Modified broker': [np.median(data_b[name]) for name in algorithms],
}

x = np.arange(len(algorithms))  # the label locations
width = 0.3  # the width of the bars
multiplier = 0

fig, ax = plt.subplots(layout='constrained')

for attribute, measurement in values_to_plot.items():
    offset = width * multiplier
    rects = ax.bar(x + offset, np.array(measurement)[:] / 1000., width, label=attribute, zorder=3, edgecolor="gray")
    multiplier += 1


# Plot box plots for design A (lower quartile, median, and upper quartile)
#plt.boxplot([np.array(data_a[algorithm])/1000. for algorithm in algorithms], positions=np.arange(len(algorithms)), widths=0.2, showfliers=False,zorder=3, medianprops={'color': 'black'})

# Plot box plots for design B (lower quartile, median, and upper quartile)
#plt.boxplot([np.array(data_b[algorithm])/1000. for algorithm in algorithms], positions=np.arange(len(algorithms)) + width, widths=0.2, showfliers=False,zorder=3, medianprops={'color': 'black'})


# Add some text for labels, title and custom x-axis tick labels, etc.
ax.yaxis.grid(True, which='major', color='gray', alpha=0.5)
ax.set_ylabel('Time (ms)')
ax.set_xlabel("Digital signature")
ax.set_title('MQTT Broker PUBLISH latency for trusted broker designs')
ax.set_xticks(x + width/2, algorithms)
ax.legend()
ax.set_ylim([0,6])
plt.show()