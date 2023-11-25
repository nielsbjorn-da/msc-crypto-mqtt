import re
import numpy as np
import matplotlib.pyplot as plt

# List of file names
path_design_a = '../Design_A/mosquitto_code/mosquitto/client/test_results/Iteration_1/'

# List of file names
file_names = [
    path_design_a + "time_results_subscriber_d2.txt",
    path_design_a + "time_results_subscriber_d3.txt",
    path_design_a + "time_results_subscriber_d5.txt",
    path_design_a + "time_results_subscriber_f512.txt",
    path_design_a + "time_results_subscriber_f1024.txt"
]

# List of file names
file_names2 = [
    path_design_a + "time_results_publisher_d2.txt",
    path_design_a + "time_results_publisher_d3.txt",
    path_design_a + "time_results_publisher_d5.txt",
    path_design_a + "time_results_publisher_f512.txt",
    path_design_a + "time_results_publisher_f1024.txt"
]

path_design_b = '../Design_B/mosquitto_code/mosquitto/client/test_results/Iteration_1/' 

file_names3 = [
    path_design_b + "time_results_subscriber_d2.txt",
    path_design_b + "time_results_subscriber_d3.txt",
    path_design_b + "time_results_subscriber_d5.txt",
    path_design_b + "time_results_subscriber_f512.txt",
    path_design_b + "time_results_subscriber_f1024.txt"
]

file_names4 = [
    path_design_b + "time_results_publisher_d2.txt",
    path_design_b + "time_results_publisher_d3.txt",
    path_design_b + "time_results_publisher_d5.txt",
    path_design_b + "time_results_publisher_f512.txt",
    path_design_b + "time_results_publisher_f1024.txt"
]


# Dictionary to store average time results for each algorithm
data = {}
data2 = {}
counter = 0

# Loop through each file
for file_name in file_names:
    # Extract algorithm name from file name
    algorithm_name = re.search(r'_subscriber_(\w+)', file_name).group(1)
    with open(file_name, 'r') as file:
        lines = file.readlines()
        extracting_payload = []
        decode_sig = []
        decode_pk = []
        verification_result = []
        total_times = []
        concat_times = []
        for line in lines:
            # Extract values using regular expression
            match1 = re.search(r'Extracting payload from cJSON execution time: (\d+) micro seconds.', line)
            match2 = re.search(r'Decode sig (Dilithium|Dilithium2|Dilithium3|Dilithium5|Falcon-512|Falcon-1024|Falcon) execution time: (\d+) micro seconds', line)
            match3 = re.search(r'Decode PK (Dilithium|Falcon) execution time: (\d+) micro seconds.', line)
            match4 = re.search(r'Verification (Dilithium|Falcon) execution time: (\d+) micro seconds', line)
            match5 = re.search(r'Total time result: (\d+) micro seconds', line)
            match6 = re.search(r"Generating concat message execution time: (\d+) micro seconds.", line)
            
            if match1:
                result = float(match1.group(1))
                extracting_payload.append(result)
            if match2:
                result = float(match2.group(2))
                decode_sig.append(result)
            if match3:
                result = float(match3.group(2))
                decode_pk.append(result)
            if match4:
                result = float(match4.group(2))
                verification_result.append(result)
            if match5:
                result = float(match5.group(1))
                total_times.append(result)
            if match6:
                result = float(match6.group(1))
                concat_times.append(result)

        # Calculate average time result for the current algorithm
        #print("\npayload", extracting_payload)
        #print("\nsig", decode_sig)
        #print("\npk", decode_pk)
        #print("\nver", verification_result)
        #print(total_times)
        #print("Concat:", concat_times)
        total_time_minus_subscriber_work = [total_times[i] - concat_times[i] - verification_result[i] - extracting_payload[i] - decode_pk[i] - decode_sig[i] for i in range(min(len(decode_sig), len(decode_pk), len(extracting_payload), len(verification_result), len(total_times)))]

        # Store average time result in the dictionary
        data[algorithm_name  + "-total_sub"] = total_time_minus_subscriber_work


# Loop through each file
for file_name in file_names2:
    with open(file_name, 'r') as file:
        lines = file.readlines()
        gen_cjson = []
        sign_msg = []
        encode_sig = []
        init_time = []
        encode_pk = []
        concat_times = []

        for line in lines:
            # Extract values using regular expression
            match1 = re.search(r'Generating cJSON execution time: (\d+) micro seconds.', line)
            match2 = re.search(r'Encode signature (Dilithium2|Dilithium3|Dilithium5|Falcon-512|Falcon-1024) execution time: (\d+) micro seconds.', line)
            match3 = re.search(r'Signing message (Dilithium2|Dilithium3|Dilithium5|Falcon-512|Falcon-1024) execution time: (\d+) micro seconds.', line)
#            match4 = re.search(r'Initialization time: (\d+) micro seconds.', line)
            match5 = re.search(r'Encode PK (Dilithium2|Dilithium3|Dilithium5|Falcon-512|Falcon-1024) execution time: (\d+) micro seconds.', line)
            match6 = re.search(r'Generating message concat execution time: (\d+) micro seconds.', line)
            if match1:
                result = float(match1.group(1))
                gen_cjson.append(result)
            if match2:
                result = float(match2.group(2))
                encode_sig.append(result)
            if match3:
                result = float(match3.group(2))
                sign_msg.append(result)
            if match4:
                result = float(match4.group(1))
                init_time.append(result)
            if match5:
                result = float(match5.group(2))
                encode_pk.append(result)
            if match6:
                result = float(match6.group(1))
                concat_times.append(result)
        
        # Extract algorithm name from file name
        algorithm_name = re.search(r'_publisher_(\w+)', file_name).group(1)
        total_times = data[algorithm_name  + "-total_sub"]
        total_time_minus_publisher_work = [total_times[i] - gen_cjson[i] - concat_times[i]*100 - encode_sig[i] - sign_msg[i] - encode_pk[i] for i in range(min(len(encode_sig), len(encode_pk), len(sign_msg), len(gen_cjson), len(total_times)))]
        data[algorithm_name] = total_time_minus_publisher_work

# Loop through each file
for file_name in file_names3:
    # Extract algorithm name from file name
    algorithm_name = re.search(r'_subscriber_(\w+)', file_name).group(1)
    with open(file_name, 'r') as file:
        lines = file.readlines()
        extracting_payload = []
        decode_sig = []
        verification_result = []
        total_times = []
        concat_times = []
        for line in lines:
            # Extract values using regular expression
            match1 = re.search(r'Extracting payload from cJSON execution time: (\d+) micro seconds.', line)
            match2 = re.search(r'Decode sig (Dilithium|Dilithium2|Dilithium3|Dilithium5|Falcon-512|Falcon-1024|Falcon) execution time: (\d+) micro seconds', line)
            match4 = re.search(r'Verification (Dilithium|Falcon|Dilithium2|Dilithium3|Dilithium5|Falcon-512|Falcon-1024) execution time: (\d+) micro seconds', line)
            match5 = re.search(r'Total time result: (\d+) micro seconds', line)
            match6 = re.search(r"Generating concat message execution time: (\d+) micro seconds.", line)
            if match1:
                result = float(match1.group(1))
                extracting_payload.append(result)
            if match2:
                result = float(match2.group(2))
                decode_sig.append(result)
            if match4:
                result = float(match4.group(2))
                verification_result.append(result)
            if match5:
                result = float(match5.group(1))
                total_times.append(result)
            if match6:
                result = float(match6.group(1))
                concat_times.append(result)

        # Calculate average time result for the current algorithm
        #print("\npayload", extracting_payload)
        #print("\nsig", decode_sig)
        #print("\npk", decode_pk)
        #print("\nver", verification_result)
        total_time_minus_subscriber_work = [total_times[i] - concat_times[i] - verification_result[i] - extracting_payload[i] - decode_pk[i] - decode_sig[i] for i in range(min(len(decode_sig), len(decode_pk), len(extracting_payload), len(verification_result), len(total_times)))]
        #print(algorithm_name)
        #print(total_time_minus_subscriber_work)
        # Store average time result in the dictionary
        data2[algorithm_name  + "-total_sub"] = total_time_minus_subscriber_work

for file_name in file_names4:
    with open(file_name, 'r') as file:
        lines = file.readlines()
        gen_cjson = []
        sign_msg = []
        encode_sig = []
        init_time = []
        #encode_pk = []
        concat_times = []

        for line in lines:
            # Extract values using regular expression
            match1 = re.search(r'Generating cJSON execution time: (\d+) micro seconds.', line)
            match2 = re.search(r'Encode signature (Dilithium2|Dilithium3|Dilithium5|Falcon-512|Falcon-1024) execution time: (\d+) micro seconds.', line)
            match3 = re.search(r'Signing message (Dilithium2|Dilithium3|Dilithium5|Falcon-512|Falcon-1024) execution time: (\d+) micro seconds.', line)
#            match4 = re.search(r'Initialization time: (\d+) micro seconds.', line)
            #match5 = re.search(r'Encode PK (Dilithium2|Dilithium3|Dilithium5|Falcon-512|Falcon-1024) execution time: (\d+) micro seconds.', line)
            match6 = re.search(r'Generating message concat execution time: (\d+) micro seconds.', line)

            if match1:
                result = float(match1.group(1))
                gen_cjson.append(result)
            if match2:
                result = float(match2.group(2))
                encode_sig.append(result)
            if match3:
                result = float(match3.group(2))
                sign_msg.append(result)
            if match4:
                result = float(match4.group(1))
                init_time.append(result)
            #if match5:
             #   result = float(match5.group(2))
              #  encode_pk.append(result)
            if match6:
                result = float(match6.group(1))
                concat_times.append(result)
        print("\n cjson", gen_cjson)
        print("\n sig", encode_sig)
        print("\n sign", sign_msg)
        #print(counter)
        # Extract algorithm name from file name
        algorithm_name = re.search(r'_publisher_(\w+)', file_name).group(1)
        total_times = data2[algorithm_name  + "-total_sub"]
        print("Total", total_times)
        total_time_minus_publisher_work = [total_times[i] - gen_cjson[i] - concat_times[i] - encode_sig[i] - sign_msg[i] for i in range(min(len(encode_sig), len(sign_msg), len(gen_cjson), len(total_times)))]
        print("titn", total_time_minus_publisher_work)
        data2[algorithm_name] = total_time_minus_publisher_work
#print(data2)
categories = ['Design A', "Design B"]
algorithms = ['d2', 'd3', 'd5', 'f512', 'f1024']  
broker_latency_design_a = [data[key] for key in algorithms]
broker_latency_design_b = [data2[key] for key in algorithms]
print(broker_latency_design_b)
element_number = 350
upper_bound = 90000

filtered_a = [item[:element_number] for item in broker_latency_design_a]
filtered_b = [item[:element_number] for item in broker_latency_design_b]
#for i in range(len(algorithms)):
 #   plt.bar(algorithms[i], np.median(broker_latency_design_a[i]))
width = 0.35

# Plotting
plt.figure(figsize=(12, 8))

# Plotting bars for design A
bars_a = plt.bar(np.arange(len(algorithms)), [np.median(filtered_a[i])/1000. for i in range(len(algorithms))], width, label='Design A - Unmodified Broker')
#print(filtered_b)0
# Plotting bars for design B
bars_b = plt.bar(np.arange(len(algorithms)) + width, [np.median(filtered_b[i])/1000. for i in range(len(algorithms))], width, label='Design B - Modified Broker')

plt.ylabel('Time (ms)')
plt.title('Median Broker Latency')
plt.xticks(np.arange(len(algorithms)) + width / 2, algorithms, rotation='vertical')
plt.legend()
plt.tight_layout()
plt.show()

'''
# Extracting data for each category and algorithm
categories = ['Extract cJSON', 'Decode signature & PK', 'Verification']
algorithms = ['d2', 'd3', 'd5', 'f512', 'f1024']

values = [[data[f'{algorithm}-{category}'] for category in categories] for algorithm in algorithms]
bar_width = 0.15
r = np.arange(len(categories))

for i, algorithm in enumerate(algorithms):
    plt.bar(r + i * bar_width, values[i], width=bar_width, edgecolor='grey', label=f'{algorithm}')

plt.xlabel('Categories')
plt.ylabel('Time')
plt.yscale('log')  # Set y-axis to logarithmic scale
plt.title('Subscriber 32-bit - Design A Local')
plt.xticks(r + bar_width * 2, categories)
plt.legend(algorithms)

#plt.show()
'''