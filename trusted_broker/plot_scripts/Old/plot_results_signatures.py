import matplotlib.pyplot as plt
import numpy as np

# Define dictionaries to store data for each function (keygen, sign, verify)
keygen_data = {}
sign_data = {}
verify_data = {}

# Open and read the data file
with open("Cycles_elapsed.txt", "r") as file:
    lines = file.readlines()

# Process the lines and populate the data dictionaries
current_algorithm = None
current_function = None

for line in lines:
    line = line.strip()
    if line.isdigit():
        if current_function == "0":
            if current_algorithm in keygen_data:
                keygen_data[current_algorithm].append(int(line))
            else:
                keygen_data[current_algorithm] = [int(line)]
        elif current_function == "1":
            if current_algorithm in sign_data:
                sign_data[current_algorithm].append(int(line))
            else:
                sign_data[current_algorithm] = [int(line)]
        elif current_function == "2":
            if current_algorithm in verify_data:
                verify_data[current_algorithm].append(int(line))
            else:
                verify_data[current_algorithm] = [int(line)]
    else:
        current_algorithm, current_function = line.split()

# Calculate the average values for each algorithm and function
keygen_averages = {algorithm: np.mean(values) for algorithm, values in keygen_data.items()}
sign_averages = {algorithm: np.mean(values) for algorithm, values in sign_data.items()}
verify_averages = {algorithm: np.mean(values) for algorithm, values in verify_data.items()}

# Extract algorithm names and their corresponding average data
algorithms = list(keygen_averages.keys())
keygen_results = list(keygen_averages.values())
sign_results = list(sign_averages.values())
verify_results = list(verify_averages.values())

# Number of algorithms and functions
num_algorithms = len(algorithms)
num_functions = 3  # Keygen, Sign, Verify

# Set the width of the bars
bar_width = 0.2
group_spacing = 0

# Create an array of positions for the bars
x = np.arange(num_algorithms)

# Create the bar plot
plt.bar(x - bar_width - group_spacing, keygen_results, bar_width, label="Keygen")
plt.bar(x, sign_results, bar_width, label="Sign")
plt.bar(x + bar_width + group_spacing, verify_results, bar_width, label="Verify")


# Customize the plot
plt.xlabel("Algorithms")
plt.ylabel("CPU clock cycles 100x M")
plt.title("CPU clock cycles")
plt.xticks(x, algorithms, rotation=45)
#plt.ylim(0, 1111800000)
plt.legend(loc='best', fontsize='small')

# Show the plot
plt.tight_layout()
plt.show()
