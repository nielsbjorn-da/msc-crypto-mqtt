# Initialize dictionaries to store data for each category
instructions_retired_data = {}
cycles_elapsed_data = {}
peak_memory_footprint_data = {}

# Read data from a file or you can replace this with your data source
with open("results.txt", "r") as file:
    lines = file.readlines()

# Iterate through the lines and group data by name and type
current_name = ""
current_type = ""
for line in lines:
    if line.strip():
        parts = line.split()
        if len(parts) == 2:
            current_name, current_type = parts[0], parts[1]
        else:
            value = int(parts[0])
            category = parts[1]

            if category == "instructions":
                instructions_retired_data.setdefault((current_name, current_type), []).append(value)
            elif category == "cycles":
                cycles_elapsed_data.setdefault((current_name, current_type), []).append(value)
            elif category == "peak":
                peak_memory_footprint_data.setdefault((current_name, current_type), []).append(value)

# Write the grouped data to separate files
def write_data_to_file(data, filename):
    with open(filename, "w") as file:
        for (name, type), values in data.items():
            file.write(f"{name} {type}\n")
            for value in values:
                file.write(f"{value}\n")

write_data_to_file(instructions_retired_data, "Instructions_retired.txt")
write_data_to_file(cycles_elapsed_data, "Cycles_elapsed.txt")
write_data_to_file(peak_memory_footprint_data, "Peak_memory_footprint.txt")
