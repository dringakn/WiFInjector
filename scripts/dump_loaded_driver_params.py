#!/usr/bin/env python3
import os


# Define the path to the module parameters directory
module_params_dir = "/sys/module/8188eu/parameters"

# Define the path to the configuration file you want to create
config_file_path = "/etc/modprobe.d/8188eu.conf"

# Create an empty dictionary to store parameter name-value pairs
param_values = {}
replacement_dict = {
    b'0': '0',
    b'1': '1',
    b'255': '255',
    b'\xff\xff': 'DE',
    b'(null)':'0',
    # b'': '0',
}

# List all files in the module parameters directory
param_files = os.listdir(module_params_dir)

# Read the values of each parameter and store them in the dictionary
for param_file in param_files:
    param_name = param_file
    param_file_path = os.path.join(module_params_dir, param_file)

    # Read the binary data from the parameter file
    with open(param_file_path, "rb") as file:
        param_value = file.read().strip()

    if param_name == 'rtw_rx_ampdu_sz_limit_3ss':
        print(f"{param_name}={param_value}\n")

    # Check if the binary value needs replacement, and replace it if necessary
    if param_value == b'':
        print(f"skipping {param_name}={param_value}")
        continue
    elif param_value in replacement_dict:
        param_value = replacement_dict[param_value]
    elif param_value.isascii():
        param_value = param_value.decode('utf-8', 'ignore')
    elif param_value.isdigit():
        param_value = str(param_value)

    # Store the parameter name and binary value in the dictionary
    param_values[param_name] = param_value

# Create the configuration file with the parameter name-binary value pairs
with open(config_file_path, "wb") as config_file:
    for param_name, param_value in param_values.items():
        # Write each parameter as an "options" line in the config file
        config_file.write(f"options 8188eu {param_name}={param_value}\n".encode('utf-8'))

print(f"Configuration file '{config_file_path}' created with module parameters.")
