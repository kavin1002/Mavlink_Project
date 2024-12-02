import psutil
import time
import argparse

# Set up command line argument parsing
parser = argparse.ArgumentParser(description='Monitor CPU and memory usage of a specific process.')
parser.add_argument('process_name', type=str, help='Name of the process to monitor (e.g., "uav_udp" or "gcs_udp").')
parser.add_argument('output_file', type=str, help='Output CSV file name')
args = parser.parse_args()

# Function to find the process by name
def find_process_by_name(name):
    for process in psutil.process_iter(['pid', 'name']):
        if process.info['name'] == name:
            return process
    return None

# Find the specified process
process = find_process_by_name(args.process_name)

if not process:
    print(f"Process '{args.process_name}' not found. Exiting.")
    exit()

# Open the output file for writing
with open(args.output_file, 'w') as file:
    # Write the header
    file.write("Time,CPU Usage (%),Memory Usage (MB)\n")

    try:
        # Monitor the process in real-time
        while True:
            # Get current time
            current_time = time.strftime("%H:%M:%S")

            # Initialize CPU and memory usage
            cpu_usage, memory_usage_mb = 0, 0

            # Get CPU and memory usage for the process
            cpu_usage = process.cpu_percent(interval=1)  # CPU usage over a 1-second interval
            memory_info = process.memory_info()
            memory_usage_mb = memory_info.rss / (1024 * 1024)  # Convert bytes to MB

            # Write the data to the file
            file.write(f"{current_time},{cpu_usage},{memory_usage_mb:.2f}\n")
            file.flush()  # Ensure data is written to the file

            print(f"Time: {current_time}, CPU: {cpu_usage}%, Memory: {memory_usage_mb:.2f} MB")

    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")
