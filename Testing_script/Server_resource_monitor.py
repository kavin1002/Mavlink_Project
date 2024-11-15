import psutil
import time
import argparse

# Set up command line argument parsing
parser = argparse.ArgumentParser(description='Monitor CPU and memory usage of uav_udp and gcs_udp processes.')
parser.add_argument('output_file', type=str, help='Output CSV file name')
args = parser.parse_args()

# Function to find the process by name
def find_process_by_name(name):
    for process in psutil.process_iter(['pid', 'name']):
        if process.info['name'] == name:
            return process
    return None

# Find the uav_udp and gcs_udp processes
uav_process = find_process_by_name("uav_udp")
gcs_process = find_process_by_name("gcs_udp")

if not uav_process:
    print("Process 'uav_udp' not found.")
if not gcs_process:
    print("Process 'gcs_udp' not found.")

if not uav_process and not gcs_process:
    print("Neither 'uav_udp' nor 'gcs_udp' processes were found. Exiting.")
    exit()

# Open the output file for writing
with open(args.output_file, 'w') as file:
    # Write the header
    file.write("Time,CPU Usage uav_udp (%),Memory Usage uav_udp (MB),CPU Usage gcs_udp (%),Memory Usage gcs_udp (MB),Average CPU Usage (%),Average Memory Usage (MB)\n")

    try:
        # Monitor the processes in real-time
        while True:
            # Get current time
            current_time = time.strftime("%H:%M:%S")

            # Initialize CPU and memory usage for each process
            uav_cpu_usage, uav_memory_usage_mb = 0, 0
            gcs_cpu_usage, gcs_memory_usage_mb = 0, 0

            # Get CPU and memory usage for uav_udp if it's running
            if uav_process:
                uav_cpu_usage = uav_process.cpu_percent(interval=1)
                uav_memory_info = uav_process.memory_info()
                uav_memory_usage_mb = uav_memory_info.rss / (1024 * 1024)  # Convert bytes to MB

            # Get CPU and memory usage for gcs_udp if it's running
            if gcs_process:
                gcs_cpu_usage = gcs_process.cpu_percent(interval=1)
                gcs_memory_info = gcs_process.memory_info()
                gcs_memory_usage_mb = gcs_memory_info.rss / (1024 * 1024)  # Convert bytes to MB

            # Calculate the average CPU and memory usage
            avg_cpu_usage = (uav_cpu_usage + gcs_cpu_usage) / 2
            avg_memory_usage = (uav_memory_usage_mb + gcs_memory_usage_mb) / 2

            # Write the data to the file
            file.write(f"{current_time},{uav_cpu_usage},{uav_memory_usage_mb},{gcs_cpu_usage},{gcs_memory_usage_mb},{avg_cpu_usage},{avg_memory_usage}\n")
            file.flush()  # Ensure data is written to the file

            print(f"Time: {current_time}, UAV CPU: {uav_cpu_usage}%, UAV Memory: {uav_memory_usage_mb:.2f} MB, "
                  f"GCS CPU: {gcs_cpu_usage}%, GCS Memory: {gcs_memory_usage_mb:.2f} MB, "
                  f"Average CPU: {avg_cpu_usage}%, Average Memory: {avg_memory_usage:.2f} MB")

    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")
