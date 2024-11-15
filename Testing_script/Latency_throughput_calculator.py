import pandas as pd
import argparse

# Set up command line argument parsing
parser = argparse.ArgumentParser(description='Calculate latency and throughput from a CSV file and save the results.')
parser.add_argument('input_file', type=str, help='Input CSV file name')
parser.add_argument('output_file', type=str, help='Output CSV file name')
args = parser.parse_args()

# Load the input CSV file
df = pd.read_csv(args.input_file)

# Convert the 'Time' column to a numeric format
df['Time'] = pd.to_numeric(df['Time'])

# -----------------------
# Calculate Latency
# -----------------------
# Calculate latency in milliseconds: difference in 'Time' between consecutive packets, converted to ms
df['Latency (ms)'] = df['Time'].diff().fillna(0) * 1000  # Fill NaN for the first row with 0

# Calculate the average latency
average_latency = df['Latency (ms)'].mean()

# Add the average latency to the first row of the next available column
df.at[0, 'Average Latency (ms)'] = average_latency

# -----------------------
# Calculate Throughput
# -----------------------
# Calculate the total duration of the capture (in seconds)
total_time = df['Time'].iloc[-1] - df['Time'].iloc[0]

# Calculate the total number of packets
total_packets = len(df)

# Calculate throughput in packets per second (pps)
throughput_pps = total_packets / total_time

# Calculate the total number of bytes transferred
# Assume 'Length' column represents the packet size in bytes
total_bytes = df['Length'].sum()

# Calculate throughput in bytes per second (Bps)
throughput_bps = total_bytes / total_time

# Calculate throughput in kilobits per second (kbps)
throughput_kbps = (total_bytes * 8) / 1000 / total_time

# Add throughput values to the first row of the next available columns
df.at[0, 'Throughput (pps)'] = throughput_pps
df.at[0, 'Throughput (Bps)'] = throughput_bps
df.at[0, 'Throughput (kbps)'] = throughput_kbps

# Save the results to the specified output CSV file
df.to_csv(args.output_file, index=False)

print("Latency and throughput calculations completed. The results are saved in:", args.output_file)
print(f"Average Latency: {average_latency:.3f} ms")
print(f"Throughput: {throughput_pps:.3f} packets per second (pps)")
print(f"Throughput: {throughput_bps:.3f} bytes per second (Bps)")
print(f"Throughput: {throughput_kbps:.3f} kilobits per second (kbps)")