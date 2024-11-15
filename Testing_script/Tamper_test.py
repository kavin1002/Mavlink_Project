from scapy.all import *

# Original payload (replace with your actual payload from the pcap)
tampered_payload = bytes.fromhex("091000000000003e03dc834cba7240e08f3c26c4c6de2642d845c044315260f71c96f9136d84599cbd3ab1f7b49166")  

# Modify one or more bytes to simulate tampering
tampered_payload = bytearray(tampered_payload)
tampered_payload[2] ^= 0xFF  # Flip bits to alter the payload

# Construct the packet with the modified payload
packet = IP(dst="127.0.0.1")/UDP(dport=14662)/Raw(load=bytes(tampered_payload))

# Send the tampered packet
send(packet, count=1)
