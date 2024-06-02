# NFQUEUE USAGE

## Installation

Install ```scapy``` and ```iptables```

```
sudo apt-get install iptables
sudo apt-get install libnetfilter-queue-dev
pip install scapy netfilterqueue
```

## Set Up iptables

```
sudo iptables -A FORWARD -j NFQUEUE --queue-num 0
```

- -A FORWARD: Appends a rule to the FORWARD chain.
- -j NFQUEUE: Jumps to the NFQUEUE target, which sends packets to a user-space queue.
- --queue-num 0: Specifies the queue number (0 in this case) to use.

## Scapy nfqueue code example

```python=
from scapy.all import *
from netfilterqueue import NetfilterQueue

def process_packet(packet):
    scapy_packet = IP(packet.get_payload())  # Convert the raw packet payload to a Scapy packet

    # Example preprocessing: Modify the TTL value
    if scapy_packet.haslayer(IP):
        scapy_packet[IP].ttl -= 1  # Decrement TTL by 1

    # Set the modified packet payload back
    packet.set_payload(bytes(scapy_packet))

    # Accept the packet (send it forward)
    packet.accept()

# Set up NFQUEUE
nfqueue = NetfilterQueue()
nfqueue.bind(0, process_packet)

try:
    print("[*] Starting packet processing...")
    nfqueue.run()  # Start processing packets
except KeyboardInterrupt:
    print("[*] Stopping packet processing...")
    nfqueue.unbind()  # Clean up when the script is stopped
```

## Extract what we needs

```
from scapy.all import IP, Raw, Ether

# Example function to process a packet
def process_packet(packet):
    scapy_packet = IP(packet.get_payload())  # Convert raw packet payload to a Scapy packet

    # Check if the packet has an IP layer
    if scapy_packet.haslayer(IP):
        # Extract address headers (source and destination IP addresses)
        src_ip = scapy_packet[IP].src
        dst_ip = scapy_packet[IP].dst
        address_headers = f"Source IP: {src_ip}, Destination IP: {dst_ip}"
        
        # Extract the raw payload
        if scapy_packet.haslayer(Raw):
            raw_payload = scapy_packet[Raw].load
        else:
            raw_payload = b''

        # Concatenate address headers and raw payload
        concatenated_data = address_headers.encode() + raw_payload

        # Calculate the length of the concatenation
        concatenated_length = len(concatenated_data)

        # Print extracted information
        print(f"Raw Payload: {raw_payload}")
        print(f"Address Headers: {address_headers}")
        print(f"Concatenated Length: {concatenated_length}")

    # Accept the packet (send it forward)
    packet.accept()

# Example usage with a packet (Replace this with actual packet data)
example_packet = Ether()/IP(src="192.168.1.1", dst="192.168.1.2")/Raw(load="Hello, world!")
process_packet(example_packet)

```
