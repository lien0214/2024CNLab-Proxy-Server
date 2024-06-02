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
