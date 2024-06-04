#!/home/liyu/anaconda3/envs/CN/bin/python3
from scapy.layers.inet import Ether, TCP, IP
from scapy.all import *
def main (x):
    try:
      pktParsed = Ether(str(x))
      if pktParsed[TCP].dport != 22:
            return
      MACsrc = pktParsed[Ether].src
      MACdst = pktParsed[Ether].dst
      IPsrc = pktParsed[IP].src
      IPdst = pktParsed[IP].dst
      TCPsrc = pktParsed[TCP].sport
      TCPdst = pktParsed[TCP].dport
      b = Ether(dst = MACsrc, src = MACdst) /IP(src = IPdst, dst = IPsrc) /TCP(sport=TCPdst,dport=TCPsrc,flags=0x10)
      sendp(b, iface="eth0")
    except:
      return
if __name__ == "__main__":
    sniff(iface="eth0", prn=lambda x: main(x))