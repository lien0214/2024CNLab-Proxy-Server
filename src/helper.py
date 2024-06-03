import socket
import time
import re

class NIC:
    def __init__(self, ip, port):
        '''maybe have to be modify''' 
        self.ip = ip
        self.port = port
        self.is_connected = False

class Packet:
    def parse_request(self, preprocessed_request):
        headers, payload = preprocessed_request.split("\r\n\r\n", 1)
        header_lines = headers.split("\r\n")
        src_ip = dest_ip = src_port = dest_port = None
        for line in header_lines:
            if line.startswith("Src-IP:"):
                src_ip = line.split(": ")[1]
            elif line.startswith("Src-Port:"):
                src_port = int(line.split(": ")[1])
            elif line.startswith("Dest-IP:"):
                dest_ip = line.split(": ")[1]
            elif line.startswith("Dest-Port:"):
                dest_port = int(line.split(": ")[1])
        return payload, (src_ip, src_port), (dest_ip, dest_port)    
    
    def __init__(self, text=None, payload=None, src_addr=None, dest_addr=None):
        if payload:
            self.text = text
            self.payload = payload
            self.src_addr = src_addr
            self.dest_addr = dest_addr
        else:
            self.text = text
            self.payload, self.src_addr, self.dest_addr = self.parse_request(text)