import socket
import threading
from queue import Queue
from scapy.all import *
from scapy.layers.inet import IP
from netfilterqueue import NetfilterQueue
import time

class RouterClient:
    def __init__(self, server_addr):
        self.server_addr = server_addr
        self.server_sock = None
        self.packet_queue = Queue()
        self.stop_event = threading.Event()

    def start_nfqueue(self):
        nfqueue = NetfilterQueue()
        nfqueue.bind(1, self.handle_packet)
        recv_thread = threading.Thread(target=self.receive_and_send)
        recv_thread.start()
        
        try:
            print("Starting NFQueue")
            nfqueue.run()
        except KeyboardInterrupt:
            print("Stopping NFQueue")
            self.stop_event.set()
            recv_thread.join()
        finally:
            nfqueue.unbind()

    def handle_packet(self, packet):
        scapy_pkt = IP(packet.get_payload())
        print(f"Received packet: {scapy_pkt.summary()}")
        self.send_to_server(scapy_pkt)
        packet.drop()  # Drop the original packet

    def send_to_server(self, packet):
        packet_data = bytes(packet)
        packet_length = len(packet_data)
        packet_length_bytes = packet_length.to_bytes(2, byteorder='big')
        data_to_send = packet_length_bytes + packet_data

        while True:
            try:
                if not self.server_sock:
                    self.connect_to_server()
                self.server_sock.sendall(data_to_send)
                break
            except socket.error:
                print("Socket error, reconnecting...")
                self.server_sock = None
                self.connect_to_server()

    def receive_and_send(self):
        while not self.stop_event.is_set():
            try:
                packet_length = self.server_sock.recv(2)
                if not packet_length:
                    continue
                packet_length = int.from_bytes(packet_length, byteorder='big')
                response = self.server_sock.recv(packet_length)
                if response:
                    packet = IP(response)
                    self.send_to_device(packet)
            except socket.error:
                self.server_sock = None
                self.connect_to_server()

    def connect_to_server(self):
        while not self.server_sock:
            try:
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_socket.connect(self.server_addr)
                self.server_sock = server_socket
                break
            except Exception as e:
                print(f"Error connecting to server: {e}")
                time.sleep(1)

    def send_to_device(self, packet):
        dest_ip = packet[IP].dst
        dest_port = packet[IP].dport if TCP in packet else 0
        device_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            device_socket.connect((dest_ip, dest_port))
            device_socket.sendall(bytes(packet))
        except Exception as e:
            print(f"Error sending packet to device: {e}")
        finally:
            device_socket.close()

if __name__ == "__main__":
    client = RouterClient(("127.0.0.1", 9000))
    client.start_nfqueue()
