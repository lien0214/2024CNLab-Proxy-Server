import socket
import threading
import queue
import time
from scapy.all import IP, TCP, Raw

BUFFER_SIZE = 2048

class NIC:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

class Server:
    def __init__(self, addr, nics):
        self.addr = addr
        self.q = queue.Queue()
        self.nics = nics
        self.queue_lock = threading.Lock()
        self.available_nic_lock = threading.Lock()
        self.available_nic = 0
    
    def valid_socket(self):
        while True:
            try:
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                nic = self.nics[self.available_nic]
                client_socket.connect((nic.ip, nic.port))
                print(f"Handle Queue on {nic.ip}:{nic.port}")
                return client_socket
            except Exception as e:
                print(f"Handle Queue error connecting to {nic.ip}:{nic.port} - {e}")
                with self.available_nic_lock:
                    self.available_nic = (self.available_nic + 1) % len(self.nics)

    def listen_for_client(self):
        # listen for client request
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(self.addr)
        server_socket.listen(5)
        print(f"Server listening on {self.addr}")
 
        while True:
            client_socket, address = server_socket.accept()
            print(f"Connection from {address}")
            threading.Thread(target=self.handle_request, args=(client_socket,)).start()

    def handle_request(self, client_socket):
        try:
            # get total packet length first(2 bytes), and then recv length of packet length
            packet_length_bytes = client_socket.recv(2)
            if not packet_length_bytes:
                return
            packet_length = int.from_bytes(packet_length_bytes, byteorder='big')
            packet_data = client_socket.recv(packet_length)
            if not packet_data:
                return
            print(f"Received packet from client with length {packet_length}")
            client_socket.close()
        except socket.error:
            print("Received request error")
            client_socket.close()
            return

        # Put the packet in the queue
        with self.queue_lock:
            self.q.put(packet_data)

    def handle_queue(self):
        while True:
            with self.queue_lock:
                while self.q.empty():
                    time.sleep(1)
                packet_data = self.q.get()

            packet = IP(packet_data)
            dest_ip = packet[IP].dst
            dest_port = packet[TCP].dport

            # Reconstruct TCP connection
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as dest_socket:
                    dest_socket.connect((dest_ip, dest_port))
                    dest_socket.sendall(bytes(packet[TCP].payload))
                    response_payload = b""
                    while True:
                        part = dest_socket.recv(BUFFER_SIZE)
                        if not part:
                            break
                        response_payload += part
            except Exception as e:
                print(f"Error sending packet to destination: {e}")
                continue

            # Prepare the response packet
            response_packet = IP(src=packet[IP].dst, dst=packet[IP].src) / TCP(sport=packet[TCP].dport, dport=packet[TCP].sport) / Raw(load=response_payload)
            response_data = bytes(response_packet)
            response_length = len(response_data)
            response_length_bytes = response_length.to_bytes(2, byteorder='big')
            data_to_send = response_length_bytes + response_data

            # Send the response back to the client
            try:
                with self.valid_socket() as send_socket:
                    send_socket.sendall(data_to_send)
            except Exception as e:
                print(f"Queue send packet failure: {e}")

if __name__ == "__main__":
    # TODO: modify to argparser
    nics = [NIC('127.0.0.1', 8001), NIC('127.0.0.1', 8002), NIC('127.0.0.1', 8003)]
    server = Server(('127.0.0.1', 9000), nics)
    threading.Thread(target=server.handle_queue).start()
    server.listen_for_client()