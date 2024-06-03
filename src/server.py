import socket
import threading
from helper import Packet, NIC
import argparse
import queue
import time

class Server:
    def __init__(self, addr, nics):
        self.addr = addr
        self.q = queue.Queue()
        self.nics = nics
        self.condition = threading.Condition()
        self.available_nic = 0
    
    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(self.addr)
        server_socket.listen(5)
        print(f"Server listening on {self.addr}")

        threading.Thread(target=self.handle_queue).start()
 
        while True:
            client_socket, address = server_socket.accept()
            print(f"Connection from {address}")
            threading.Thread(target=self.handle_request, args=(client_socket,)).start()
    
    def handle_queue(self):
        def valid_socket():
            while True:
                try:
                    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    nic = self.nics[self.available_nic]
                    client_socket.connect((nic.ip, nic.port))
                    print(f"Connected to {nic.ip}:{nic.port}")
                    return client_socket
                                    
                except Exception as e:
                    print(f"Error connecting to {nic.ip}:{nic.port} - {e}")
                    with self.condition:
                        self.available_nic = (self.available_nic + 1) % len(self.nics)
                    if self.available_nic == 0:
                        print("All NICs failed, retrying in 2 ns...")
                        time.sleep(2)

        
        send_socket = valid_socket()
        while True:
            with self.condition:
                while self.q.empty():
                    self.condition.wait()
                packet = self.q.get()
                try:
                    send_socket.sendall(packet.text.encode())
                except:
                    send_socket.close()
                    send_socket = valid_socket()
                    send_socket.sendall(packet.text.encode())

    def process_payload(self, payload, src_addr, dest_addr):
        """
        Preprocess the request to include custom headers for source address, destination address, and payload.
        """
        src_ip, src_port = src_addr
        dest_ip, dest_port = dest_addr
        custom_header = (
            f"Src-IP: {src_ip}\r\n"
            f"Src-Port: {src_port}\r\n"
            f"Dest-IP: {dest_ip}\r\n"
            f"Dest-Port: {dest_port}\r\n"
            f"\r\n\r\n"
        )
        return custom_header + payload
    
    def handle_request(self, client_socket):
        try:
            req = client_socket.recv(70000)
            print(f"Received request: {req.decode()}")
        except socket.error:
            print("Received request error")
            client_socket.close()
            return

        req_packet = Packet(req.decode())

        dest_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        dest_socket.connect(req_packet.dest_addr)
        dest_socket.sendall(req_packet.payload.encode())

        response = dest_socket.recv(70000)
        
        print(f'get response : {response}\n')
        dest_socket.close()
        
        response = self.process_payload(response.decode(), req_packet.dest_addr, req_packet.src_addr)
        response_packet = Packet(text=response)
        print(f'response text : {response_packet.text}')
        print(f'response payload : {response_packet.payload}')
        print(f'response src : {response_packet.src_addr}')
        print(f'response dst : {response_packet.dest_addr}')

        with self.condition:
            self.q.put(response_packet)
            self.condition.notify()
        
        client_socket.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Start the server.")
    parser.add_argument('--ip', type=str, required=False, help='IP address of the server')
    parser.add_argument('--port', type=int, required=False, help='Port number of the server')
    args = parser.parse_args()
    
    nics = [NIC('127.0.0.1', 8001), NIC('127.0.0.1', 8002),NIC('127.0.0.1', 8003)]
    server = Server(('127.0.0.1', 9000), nics)
    server.start()
