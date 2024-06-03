import socket
import threading
from helper import PreprocessedPacket, NIC, recv_preprocessed_packet, send_preprocessed_packet
import queue
import time

class Server:
    def __init__(self, addr, nics):
        self.addr = addr
        self.q = queue.Queue()
        self.nics = nics
        self.queue_lock = threading.Lock()
        self.available_nic_lock = threading.Lock()
        self.available_nic = 0
    
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
    
    def handle_queue(self):

        def valid_socket():
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

        send_socket = valid_socket()
        packet = None
        while True:
            if packet == None:
                with self.queue_lock:
                    while self.q.empty():
                        # TODO: wait condition implementation, no busy waiting
                        time.sleep(20)
                    packet = self.q.get()
            try:
                send_preprocessed_packet(send_socket, packet)
            except Exception as e:
                print(f"Queue send packet failure: {e}")
                send_socket.close()
                send_socket = valid_socket()
    
    def handle_request(self, client_socket):
        try:
            # get total packet length first(2 bytes), and then recv length of packet length
            request_preprocessed_packet = recv_preprocessed_packet(client_socket)
            print(f"Received request from client")
            client_socket.close()
        except socket.error:
            print("Received request error")
            client_socket.close()
            return

        # Send request with its own identity
        dest_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        dest_socket.connect((request_preprocessed_packet.dest_ip, request_preprocessed_packet.dest_port))
        dest_socket.sendall(request_preprocessed_packet.payload.encode())

        #TODO: not sure
        response_payload = dest_socket.recv(70000)
        
        print(f'Get response with length: {len(response_payload)}\n')
        dest_socket.close()
        
        response_preprocessed_packet = PreprocessedPacket(
            src_ip=request_preprocessed_packet.dest_ip,
            src_port=request_preprocessed_packet.dest_port,
            dest_ip=request_preprocessed_packet.src_ip,
            dest_port=request_preprocessed_packet.src_port,
            payload=response_payload
        )

        # put in queue
        with self.queue_lock:
            self.q.put(response_preprocessed_packet)

if __name__ == "__main__":
    # TODO: modify to argparser
    nics = [NIC('127.0.0.1', 8001), NIC('127.0.0.1', 8002),NIC('127.0.0.1', 8003)]
    server = Server(('127.0.0.1', 9000), nics)
    threading.Thread(target=server.handle_queue).start()
    server.listen_for_client()