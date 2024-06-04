import socket
import threading
from helper import NIC, PreprocessedPacket, recv_preprocessed_packet, send_preprocessed_packet, send_payload_to_device, MAX_BUFFER_SIZE
import time

class RouterClient:
    def __init__(self, nics, server_addr):
        self.nics = nics
        self.server_addr = server_addr
        self.available_nic = 0
        self.lock = threading.Lock()
        self.server_sock = None

    # def listen_for_nic(self):
    #     while True:
    #         # listen on one nic until it fails, and then looping look for available nic
    #         try:
    #             with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
    #                 # set nic server listen
    #                 nic = self.nics[self.available_nic]
    #                 client_socket.bind((nic.ip, nic.port))
    #                 client_socket.listen(5)
    #                 print(f"Listen on nic addr: {nic.ip}:{nic.port}")
    #                 while True:
    #                     # accept preprocessed packet from server and send raw payload back to devices
    #                     server_socket, address = client_socket.accept()
    #                     with server_socket:
    #                         print(f"Accept from: {address}")
    #                         # TODO: handle receive timeout error? (maybe failure)
    #                         response_preprocessed_packet = recv_preprocessed_packet(server_socket)
    #                         if response_preprocessed_packet == None: raise Exception("response None")
    #                         print(f"Received response")
                            
    #                         print(f"send to device address: {response_preprocessed_packet.dest_ip} {response_preprocessed_packet.dest_port}")
    #                         send_payload_to_device(
    #                             response_preprocessed_packet.dest_ip,
    #                             response_preprocessed_packet.dest_port,
    #                             response_preprocessed_packet.payload
    #                         )
                                
    #         except Exception as e:
    #             print(f"Error: {e}")
    #             with self.lock:
    #                 self.available_nic = (self.available_nic + 1) % len(self.nics)
    #             if self.available_nic == 0:
    #                 time.sleep(20)

    def listen_for_devices(self, listen_address):
        # setup
        router_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        router_socket.bind(listen_address)
        router_socket.listen(5)
        print("Listening for device connections on {}".format(listen_address))
        
        while True:
            # accepting and handle device request
            device_socket, address = router_socket.accept()
            print(f"Connection from {address}")
            threading.Thread(target=self.handle_device_request, args=(device_socket,)).start()

    def handle_device_request(self, device_socket):
        # TODO: Modify to scapy
        request_text = device_socket.recv(MAX_BUFFER_SIZE).decode()
        print(f"Received request: {request_text}")
        request_packet = PreprocessedPacket()
        # TODO end
        # Get request_packet as PreprocessedPacket

        print("Sending request to server")
        # try:
        #     # TODO: maybe change to queue for another single socket to handle it 
        #     # doesn't handle failure when send packet from client to server
        if not send_preprocessed_packet(self.server_sock, request_packet):   
            self.server_sock = None 
            while self.server_socket == None:
                try:
                    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    nic = self.nics[self.available_nic]
                    server_socket.bind((nic.ip, nic.port))
                    server_socket.connect(self.server_addr)
                    self.server_sock = server_socket
                except Exception as e:
                    print(f"Sending Error: {e}")
                    with self.lock:
                        self.available_nic = (self.available_nic + 1) % len(self.nics)
                    if self.available_nic == 0:
                        time.sleep(20)
            send_preprocessed_packet(self.server_sock, request_packet)
        
        response_preprocessed_packet = recv_preprocessed_packet(self.server_sock)
        if response_preprocessed_packet == None:   
            self.server_sock = None 
            while self.server_socket == None:
                try:
                    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    nic = self.nics[self.available_nic]
                    server_socket.bind((nic.ip, nic.port))
                    server_socket.connect(self.server_addr)
                    self.server_sock = server_socket
                    break
                except Exception as e:
                    print(f"Receiving Error: {e}")
                    with self.lock:
                        self.available_nic = (self.available_nic + 1) % len(self.nics)
                    if self.available_nic == 0:
                        time.sleep(20)
            response_preprocessed_packet = recv_preprocessed_packet(self.server_sock, request_packet)

        print(f"Received response")
        
        print(f"send to device address: {response_preprocessed_packet.dest_ip} {response_preprocessed_packet.dest_port}")
        send_payload_to_device(
            response_preprocessed_packet.dest_ip,
            response_preprocessed_packet.dest_port,
            response_preprocessed_packet.payload
        )

if __name__ == "__main__":
    # TODO: modify to argparse
    
    # initial nics and client class
    nics = [NIC("127.0.0.1", 8001), NIC('127.0.0.1', 8002), NIC('127.0.0.1', 8003)]
    client = RouterClient(nics, ("127.0.0.1", 9000))
    
    # Start listen for nic and device
    # threading.Thread(target=client.listen_for_nic).start()
    client.listen_for_devices(("127.0.0.1", int(input("Enter the local server port: "))))