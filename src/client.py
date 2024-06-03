import socket
import threading
from helper import NIC, Packet
import time

class RouterClient:
    def __init__(self, nics, server_addr):
        self.nics = nics
        self.server_addr = server_addr
        self.device_socket = None
        self.available_nic = 0

    def forever_listen(self):
        while True:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                    nic = self.nics[self.available_nic]
                    client_socket.bind((nic.ip, nic.port))
                    client_socket.listen(5)
                    print(f"Forever listening on addr: {nic.ip}:{nic.port}")
                    server_socket, address = client_socket.accept()
                    with server_socket:
                        print(f"Accept from: {address}")
                        response = server_socket.recv(70000)
                        print(f"Received response: {response.decode()}")
                        if self.device_socket:
                            self.device_socket.sendall(response)
                            self.device_socket.close()
                            self.device_socket = None
                                
            except Exception as e:
                print(f"Error: {e}")
                self.available_nic = (self.available_nic + 1) % len(self.nics)
                if self.available_nic == 0:
                    time.sleep(2)

    def listen_for_devices(self, listen_ip, listen_port):
        router_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        router_socket.bind((listen_ip, listen_port))
        router_socket.listen(5)
        print("Listening for device connections on {}:{}".format(listen_ip, listen_port))
        
        while True:
            device_socket, address = router_socket.accept()
            threading.Thread(target=self.forever_listen).start()
            self.device_socket = device_socket
                    
            print(f"Connection from {address}")
            threading.Thread(target=self.handle_device_request, args=(device_socket,)).start()

    def handle_device_request(self, device_socket):
        request = device_socket.recv(70000)
        print(f"Received request: {request.decode()}")
        req_packet = Packet(text=request.decode())
        
        for nic in self.nics:
            if nic.is_connected:
                print(f"Choose nic: {nic.ip}, {nic.port}")
                self.send_to_server(req_packet, nic)
                break

    def send_to_server(self, req_packet, nic):
        print("Sending request to server")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
                server_socket.connect(self.server_addr)
                server_socket.sendall(req_packet.text.encode())
                server_socket.settimeout(5)
        except Exception as e:
            print(f"Error sending to server: {e}")

if __name__ == "__main__":
    nics = [NIC("127.0.0.1", 8001), NIC('127.0.0.1', 8002), NIC('127.0.0.1', 8003)]

    client = RouterClient(nics, ("127.0.0.1", 9000))
    client.listen_for_devices("127.0.0.1", int(input("Enter the local server port: ")))
