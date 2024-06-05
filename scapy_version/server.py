import socket
from scapy.all import *
import threading
from queue import Queue
import time
import netifaces
import argparse

BUFFER_SIZE = 4096

class NIC:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

class TCPConnection:
    # for reconstructing TCP connection with packets
    def __init__(self, src, sport, dst, dport):
        self.src = src
        self.sport = sport
        self.dst = dst
        self.dport = dport
        self.buffer = {}
        self.expected_seq = None
        self.data = b''
        self.lock = threading.Lock()
        self.complete = threading.Event()

    def add_packet(self, packet):
        tcp = packet[TCP]
        seq = tcp.seq
        payload = bytes(tcp.payload)

        with self.lock:
            if self.expected_seq is None:
                self.expected_seq = seq

            if seq == self.expected_seq:
                self.data += payload
                self.expected_seq += len(payload)

                while self.expected_seq in self.buffer:
                    self.data += self.buffer.pop(self.expected_seq)
                    self.expected_seq += len(self.buffer[self.expected_seq])
            else:
                self.buffer[seq] = payload

    def get_data(self):
        with self.lock:
            return self.data

    def is_complete(self):
        return self.complete.is_set()

    def set_complete(self):
        self.complete.set()

class Server:
    def __init__(self, server_address, nics):
        self.server_address = server_address
        self.nics = nics
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(self.server_address)
        self.server_socket.listen(5)
        self.queue_lock = threading.Lock()
        self.q = Queue()
        self.client_sockets = {}
        self.connections = {}

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

    def receive_packets(self):
        while True:
            client_socket, client_address = self.server_socket.accept()
            print(f"Connection from {client_address}")
            threading.Thread(target=self.handle_client, args=(client_socket,)).start()

    def handle_client(self, client_socket):
        while True:
            try:
                packet_length = client_socket.recv(2)
                if not packet_length:
                    break
                packet_length = int.from_bytes(packet_length, byteorder='big')
                packet_data = client_socket.recv(packet_length)
                with self.queue_lock:
                    self.q.put((client_socket, packet_data))
            except Exception as e:
                print(f"Error receiving packet: {e}")
                break

    def handle_queue(self):
        while True:
            with self.queue_lock:
                if self.q.empty():
                    time.sleep(1)
                    continue
                client_socket, packet_data = self.q.get()

            packet = IP(packet_data)
            dest_ip = packet[IP].dst
            dest_port = packet[TCP].dport
            conn_key = (packet[IP].src, packet[TCP].sport, dest_ip, dest_port)

            if conn_key not in self.connections:
                self.connections[conn_key] = TCPConnection(packet[IP].src, packet[TCP].sport, dest_ip, dest_port)

            conn = self.connections[conn_key]
            conn.add_packet(packet)

            if TCP in packet and packet[TCP].flags & 0x01:  # FIN flag
                conn.set_complete()

            if conn.is_complete():
                self.send_to_destination(conn_key, conn.get_data())

    def send_to_destination(self, conn_key, data):
        dest_ip, dest_port = conn_key[2], conn_key[3]
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as dest_socket:
                dest_socket.connect((dest_ip, dest_port))
                dest_socket.sendall(data)
                response_payload = b""
                while True:
                    part = dest_socket.recv(BUFFER_SIZE)
                    if not part:
                        break
                    response_payload += part

                # Prepare the response packet segments
                seq_num = 0
                while response_payload:
                    payload_chunk = response_payload[:BUFFER_SIZE]
                    response_payload = response_payload[BUFFER_SIZE:]

                    response_packet = IP(src=conn_key[2], dst=conn_key[0]) / TCP(
                        sport=conn_key[3], dport=conn_key[1], seq=seq_num, ack=1, flags='A') / Raw(load=payload_chunk)
                    
                    response_data = bytes(response_packet)
                    response_length = len(response_data)
                    response_length_bytes = response_length.to_bytes(2, byteorder='big')
                    data_to_send = response_length_bytes + response_data

                    # Send the response back to the client
                    try:
                        client_socket = self.client_sockets[conn_key]
                        client_socket.sendall(data_to_send)
                    except Exception as e:
                        print(f"Queue send packet failure: {e}")
                        break

                    seq_num += len(payload_chunk)

                # Send FIN packet to indicate the end of transmission
                fin_packet = IP(src=conn_key[2], dst=conn_key[0]) / TCP(
                    sport=conn_key[3], dport=conn_key[1], seq=seq_num, ack=1, flags='FA')
                fin_data = bytes(fin_packet)
                fin_length = len(fin_data)
                fin_length_bytes = fin_length.to_bytes(2, byteorder='big')
                data_to_send = fin_length_bytes + fin_data

                try:
                    client_socket.sendall(data_to_send)
                except Exception as e:
                    print(f"Queue send FIN packet failure: {e}")

        except Exception as e:
            print(f"Error sending data to destination: {e}")


def get_ip_address(nic_name):
    try:
        return netifaces.ifaddresses(nic_name)[netifaces.AF_INET][0]['addr']
    except KeyError:
        print(f"Could not get IP address for {nic_name}. Make sure the NIC name is correct and has an IPv4 address.")
        exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Start the server with specified NICs.")
    parser.add_argument('nics', metavar='N', type=str, nargs='+', help='NIC names to use')
    parser.add_argument('--port', type=int, default=9000, help='Port to listen on')

    args = parser.parse_args()
    nic_names = args.nics
    port = args.port

    nics = []
    for i, nic_name in enumerate(nic_names):
        ip_address = get_ip_address(nic_name)
        nics.append(NIC(ip_address, 8001 + i))

    server = Server(('0.0.0.0', port), nics)
    threading.Thread(target=server.handle_queue).start()
    server.receive_packets()
