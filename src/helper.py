import socket

MAX_BUFFER_SIZE = 70000

class NIC:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

class PreprocessedPacket:
    '''
    context format:
        str: src-ip
        int: src-port
        str: dest-ip
        int: dest-port
        str: payload
    '''
    def __init__(self, payload=None, src_ip=None, src_port=None, dest_ip=None, dest_port=None):
        self.payload = payload
        self.src_ip = src_ip
        self.src_port = src_port
        self.dest_ip = dest_ip
        self.dest_port = dest_port


def send_preprocessed_packet(sock, preprocessed_packet):
    src_ip = preprocessed_packet.src_ip
    src_port = preprocessed_packet.src_port
    dest_ip = preprocessed_packet.dest_ip
    dest_port = preprocessed_packet.dest_port
    payload = preprocessed_packet.payload
    # Encode all parts
    src_ip_encoded = src_ip.encode('utf-8')
    src_port_encoded = src_port.to_bytes(2, 'big')
    dest_ip_encoded = dest_ip.encode('utf-8')
    dest_port_encoded = dest_port.to_bytes(2, 'big')
    payload_encoded = payload.encode('utf-8')
    
    # Create lengths for IP addresses
    src_ip_length = len(src_ip_encoded)
    dest_ip_length = len(dest_ip_encoded)
    
    # Encode lengths
    src_ip_length_encoded = src_ip_length.to_bytes(1, 'big')  # Assuming IP address length < 256
    dest_ip_length_encoded = dest_ip_length.to_bytes(1, 'big')
    
    # Concatenate all parts into a single message
    message = (src_ip_length_encoded + src_ip_encoded + 
               src_port_encoded + 
               dest_ip_length_encoded + dest_ip_encoded + 
               dest_port_encoded + 
               payload_encoded)
    
    # Calculate total message length and encode it
    total_length = len(message)
    total_length_encoded = total_length.to_bytes(2, 'big')  # Use 2 bytes for total length (up to 65535 bytes)

    # Prepend the total length to the message
    final_message = total_length_encoded + message
    
    # Send the message over the socket
    sock.sendall(final_message)

def recv_preprocessed_packet(sock) -> PreprocessedPacket:
    try:
        # First, read the total length of the message (2 bytes)
        total_length_encoded = sock.recv(2)
        total_length = int.from_bytes(total_length_encoded, 'big')
        
        # Receive the full message based on the total length
        message = sock.recv(total_length)
        
        # Extract the lengths of the IP addresses
        src_ip_length = int.from_bytes(message[0:1], 'big')
        src_ip_start = 1
        src_ip_end = src_ip_start + src_ip_length
        
        src_ip_encoded = message[src_ip_start:src_ip_end]
        src_ip = src_ip_encoded.decode('utf-8')
        
        src_port_start = src_ip_end
        src_port_end = src_port_start + 2
        src_port_encoded = message[src_port_start:src_port_end]
        src_port = int.from_bytes(src_port_encoded, 'big')
        
        dest_ip_length_start = src_port_end
        dest_ip_length_end = dest_ip_length_start + 1
        dest_ip_length = int.from_bytes(message[dest_ip_length_start:dest_ip_length_end], 'big')
        
        dest_ip_start = dest_ip_length_end
        dest_ip_end = dest_ip_start + dest_ip_length
        dest_ip_encoded = message[dest_ip_start:dest_ip_end]
        dest_ip = dest_ip_encoded.decode('utf-8')
        
        dest_port_start = dest_ip_end
        dest_port_end = dest_port_start + 2
        dest_port_encoded = message[dest_port_start:dest_port_end]
        dest_port = int.from_bytes(dest_port_encoded, 'big')
        
        payload_start = dest_port_end
        payload_encoded = message[payload_start:]
        payload = payload_encoded.decode('utf-8')
        
        return PreprocessedPacket(
            payload=payload,
            src_ip=src_ip,
            src_port=src_port,
            dest_ip=dest_ip,
            dest_port=dest_port
        )
    except Exception as e:
        print(f"recv preprocessed packet error: {e}")
        return None

def send_payload_to_device(dest_ip, dest_port, payload):
    # Create a socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            # Connect to the destination address
            sock.connect((dest_ip, dest_port))
            payload_encoded = payload.encode()
            sock.sendall(payload_encoded)
            return True
    except:
        return False