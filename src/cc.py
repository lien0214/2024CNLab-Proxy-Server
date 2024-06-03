import socket

def preprocess_request(request, src_addr, dest_addr):
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
    return custom_header + request

def fetch_google_homepage_via_local_server(local_host, local_port):
    request = (
        "GET / HTTP/1.1\r\n"
        "Host: www.google.com\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3\r\n"
        "Connection: close\r\n"
        "\r\n"
    )

    # Source and destination addresses for the custom header
    src_addr = ("127.0.0.1", 7000)  # Example source address (adjust as needed)
    dest_addr = ("www.google.com", 80)  # Example destination address

    # Preprocess the request to include custom headers
    preprocessed_request = preprocess_request(request, src_addr, dest_addr)
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((local_host, local_port))
            client_socket.sendall(preprocessed_request.encode())

            response = client_socket.recv(4096)

            print(f"receive: {response.decode()}")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    fetch_google_homepage_via_local_server("localhost", int(input("Enter the local server port: ")))
