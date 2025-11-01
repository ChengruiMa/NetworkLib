import socket 
import os
import threading

# Define host ip and port
HOST = '0.0.0.0'
PORT = 1769

# Thread-safe counter for active connections
active_connections = 0
connection_lock = threading.Lock()

def handle_client(client_socket, addr):
    """
    Communicator function - handles a single client's request in a separate thread.
    """
    global active_connections
    
    with connection_lock:
        active_connections += 1
        conn_id = active_connections
    
    print(f"[CONN {conn_id}] New connection from {addr[0]}:{addr[1]}")
    
    try:
        # Read the data from client socket
        request = client_socket.recv(1024).decode()
        
        # Parse the HTTP request - expecting GET /<filename>
        lines = request.split('\n')
        if len(lines) > 0:
            first_line = lines[0].split()
            if len(first_line) >= 2 and first_line[0] == 'GET':
                # Extract filename (remove leading '/')
                filename = first_line[1][1:]
                
                # Handle empty filename (default to index)
                if filename == '':
                    filename = 'index.html'
                
                print(f"[CONN {conn_id}] GET /{filename}")
                
                # Check if file exists
                if os.path.isfile(filename):
                    # File found - open and read contents
                    with open(filename, 'rb') as f:
                        file_content = f.read()
                    
                    # Create HTTP OK response
                    response_header = "HTTP/1.1 200 OK\r\n\r\n"
                    client_socket.sendall(response_header.encode())
                    client_socket.sendall(file_content)
                    
                    print(f"[CONN {conn_id}] 200 OK - Sent {len(file_content):,} bytes")
                else:
                    # File not found - send 404
                    response = "HTTP/1.1 404 Not Found\r\n\r\n<html><head></head><body><h1>404 Not Found</h1></body></html>\r\n"
                    client_socket.sendall(response.encode())
                    print(f"[CONN {conn_id}] 404 Not Found - {filename}")
    
    except Exception as e:
        print(f"[CONN {conn_id}] ERROR: {e}")
    
    finally:
        client_socket.close()
        with connection_lock:
            active_connections -= 1
        print(f"[CONN {conn_id}] Connection closed\n")


def main():
    """
    Main thread - listens for client connections and spawns Communicator threads.
    """
    # Create TCP socket listening on ip address and port
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    
    print("=" * 60)
    print(f"Multi-threaded HTTP Server")
    print(f"Listening on http://{HOST}:{PORT}")
    print(f"Press Ctrl+C to shutdown")
    print("=" * 60 + "\n")
    
    try:
        while True:
            client_socket, addr = server_socket.accept()
            client_thread = threading.Thread(target=handle_client, args=(client_socket, addr))
            client_thread.start()
    
    except KeyboardInterrupt:
        print("\n" + "=" * 60)
        print("Shutting down server...")
        print("=" * 60)
    finally:
        server_socket.close()


if __name__ == "__main__":
    main()