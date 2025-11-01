import socket 
import os

# Define host ip and port
HOST = '0.0.0.0'  # Any localhost interface
PORT = 1769

# Create TCP socket listening on ip address and port
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))

# Listen for connections
server_socket.listen()
print(f"Server listening on {HOST}:{PORT}...")

try:
    # Loop forever - handle one request at a time
    while True:
        # Accept a connection
        client_socket, addr = server_socket.accept()
        print(f"Connected by {addr}")
        
        try:
            # Read the data from client socket
            request = client_socket.recv(1024).decode()
            print(f"Received request:\n{request}")
            
            # Parse the HTTP request - expecting GET /<filename>
            lines = request.split('\n')
            if len(lines) > 0:
                first_line = lines[0].split()
                if len(first_line) >= 2 and first_line[0] == 'GET':
                    # Extract filename (remove leading '/')
                    filename = first_line[1][1:]  # Remove the leading '/'
                    
                    # Handle empty filename (default to index)
                    if filename == '':
                        filename = 'index.html'
                    
                    print(f"Requested file: {filename}")
                    
                    # Check if file exists
                    if os.path.isfile(filename):
                        # File found - open and read contents
                        with open(filename, 'rb') as f:
                            file_content = f.read()
                        
                        # Create HTTP OK response
                        response_header = "HTTP/1.1 200 OK\r\n\r\n"
                        
                        # Send header as bytes
                        client_socket.sendall(response_header.encode())
                        
                        # Send file contents (handles large files automatically)
                        client_socket.sendall(file_content)
                        
                        print(f"File {filename} sent successfully")
                    else:
                        # File not found - send 404
                        response = "HTTP/1.1 404 Not Found\r\n\r\n<html><head></head><body><h1>404 Not Found</h1></body></html>\r\n"
                        client_socket.sendall(response.encode())
                        print(f"File {filename} not found - sent 404")
        
        except Exception or KeyboardInterrupt as e :
            print(f"Error handling request: {e}")
        
        finally:
            # Close the client socket
            client_socket.close()
            print("Client socket closed\n")

except KeyboardInterrupt:
    print("\nShutting down server...")
finally:
    server_socket.close()