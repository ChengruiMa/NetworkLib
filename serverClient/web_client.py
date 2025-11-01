import socket
import sys

def main():
    # Check command line arguments
    if len(sys.argv) != 4:
        print("Usage: python3 web_client.py <server_host> <server_port> <filename>")
        print("Example: python3 web_client.py localhost 1769 helloworld.html")
        sys.exit(1)
    
    # Parse command line
    server_host = sys.argv[1]
    server_port = int(sys.argv[2])
    filename = sys.argv[3]
    
    print(f"[CLIENT] Connecting to {server_host}:{server_port}")
    print(f"[CLIENT] Requesting file: {filename}\n")
    
    try:
        # Create TCP socket and connect to server
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((server_host, server_port))
        print(f"[CLIENT] Connected successfully!\n")
        
        # Create HTTP GET request
        request = f"GET /{filename} HTTP/1.1\r\nHost: {server_host}\r\n\r\n"
        
        # Send the request
        client_socket.sendall(request.encode())
        print(f"[CLIENT] Sent request:\n{request}")
        
        # Use bytes to receive chunked response from server
        response = b""  
        while True:
            # 4096 bytes maximum a time
            chunk = client_socket.recv(4096)
            if not chunk:
                # No more data
                break
            response += chunk
        
        print(f"[CLIENT] Received {len(response)} bytes from server\n")
        print("=" * 80)
        print("[SERVER RESPONSE]")
        print("=" * 80)
        
        # Try to decode and print the response
        try:
            # Attempt to decode as text
            print(response.decode())
        except UnicodeDecodeError:
            # If binary file, show first part and summary
            print("[Binary file received - showing first 500 bytes]")
            print(response[:500])
            print(f"\n... [Total: {len(response)} bytes]")
        
        print("=" * 80)
        
    except ConnectionRefusedError:
        print(f"[ERROR] Could not connect to {server_host}:{server_port}")
        print("[ERROR] Make sure the server is running!")
        sys.exit(1)
    
    except Exception as e:
        print(f"[ERROR] An error occurred: {e}")
        sys.exit(1)
    
    finally:
        # Close the socket
        client_socket.close()
        print("\n[CLIENT] Connection closed")


if __name__ == "__main__":
    main()