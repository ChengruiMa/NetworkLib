# HTTP Server and Client Implementation

Simple HTTP server and client implementations in Python for a single-threaded and a multi-threaded web server, and a web client that uses TCP connection to communicate with and scrape from any server.

## Requirements

- Python 3.x
- Standard library only (no external dependencies)

## Tools Overview

### 1. web_server.py
Basic single-threaded HTTP server that handles one client request at a time.

**Usage:**
```bash
python3 web_server.py
```

**Features:**
- Listens on port 1769
- Serves files from the current directory
- Handles GET requests
- Returns 200 OK for found files
- Returns 404 Not Found for missing files
- Defaults to `index.html` for root path requests
- Supports both text and binary files
- Single-threaded and no concurrent connection handling

### 2. multiThread_server.py
A multi-threaded HTTP server that handles multiple concurrent client connections.

**Usage:**
```bash
python3 multiThread_server.py
```

**Features:**
- Listens on port 1769
- Handles multiple clients simultaneously using threads
- Thread-safe connection counting
- Logging connections with increasing IDs
- Same file serving capabilities as basic server

**Server Output Example:**
```
[CONN 1] New connection from 127.0.0.1:54321
[CONN 1] GET /helloworld.html
[CONN 1] 200 OK - Sent 1,234 bytes
[CONN 1] Connection closed
```

### 3. web_client.py
HTTP client that connects to the server and requests files.

**Usage:**
```bash
python3 web_client.py <server_host> <server_port> <filename>
```

**Examples:**
```bash
python3 web_client.py localhost 1769 helloworld.html
python3 web_client.py 127.0.0.1 1769 english_words.txt
python3 web_client.py localhost 1769 nonexistent.txt
```

**Features:**
- Creates HTTP GET requests
- Receives and displays server responses
- Handles both text and binary files
- Shows connection information and handles connection failures
- Chunked data reception (4096 bytes per chunk)

**Client Output Example:**
```
[CLIENT] Connecting to localhost:1769
[CLIENT] Requesting file: helloworld.html
[CLIENT] Connected successfully!
[CLIENT] Received 1234 bytes from server
[SERVER RESPONSE]
HTTP/1.1 200 OK

<html>...
```

## Test Files

The directory includes test files for demonstration:
- `helloworld.html` - Sample HTML file

## Quick Start

### 1. Start the Server
In one terminal:
```bash
python3 web_server.py
# or for multi-threaded:
python3 multiThread_server.py
```

### 2. Make a Request with the Client
In another terminal:
```bash
python3 web_client.py localhost 1769 helloworld.html
```

### 3. Test with a Web Browser
Open your browser and navigate to:
```
http://localhost:1769/helloworld.html
```

## Testing Different Scenarios

### Successful File Request
```bash
python3 web_client.py localhost 1769 helloworld.html
# Expected: 200 OK with file contents
```

### File Not Found
```bash
python3 web_client.py localhost 1769 missing.txt
# Expected: 404 Not Found error page
```

### Default Index
```bash
# Request root path (/) - should serve index.html if it exists
curl http://localhost:1769/
```

## Multi-Threading Benefits

The multi-threaded server (`multiThread_server.py`) can handle multiple simultaneous requests:

```bash
# Terminal 1: Start multi-threaded server
python3 multiThread_server.py

# Terminal 2, 3, 4: Multiple simultaneous clients
python3 web_client.py localhost 1769 helloworld.html &
python3 web_client.py localhost 1769 helloworld.html &
```

Both requests should be processed concurrently instead of sequentially.

## HTTP Protocol Implementation

These tools implement a simplified version of HTTP/1.1:

**Request Format:**
```
GET /<filename> HTTP/1.1
Host: <server_host>
```

**Response Format (Success):**
```
HTTP/1.1 200 OK

<file_contents>
```

**Response Format (Not Found):**
```
HTTP/1.1 404 Not Found

<html><head></head><body><h1>404 Not Found</h1></body></html>
```

## Implementation Details

### Server Configuration
- **Host:** `0.0.0.0` (listens on all interfaces)
- **Port:** `1769`
- **Socket Type:** TCP (SOCK_STREAM)
- **Receive Buffer:** 1024 bytes

### Client Configuration
- **Socket Type:** TCP (SOCK_STREAM)
- **Receive Chunk Size:** 4096 bytes
- **Protocol:** HTTP/1.1

### Threading Setups
- Main thread: Accepts connections
- Worker threads: Handle individual client requests
- Thread-safe connection counter with locks
- Daemon threads for automatic cleanup