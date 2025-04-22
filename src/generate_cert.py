#!/usr/bin/env python3
"""
Certificate Generator
--------------------
This script generates self-signed certificates for the secure reverse shell.
"""
import os
import subprocess

def generate_certificates():
    """Generate self-signed certificates for SSL/TLS encryption."""
    print("[*] Generating self-signed certificates...")
    
    if not os.path.exists("./certs"):
        os.makedirs("./certs")
    
    os.chdir("./certs")
    
    # Generate private key
    subprocess.run([
        "openssl", "genrsa", 
        "-out", "server.key", "2048"
    ], check=True)
    
    # Generate self-signed certificate (valid for 365 days)
    subprocess.run([
        "openssl", "req", "-new", 
        "-key", "server.key",
        "-out", "server.csr",
        "-subj", "/C=XX/ST=State/L=Locality/O=Organization/CN=localhost"
    ], check=True)
    
    subprocess.run([
        "openssl", "x509", "-req",
        "-days", "365", 
        "-in", "server.csr",
        "-signkey", "server.key",
        "-out", "server.crt"
    ], check=True)
    
    print("[*] Certificates created in the 'certs' directory")
    print("[*] server.crt - Certificate file")
    print("[*] server.key - Private key file")

if __name__ == "__main__":
    generate_certificates()