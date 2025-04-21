import streamlit as st
import socket
import os
import ssl
import sys
import time
import json
import bcrypt  # For secure password hashing
from auth import AuthDB  # Import the AuthDB class

# Configuration
HOST = ''    # Listen on all available interfaces
PORT = 9999  # Port for incoming connections

# Directory for SSL certificates
CERT_DIR = os.path.join(os.path.dirname(__file__), "./certs")
CERT_FILE = os.path.join(CERT_DIR, "server.crt")
KEY_FILE = os.path.join(CERT_DIR, "server.key")

# Directory for user authentication
AUTH_DIR = os.path.join(os.path.dirname(__file__), "./auth")
AUTH_FILE = os.path.join(AUTH_DIR, "auth.json")
auth_db: AuthDB = AuthDB(AUTH_FILE)


def log_message(message):
    """Appends a message to the session state log."""
    st.session_state.logs.append(f"[{time.strftime('%H:%M:%S')}] {message}")

def create_secure_server():
    """Create a secure server socket with SSL/TLS."""
    log_message("Attempting to create secure server...")
    try:
        # Check if certificates exist
        if not os.path.exists(CERT_DIR):
            os.makedirs(CERT_DIR)
            log_message(f"Created certificate directory: {CERT_DIR}")

        if not (os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE)):
            log_message("[!] SSL certificates not found.")
            log_message(f"[!] Expected at: {CERT_FILE} and {KEY_FILE}")
            log_message("[!] Please run generate_cert.py (in tmp or similar) and place certs in certs/ folder.")
            st.error("SSL certificates not found. Cannot start server.")
            return None

        # Create a standard socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Bind and listen
        server_socket.bind((HOST, PORT))
        server_socket.listen(1)
        log_message(f"[*] Server listening on port {PORT}")

        # Create SSL context
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

        # Wrap the socket with SSL
        ssl_server = context.wrap_socket(server_socket, server_side=True)
        log_message("[*] Server socket created and wrapped with SSL.")
        return ssl_server
    
    except Exception as e:
        log_message(f"[!] Error creating server: {e}")
        st.error(f"Error creating server: {e}")
        return None

def authenticate_client(client_socket):
    """Authenticate client using the user management system."""
    try:
        init_result = auth_db.init_user_store()
        if isinstance(init_result, str):
            log_message(init_result)
        
        # Send authentication request
        client_socket.send("AUTH_REQUIRED".encode('utf-8'))
        log_message("[*] Sent authentication request to client")

        # Receive credentials (with timeout)
        client_socket.settimeout(10.0) # 10 second timeout
        auth_data = client_socket.recv(1024).decode('utf-8')
        client_socket.settimeout(None) # Disable timeout

        if not auth_data:
            log_message("[!] No authentication data received")
            client_socket.send("AUTH_FAILED".encode('utf-8'))
            return False

        # Validate credentials
        try:
            username, password = auth_data.split(':', 1)
            username = username.strip()
            password = password.strip()

            if auth_db.verify_user(username, password):
                client_socket.send("AUTH_SUCCESS".encode('utf-8'))
                log_message(f"[*] Client authentication successful (username: {username})")
                # Store the authenticated username in session state
                st.session_state.current_user = username
                return True
            else:
                client_socket.send("AUTH_FAILED".encode('utf-8'))
                log_message(f"[!] Authentication failed (username: {username})")
                return False
        except Exception as e:
            client_socket.send("AUTH_ERROR".encode('utf-8'))
            log_message(f"[!] Authentication format error: {e}")
            return False
    except socket.timeout:
        log_message("[!] Authentication timed out.")
        return False
    except Exception as e:
        log_message(f"[!] Error during authentication: {e}")
        return False

#
# Streamlit UI
# 
st.set_page_config(page_title="Secure Reverse Shell",layout="wide", page_icon="🔐")
st.title("🔐 :rainbow[Secure Reverse Shell Server]")

# Initialize session state configss
if 'server_socket' not in st.session_state:
    st.session_state.server_socket = None
if 'client_socket' not in st.session_state:
    st.session_state.client_socket = None
if 'client_address' not in st.session_state:
    st.session_state.client_address = None
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'logs' not in st.session_state:
    st.session_state.logs = ["[*] UI Initialized."]
if 'output' not in st.session_state:
    st.session_state.output = ""
if 'command_processed' not in st.session_state:
    st.session_state.command_processed = False

# Initialize additional session state variables for user management
if 'user_management_tab' not in st.session_state:
    st.session_state.user_management_tab = "view"
if 'add_user_result' not in st.session_state:
    st.session_state.add_user_result = None
if 'delete_user_result' not in st.session_state:
    st.session_state.delete_user_result = None

# --- Server Config Cols ---
col1, col3 = st.columns(2)

with col1:
    st.subheader("⚙️ Server Configuration")
    if st.session_state.server_socket is None:
        if st.button("🟢 Start Server"):
            server = create_secure_server()
            if server:
                st.session_state.server_socket = server
                st.rerun() # Rerun to update UI state
            else:
                pass
    else:
        st.success(f"✅ Server Listening on Port {PORT}")
        if st.button("🔴 Stop Server"):
            log_message("[*] Stopping server...")
            if st.session_state.client_socket:
                try:
                    st.session_state.client_socket.close()
                except Exception as e:
                    log_message(f"[!] Error closing client socket: {e}")
            try:
                st.session_state.server_socket.close()
            except Exception as e:
                 log_message(f"[!] Error closing server socket: {e}")
            # Reset state
            st.session_state.server_socket = None
            st.session_state.client_socket = None
            st.session_state.client_address = None
            st.session_state.authenticated = False
            st.session_state.output = ""
            log_message("[*] Server stopped and state reset.")
            st.rerun()

with col1:
    if st.session_state.server_socket and st.session_state.client_socket is None:
        st.info("Server running. Waiting for client connection...")
        if st.button("⏳ Accept Connection (Blocks UI)"):
            log_message("[*] Waiting to accept client connection...")
            try:
                # NOTE: This will block the UI until a client connects
                client_conn, addr = st.session_state.server_socket.accept()
                st.session_state.client_socket = client_conn
                st.session_state.client_address = addr
                log_message(f"[*] Connection established from {addr[0]}:{addr[1]}")
                st.rerun()
            except Exception as e:
                log_message(f"[!] Error accepting connection: {e}")
                st.error(f"Failed to accept connection: {e}")

    elif st.session_state.client_socket and not st.session_state.authenticated:
        st.warning(f"🔌 Client Connected: {st.session_state.client_address[0]}:{st.session_state.client_address[1]}. Authenticating...")
        auth_success = authenticate_client(st.session_state.client_socket)
        if auth_success:
            st.session_state.authenticated = True
            st.success("🔑 Authentication Successful")
            st.rerun()
        else:
            log_message(f"[!] Authentication failed from {st.session_state.client_address[0]}:{st.session_state.client_address[1]}. Closing connection.")
            st.error("Authentication Failed. Connection closed.")
            try:
                st.session_state.client_socket.close()
            except Exception as e:
                 log_message(f"[!] Error closing client socket after failed auth: {e}")
            st.session_state.client_socket = None
            st.session_state.client_address = None
            st.session_state.authenticated = False
            st.rerun()

    elif st.session_state.authenticated:
        st.success(f"✅ Authenticated Client: {st.session_state.client_address[0]}:{st.session_state.client_address[1]}")
    else:
        st.info("Server not running or no client connected.")


with col3:
    st.subheader("🪵 Server Log")
    st.text_area("Logs", value="\n".join(st.session_state.logs), height=200, key="log_area", disabled=True)


st.divider()

#
# Command Interaction
# 
st.subheader("🖥️ Shell Command Prompt")
if st.session_state.authenticated:
    # Reset the command_processed flag when a new command is typed
    def on_input_change():
        st.session_state.command_processed = False
    
    command = st.text_input("Enter command:", key="command_input", 
                           placeholder="Type command and press Enter or click Send",
                           on_change=on_input_change)

    if st.button("➤ Send Command") or (command and not st.session_state.command_processed):
        if command:
            # Set the flag to prevent duplicate command sending (common issue)
            st.session_state.command_processed = True
            log_message(f"[*] Sending command: {command}")
            try:
                # Send the command to the client
                st.session_state.client_socket.sendall(command.encode('utf-8'))
                st.session_state.client_socket.sendall("\n".encode('utf-8'))

                # Exit if 'quit' command
                if command.lower() == "quit":
                    log_message("[*] 'quit' command sent. Closing connection...")
                    st.session_state.output += "\n[*] 'quit' command sent. Connection closed by server.\n"
                    try:
                        st.session_state.client_socket.close()
                    except Exception as e:
                        log_message(f"[!] Error closing client socket: {e}")
                    st.session_state.client_socket = None
                    st.session_state.client_address = None
                    st.session_state.authenticated = False
                    st.rerun()

                else:
                    # Wait for response (Blocks UI)
                    log_message("[*] Waiting for response...")
                    st.session_state.client_socket.settimeout(15.0) # 15 second timeout for response
                    response = st.session_state.client_socket.recv(65536).decode('utf-8', errors='ignore')
                    st.session_state.client_socket.settimeout(None) # Disable timeout
                    log_message("[*] Response received.")
                    st.session_state.output += f"Shell> {command}\n{response}\n"
                    st.session_state.command_processed = True
                    st.rerun() # Rerun to update output area

            except socket.timeout:
                log_message("[!] Command response timed out.")
                st.warning("Command response timed out.")
                st.session_state.output += f"Shell> {command}\n[!] Response timed out.\n"
                st.session_state.command_processed = True
                st.rerun()
            except Exception as e:
                log_message(f"[!] Error communicating with client: {e}")
                st.error(f"Communication Error: {e}. Closing connection.")
                st.session_state.output += f"Shell> {command}\n[!] Communication Error: {e}. Connection lost.\n"
                try:
                    st.session_state.client_socket.close()
                except Exception as close_e:
                    log_message(f"[!] Error closing client socket after comm error: {close_e}")
                st.session_state.client_socket = None
                st.session_state.client_address = None
                st.session_state.authenticated = False
                st.rerun()
        else:
            st.warning("Please enter a command.")

    st.text_area("Command Output", value=st.session_state.output, height=400, key="output_area", disabled=True)

else:
    st.info("Start the server, accept a connection, and authenticate a client to interact.")

# --- User Management Section ---
st.divider()
st.subheader("👥 User Management")

# Force refresh users data whenever this section is displayed
users = auth_db.get_users()
user_tab, add_tab, delete_tab = st.tabs(["View Users", "Add User", "Delete User"])

with user_tab:
    st.subheader("Current Users")
    
    # Refresh button to reload user data in case of inconsistent UI state changes
    if st.button("🔄 Refresh User List"):
        st.rerun()
    
    if users:
        user_data = []
        for username, data in users.items():
            user_data.append({
                "Username": username,
                "Admin": "✅" if data.get("is_admin", False) else "❌",
                "Created": data.get("created_at", "Unknown")
            })
            
        st.table(user_data)
    else:
        st.warning("No users found. Add a user to get started.")

with add_tab:
    st.subheader("Add New User")
    
    # Form for adding a new user
    with st.form("add_user_form"):
        new_username = st.text_input("Username", placeholder="Enter username (letters and numbers only)")
        new_password = st.text_input("Password", type="password", placeholder="Enter password")
        confirm_password = st.text_input("Confirm Password", type="password", placeholder="Confirm password")
        is_admin = st.checkbox("Admin User", value=False, help="Admin users can manage other users")
        
        submitted = st.form_submit_button("Add User")
        
        if submitted:
            if not new_username or not new_password:
                st.error("Username and password are required")
            elif new_password != confirm_password:
                st.error("Passwords do not match")
            else:
                success, message = auth_db.add_user(new_username, new_password, is_admin)
                if success:
                    st.success(message)
                    st.toast("✅ User added successfully")
                    log_message(f"[*] Added new user: {new_username} (admin: {is_admin})")
                else:
                    st.error(message)
                    st.toast("❗️ Oops! Something went wrong.")
                    log_message(f"[!] Error adding user: {message}")

with delete_tab:
    st.subheader("Delete User")
    
    users = auth_db.get_users()
    usernames = list(users.keys())
    
    if not usernames:
        st.warning("No users to delete")
    else:
        user_to_delete = st.selectbox("Select User to Delete", usernames)
        
        if st.button("Delete User", type="primary", use_container_width=True):
            if user_to_delete:
                current_user = st.session_state.get('current_user', None)
                success, message = auth_db.delete_user(user_to_delete, current_user)
                if success:
                    st.success(message)
                    st.toast("✅ User deleted successfully")
                    log_message(f"[*] Deleted user: {user_to_delete}")
                else:
                    st.error(message)
                    st.toast("❗️ Oops! Something went wrong.")
                    log_message(f"[!] Error deleting user: {message}")
            else:
                st.error("Please select a user to delete")

st.divider()