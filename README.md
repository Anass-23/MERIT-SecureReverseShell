# Secure Reverse Shell

A secure reverse shell application with authentication and encrypted communication.

## Description

This project implements a secure reverse shell system with the following features:
- Encrypted communication using SSL/TLS
- User authentication system
- Web-based UI using Streamlit
- Command-line interface options

## Prerequisites

- Python 3.11 or higher
- pip (Python package installer)

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/Anass-23/tmp-WirelessProject.git
cd tmp-WirelessProject
```

### 2. Set up a virtual environment (recommended)

```bash
# Create a virtual environment
python3.11 -m venv env

# Activate the virtual environment
# On macOS/Linux:
source env/bin/activate
# On Windows:
# env\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Generate SSL certificates

> NOTE: Before running the server, you need to generate SSL certificates:

```bash
python src/generate_cert.py
```

This will create the necessary certificate files in the `src/certs/` directory.

## Running the Application

### Option 1: Web-based UI (Recommended)

```bash
cd src
streamlit run server_ui.py
```

The Streamlit interface will open in your default web browser. From there, you can:
1. Start the server
2. Accept client connections
3. Authenticate clients
4. Send commands and view responses
5. Manage users (add/delete)

### Option 2: Command-line Interface

Server:
```bash
cd src
python server_cli.py
```

Client:
```bash
cd src
python client.py
```

### Using the startup script

Alternatively, you can use the provided startup script:

```bash
cd src
chmod +x start_server.sh
./start_server.sh
```

## Default Credentials

The system creates a default admin user on first run:
- Username: `admin`
- Password: `secure_admin_pwd_MERIT2025`

It's recommended to change this password after first login.

## Troubleshooting

### File Not Found Errors
If you encounter errors related to missing directories or files (like auth.json):
```
FileNotFoundError: [Errno 2] No such file or directory: './auth/auth.json'
```

Create the necessary directories manually:
```bash
mkdir -p src/auth
mkdir -p src/certs
```

### Certificate Errors
If you encounter SSL certificate errors, delete existing certificates and regenerate them:
```bash
rm -rf src/certs/
python src/generate_cert.py
```

## License

See the LICENSE file for details.