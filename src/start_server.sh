#!/bin/bash
# Start the Streamlit UI for the reverse shell server

# Change to the script directory
cd "$(dirname "$0")"

# Check if Python and required packages are installed
if ! command -v python3 &> /dev/null; then
    echo "Python 3 is not installed. Please install Python 3."
    exit 1
fi

if ! python3 -c "import streamlit" &> /dev/null; then
    echo "Streamlit is not installed. Installing now..."
    pip3 install streamlit
fi

# Start the Streamlit server
echo "Starting Streamlit server..."
streamlit run server_ui.py