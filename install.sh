#!/usr/bin/env bash

# Exit immediately if a command exits with a non-zero status
set -e

INSTALL_DIR="/opt/namecheap"
SCRIPT_NAME="namecheap_hook.py"
CONFIG_NAME="namecheap.ini"

# Check if script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Error: Please run this installation script as root (using sudo)."
  exit 1
fi

echo "=== Installing Namecheap ACME Hook ==="

# Create installation directory
echo "Creating directory $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"

# Copy namecheap_hook.py
echo "Copying $SCRIPT_NAME to $INSTALL_DIR..."
cp "namecheap_hook.py" "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/$SCRIPT_NAME"

# Copy namecheap.ini if it doesn't already exist
if [ ! -f "$INSTALL_DIR/$CONFIG_NAME" ]; then
  echo "Copying configuration template to $INSTALL_DIR/$CONFIG_NAME..."
  cp "namecheap.ini.example" "$INSTALL_DIR/$CONFIG_NAME"
  chmod 600 "$INSTALL_DIR/$CONFIG_NAME"
  echo "Configuration template installed. Please edit it to set your API keys: $INSTALL_DIR/$CONFIG_NAME"
else
  echo "Configuration file $INSTALL_DIR/$CONFIG_NAME already exists. Skipping overwrite."
fi

# Install dependencies
echo "Installing python dependencies..."
if command -v pip3 >/dev/null 2>&1; then
  pip3 install -r requirements.txt
elif command -v pip >/dev/null 2>&1; then
  pip install -r requirements.txt
else
  echo "Warning: pip3/pip not found. Please install the dependencies in requirements.txt manually."
fi

echo "=== Installation Completed Successfully ==="
echo "Make sure to:"
echo "1. Whitelist your public IP address in your Namecheap Profile -> Tools -> Namecheap API Access."
echo "2. Edit $INSTALL_DIR/$CONFIG_NAME with your Namecheap API credentials."
echo "3. Test the hook with Certbot using:"
echo "   certbot certonly --manual --preferred-challenges dns \\"
echo "     --manual-auth-hook \"$INSTALL_DIR/$SCRIPT_NAME auth\" \\"
echo "     --manual-cleanup-hook \"$INSTALL_DIR/$SCRIPT_NAME cleanup\" \\"
echo "     -d example.com -d *.example.com"
