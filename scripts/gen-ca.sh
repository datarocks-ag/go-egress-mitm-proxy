#!/bin/bash

# Configuration
CA_DIR="./certs"
CA_KEY="$CA_DIR/ca.key"
CA_CRT="$CA_DIR/ca.crt"
CA_SUBJ="/C=US/ST=State/L=City/O=ProxyCorp/OU=Security/CN=Internal-MITM-CA"

# Create directory if not exists
mkdir -p $CA_DIR

echo "Generating Root CA Private Key..."
openssl genrsa -out $CA_KEY 4096

echo "Generating Root CA Certificate..."
openssl req -x509 -new -nodes -key $CA_KEY -sha256 -days 3650 -out $CA_CRT -subj "$CA_SUBJ"

echo "--------------------------------------------------"
echo "Done!"
echo "1. Provide '$CA_KEY' and '$CA_CRT' to your Go Proxy."
echo "2. IMPORTANT: Install '$CA_CRT' on your CLIENT machines"
echo "   (Browser, OS, or Docker) as a Trusted Root Authority."
echo "--------------------------------------------------"
