# Signer-Pro - Evasion and Delivery in 1 hand

A professional application for signing executable files and scripts (.exe, .py, etc.) using certificates from remote sources, with options for local saving or network distribution.
```bash
signer-pro.py
├── CertificateHandler (certificate operations)
├── FileSigner (signing operations)
├── NetworkSender (network transmission)
└── SignerUI (GUI interface)
```
## Features
- Download certificates from HTTPS URLs
- Sign files using SHA-256 with RSA encryption
- Save signatures to local Downloads directory
- Send signed files via IPv4/IPv6 networks
- Professional GUI with error handling
- Comprehensive logging

## Requirements
- Python 3.8+
- See `requirements.txt` for dependencies

## Installation
```bash
python -m venv signer-env
source signer-env/bin/activate  # Linux/Mac
signer-env\Scripts\activate      # Windows
pip install -r requirements.txt
python3 signer-pro.py    # Linux/Mac
python.exe signer-pro.py # Windows
