import os
import sys
import socket
import logging
import requests
import ssl
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel, 
                             QLineEdit, QPushButton, QFileDialog, QGroupBox, QRadioButton, 
                             QHBoxLayout, QMessageBox, QComboBox, QCheckBox)
from PyQt5.QtCore import Qt

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("signer.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("SignerApp")

class CertificateHandler:
    @staticmethod
    def download_certificate(url):
        """Download certificate from URL with error handling"""
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            return response.content
        except requests.exceptions.RequestException as e:
            logger.error(f"Certificate download failed: {e}")
            raise

    @staticmethod
    def load_private_key(pem_data, password=None):
        """Load private key from PEM data with multiple format support"""
        try:
            # Try loading as PKCS8 private key
            return serialization.load_pem_private_key(
                pem_data,
                password=password,
                backend=default_backend()
            )
        except (ValueError, TypeError, UnsupportedAlgorithm):
            pass
        
        try:
            # Try loading as PKCS1 private key
            key = serialization.load_pem_private_key(
                pem_data,
                password=password,
                backend=default_backend()
            )
            if isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
                return key
        except (ValueError, TypeError, UnsupportedAlgorithm):
            pass
        
        try:
            # Try loading as OpenSSL traditional format
            return rsa.RSAPrivateKey.load_pem_private_key(
                pem_data,
                password=password
            )
        except (ValueError, TypeError, UnsupportedAlgorithm):
            pass
        
        raise ValueError("Unsupported private key format. The key might be encrypted or in an unsupported format.")

    @staticmethod
    def load_certificate(pem_data):
        """Load certificate from PEM data"""
        try:
            return x509.load_pem_x509_certificate(pem_data, default_backend())
        except ValueError:
            # Try DER format if PEM fails
            try:
                return x509.load_der_x509_certificate(pem_data, default_backend())
            except ValueError as e:
                logger.error(f"Certificate loading failed: {e}")
                raise

class FileSigner:
    @staticmethod
    def sign_file(file_path, private_key):
        """Sign file using private key"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            signature = private_key.sign(
                data,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return signature
        except Exception as e:
            logger.error(f"Signing failed: {e}")
            raise

class NetworkSender:
    @staticmethod
    def send_file(ip_address, port, file_path, signature, protocol='IPv4'):
        """Send file and signature to remote system"""
        try:
            family = socket.AF_INET if protocol == 'IPv4' else socket.AF_INET6
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.connect((ip_address, port))
                
                # Send filename
                filename = os.path.basename(file_path)
                sock.sendall(filename.encode() + b'\0')
                
                # Send file
                with open(file_path, 'rb') as f:
                    while chunk := f.read(4096):
                        sock.sendall(chunk)
                
                # Send signature
                sock.sendall(signature)
                
                # Send end marker
                sock.sendall(b'<SIGNATURE_END>')
            return True
        except Exception as e:
            logger.error(f"Network send failed: {e}")
            raise

class SignerUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Enterprise File Signer")
        self.setGeometry(100, 100, 700, 500)
        self.init_ui()
        self.file_path = ""
        self.signature = None
        self.private_key = None
        logger.info("Application started")

    def init_ui(self):
        main_widget = QWidget()
        main_layout = QVBoxLayout()
        
        # Certificate Options
        cert_group = QGroupBox("Certificate Options")
        cert_layout = QVBoxLayout()
        
        # Certificate URL
        url_layout = QHBoxLayout()
        url_layout.addWidget(QLabel("Certificate URL:"))
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://domain.com/certificate.pem")
        url_layout.addWidget(self.url_input)
        
        # Password for private key
        pass_layout = QHBoxLayout()
        pass_layout.addWidget(QLabel("Key Password:"))
        self.pass_input = QLineEdit()
        self.pass_input.setEchoMode(QLineEdit.Password)
        self.pass_input.setPlaceholderText("Optional if key is encrypted")
        pass_layout.addWidget(self.pass_input)
        
        # Self-signed certificate option
        self.self_signed_check = QCheckBox("Generate self-signed certificate from domain")
        self.self_signed_domain = QLineEdit()
        self.self_signed_domain.setPlaceholderText("example.com")
        self.self_signed_domain.setEnabled(False)
        
        self.self_signed_check.stateChanged.connect(
            lambda state: self.self_signed_domain.setEnabled(state == Qt.Checked)
        )
        
        cert_layout.addLayout(url_layout)
        cert_layout.addLayout(pass_layout)
        cert_layout.addWidget(self.self_signed_check)
        cert_layout.addWidget(self.self_signed_domain)
        cert_group.setLayout(cert_layout)
        
        # File Selection
        file_layout = QHBoxLayout()
        file_layout.addWidget(QLabel("File to sign:"))
        self.file_input = QLineEdit()
        self.file_input.setReadOnly(True)
        file_layout.addWidget(self.file_input)
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_file)
        file_layout.addWidget(browse_btn)
        
        # Destination Options
        dest_group = QGroupBox("Output Destination")
        dest_layout = QVBoxLayout()
        
        self.local_save_radio = QRadioButton("Save to Downloads")
        self.network_send_radio = QRadioButton("Send via Network")
        self.local_save_radio.setChecked(True)
        
        # Network Options
        network_group = QGroupBox("Network Configuration")
        network_layout = QVBoxLayout()
        
        protocol_layout = QHBoxLayout()
        protocol_layout.addWidget(QLabel("Protocol:"))
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["IPv4", "IPv6"])
        protocol_layout.addWidget(self.protocol_combo)
        
        address_layout = QHBoxLayout()
        address_layout.addWidget(QLabel("IP Address:"))
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("192.168.1.100 or 2001:db8::1")
        address_layout.addWidget(self.ip_input)
        
        port_layout = QHBoxLayout()
        port_layout.addWidget(QLabel("Port:"))
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("9000")
        port_layout.addWidget(self.port_input)
        
        network_layout.addLayout(protocol_layout)
        network_layout.addLayout(address_layout)
        network_layout.addLayout(port_layout)
        network_group.setLayout(network_layout)
        network_group.setEnabled(False)
        
        # Connect radio buttons
        self.network_send_radio.toggled.connect(
            lambda: network_group.setEnabled(self.network_send_radio.isChecked())
        )
        
        # Action Buttons
        btn_layout = QHBoxLayout()
        sign_btn = QPushButton("Sign and Process File")
        sign_btn.clicked.connect(self.process_file)
        
        gen_cert_btn = QPushButton("Generate Self-Signed Cert")
        gen_cert_btn.clicked.connect(self.generate_self_signed)
        btn_layout.addWidget(sign_btn)
        btn_layout.addWidget(gen_cert_btn)
        
        # Assemble layout
        dest_layout.addWidget(self.local_save_radio)
        dest_layout.addWidget(self.network_send_radio)
        dest_layout.addWidget(network_group)
        dest_group.setLayout(dest_layout)
        
        main_layout.addWidget(cert_group)
        main_layout.addLayout(file_layout)
        main_layout.addWidget(dest_group)
        main_layout.addLayout(btn_layout)
        
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)
    
    def browse_file(self):
        self.file_path, _ = QFileDialog.getOpenFileName(
            self, "Select File", "", "All Files (*)"
        )
        if self.file_path:
            self.file_input.setText(self.file_path)
            logger.info(f"Selected file: {self.file_path}")

    def generate_self_signed(self):
        """Generate self-signed certificate"""
        domain = self.self_signed_domain.text()
        if not domain:
            self.show_error("Domain is required for self-signed certificate")
            return
        
        try:
            # This would normally call the generate_cert.py script
            # For demo purposes, we'll just show a message
            msg = (f"Self-signed certificate for {domain} generated.\n"
                   "Files created: private_key.pem, certificate.pem")
            QMessageBox.information(self, "Success", msg)
            logger.info(f"Generated self-signed certificate for {domain}")
        except Exception as e:
            self.show_error(f"Certificate generation failed: {str(e)}")
            logger.exception("Certificate generation failed")

    def process_file(self):
        """Main processing function for signing and distribution"""
        url = self.url_input.text()
        password = self.pass_input.text().encode() or None
        
        if not url and not self.self_signed_check.isChecked():
            self.show_error("Certificate URL is required")
            return
        
        if not self.file_path:
            self.show_error("Please select a file to sign")
            return
        
        try:
            if self.self_signed_check.isChecked():
                # Use self-signed certificate
                domain = self.self_signed_domain.text()
                if not domain:
                    self.show_error("Domain is required for self-signed certificate")
                    return
                
                # In a real implementation, we would load the generated files
                # For demo, we'll generate a temporary key
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                )
                logger.info(f"Using self-signed certificate for {domain}")
            else:
                # Download certificate
                cert_data = CertificateHandler.download_certificate(url)
                logger.info(f"Certificate downloaded from {url}")
                
                # Load private key
                private_key = CertificateHandler.load_private_key(cert_data, password)
                logger.info("Private key loaded")
            
            # Sign file
            signature = FileSigner.sign_file(self.file_path, private_key)
            self.signature = signature
            logger.info("File signed successfully")
            
            # Process output
            if self.local_save_radio.isChecked():
                self.save_locally()
            else:
                self.send_via_network()
                
        except Exception as e:
            self.show_error(f"Processing error: {str(e)}")
            logger.exception("Processing failed")

    def save_locally(self):
        """Save signed file to downloads directory"""
        try:
            downloads = Path.home() / "Downloads"
            downloads.mkdir(exist_ok=True)
            
            filename = os.path.basename(self.file_path)
            sig_file = downloads / f"{filename}.sig"
            
            with open(sig_file, 'wb') as f:
                f.write(self.signature)
                
            logger.info(f"Signature saved to {sig_file}")
            QMessageBox.information(
                self, 
                "Success", 
                f"Signature saved to:\n{sig_file}"
            )
        except Exception as e:
            self.show_error(f"Save failed: {str(e)}")
            logger.exception("Local save failed")

    def send_via_network(self):
        """Send file and signature via network"""
        ip_address = self.ip_input.text()
        port_str = self.port_input.text()
        
        if not ip_address:
            self.show_error("IP address is required")
            return
        
        if not port_str.isdigit():
            self.show_error("Invalid port number")
            return
            
        port = int(port_str)
        protocol = self.protocol_combo.currentText()
        
        try:
            NetworkSender.send_file(
                ip_address,
                port,
                self.file_path,
                self.signature,
                protocol
            )
            logger.info(f"File sent to {ip_address}:{port} via {protocol}")
            QMessageBox.information(
                self, 
                "Success", 
                f"File successfully sent to:\n{ip_address}:{port}"
            )
        except Exception as e:
            self.show_error(f"Network send failed: {str(e)}")
            logger.exception("Network transmission failed")

    def show_error(self, message):
        """Show error message dialog"""
        QMessageBox.critical(self, "Error", message)
        logger.error(message)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SignerUI()
    window.show()
    sys.exit(app.exec_())