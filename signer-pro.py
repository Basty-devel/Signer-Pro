import hashlib
import json
import logging
import logging.handlers
import os
import random
import socket
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Tuple, Union

import requests
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from PyQt5.QtCore import QSettings, QSize, QThread, QTimer, Qt, pyqtSignal
from PyQt5.QtGui import QColor, QFont, QIcon, QPalette, QPixmap, QTextCursor
from PyQt5.QtWidgets import (QAction, QApplication, QCheckBox, QComboBox,
                             QDialog, QDialogButtonBox, QFileDialog, QFormLayout,
                             QGridLayout, QGroupBox, QHBoxLayout, QInputDialog,
                             QLabel, QLineEdit, QListWidget, QListWidgetItem,
                             QMainWindow, QMenu, QMessageBox, QProgressBar,
                             QPushButton, QRadioButton, QSizePolicy, QSplitter,
                             QStatusBar, QSystemTrayIcon, QTabWidget, QTextEdit,
                             QVBoxLayout, QWidget)

# Configure logging with rotation
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.handlers.RotatingFileHandler(
            "signer.log", maxBytes=10*1024*1024, backupCount=5
        ),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("EnterpriseSigner")

class CertificateTemplates:
    """Certificate templates for various software providers"""
    
    TEMPLATES = {
        "Custom": {
            "organization": "nestler.dev",
            "organizational_unit": "Security Division",
            "country": "GER",
            "state": "Saxony",
            "locality": "Chemnitz",
            "key_usage": {
                "digital_signature": True,
                "content_commitment": True,
                "key_encipherment": True,
                "data_encipherment": True,
                "key_agreement": True,
                "key_cert_sign": True,
                "crl_sign": True,
            },
            "extended_key_usage": [
                ExtendedKeyUsageOID.SERVER_AUTH,
                ExtendedKeyUsageOID.CLIENT_AUTH,
                ExtendedKeyUsageOID.CODE_SIGNING
            ],
            "basic_constraints": {"ca": True, "path_length": 0}
        },
        "Microsoft Defender Update": {
            "organization": "Microsoft Corporation",
            "organizational_unit": "Windows Defender",
            "country": "US",
            "state": "Washington",
            "locality": "Redmond",
            "key_usage": {
                "digital_signature": True,
                "content_commitment": True,
                "key_encipherment": True,
                "data_encipherment": False,
                "key_agreement": False,
                "key_cert_sign": False,
                "crl_sign": False,
            },
            "extended_key_usage": [
                ExtendedKeyUsageOID.CODE_SIGNING,
                ExtendedKeyUsageOID.TIME_STAMPING
            ],
            "basic_constraints": {"ca": False, "path_length": None}
        },
        "Google Chrome Security Update": {
            "organization": "Google LLC",
            "organizational_unit": "Chrome Security",
            "country": "US",
            "state": "California",
            "locality": "Mountain View",
            "key_usage": {
                "digital_signature": True,
                "content_commitment": True,
                "key_encipherment": True,
                "data_encipherment": False,
                "key_agreement": False,
                "key_cert_sign": False,
                "crl_sign": False,
            },
            "extended_key_usage": [
                ExtendedKeyUsageOID.CODE_SIGNING,
                ExtendedKeyUsageOID.EMAIL_PROTECTION
            ],
            "basic_constraints": {"ca": False, "path_length": None}
        },
        "Mozilla Firefox Security Update": {
            "organization": "Mozilla Corporation",
            "organizational_unit": "Firefox Security",
            "country": "US",
            "state": "California",
            "locality": "San Francisco",
            "key_usage": {
                "digital_signature": True,
                "content_commitment": True,
                "key_encipherment": True,
                "data_encipherment": False,
                "key_agreement": False,
                "key_cert_sign": False,
                "crl_sign": False,
            },
            "extended_key_usage": [
                ExtendedKeyUsageOID.CODE_SIGNING,
                ExtendedKeyUsageOID.EMAIL_PROTECTION
            ],
            "basic_constraints": {"ca": False, "path_length": None}
        },
        "Apple Security Update": {
            "organization": "Apple Inc.",
            "organizational_unit": "Software Security",
            "country": "US",
            "state": "California",
            "locality": "Cupertino",
            "key_usage": {
                "digital_signature": True,
                "content_commitment": True,
                "key_encipherment": True,
                "data_encipherment": False,
                "key_agreement": False,
                "key_cert_sign": False,
                "crl_sign": False,
            },
            "extended_key_usage": [
                ExtendedKeyUsageOID.CODE_SIGNING,
                ExtendedKeyUsageOID.TIME_STAMPING
            ],
            "basic_constraints": {"ca": False, "path_length": None}
        },
        "Kaspersky Antivirus Update": {
            "organization": "Kaspersky Lab",
            "organizational_unit": "Security Updates",
            "country": "RU",
            "state": "Moscow",
            "locality": "Moscow",
            "key_usage": {
                "digital_signature": True,
                "content_commitment": True,
                "key_encipherment": True,
                "data_encipherment": False,
                "key_agreement": False,
                "key_cert_sign": False,
                "crl_sign": False,
            },
            "extended_key_usage": [
                ExtendedKeyUsageOID.CODE_SIGNING,
                ExtendedKeyUsageOID.TIME_STAMPING
            ],
            "basic_constraints": {"ca": False, "path_length": None}
        },
        "Norton Antivirus Update": {
            "organization": "NortonLifeLock Inc.",
            "organizational_unit": "Security Updates",
            "country": "US",
            "state": "Arizona",
            "locality": "Tempe",
            "key_usage": {
                "digital_signature": True,
                "content_commitment": True,
                "key_encipherment": True,
                "data_encipherment": False,
                "key_agreement": False,
                "key_cert_sign": False,
                "crl_sign": False,
            },
            "extended_key_usage": [
                ExtendedKeyUsageOID.CODE_SIGNING,
                ExtendedKeyUsageOID.TIME_STAMPING
            ],
            "basic_constraints": {"ca": False, "path_length": None}
        },
        "McAfee Antivirus Update": {
            "organization": "McAfee LLC",
            "organizational_unit": "Security Updates",
            "country": "US",
            "state": "California",
            "locality": "San Jose",
            "key_usage": {
                "digital_signature": True,
                "content_commitment": True,
                "key_encipherment": True,
                "data_encipherment": False,
                "key_agreement": False,
                "key_cert_sign": False,
                "crl_sign": False,
            },
            "extended_key_usage": [
                ExtendedKeyUsageOID.CODE_SIGNING,
                ExtendedKeyUsageOID.TIME_STAMPING
            ],
            "basic_constraints": {"ca": False, "path_length": None}
        },
        "Bitdefender Antivirus Update": {
            "organization": "Bitdefender",
            "organizational_unit": "Security Updates",
            "country": "RO",
            "state": "Bucharest",
            "locality": "Bucharest",
            "key_usage": {
                "digital_signature": True,
                "content_commitment": True,
                "key_encipherment": True,
                "data_encipherment": False,
                "key_agreement": False,
                "key_cert_sign": False,
                "crl_sign": False,
            },
            "extended_key_usage": [
                ExtendedKeyUsageOID.CODE_SIGNING,
                ExtendedKeyUsageOID.TIME_STAMPING
            ],
            "basic_constraints": {"ca": False, "path_length": None}
        },
        "Avast Antivirus Update": {
            "organization": "Avast Software",
            "organizational_unit": "Security Updates",
            "country": "CZ",
            "state": "Prague",
            "locality": "Prague",
            "key_usage": {
                "digital_signature": True,
                "content_commitment": True,
                "key_encipherment": True,
                "data_encipherment": False,
                "key_agreement": False,
                "key_cert_sign": False,
                "crl_sign": False,
            },
            "extended_key_usage": [
                ExtendedKeyUsageOID.CODE_SIGNING,
                ExtendedKeyUsageOID.TIME_STAMPING
            ],
            "basic_constraints": {"ca": False, "path_length": None}
        }
    }

class ConfigurationManager:
    """Centralized configuration management for the application"""
    
    def __init__(self):
        self.settings = QSettings("EnterpriseSoft", "FileSignerPro")
        self.config_path = Path.home() / ".enterprise_signer" / "signer_config.json"
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self.load_config()
    
    def load_config(self) -> Dict[str, Any]:
        """Load configuration from file"""
        default_config = {
            "theme": "Fusion",
            "language": "en",
            "recent_files": [],
            "default_key_type": "rsa",
            "default_key_size": 4096,
            "default_algorithm": "SHA512",
            "network_timeout": 30,
            "chunk_size": 16384,
            "max_recent_files": 10,
            "window_geometry": None,
            "window_state": None,
            "last_directory": str(Path.home()),
            "dark_mode": False,
            "default_certificate_template": "Custom"
        }
        
        if self.config_path.exists():
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    loaded_config = json.load(f)
                    default_config.update(loaded_config)
            except Exception as e:
                logger.error(f"Error loading config: {e}")
        
        return default_config
    
    def save_config(self, config: Dict[str, Any]) -> bool:
        """Save configuration to file"""
        try:
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=4, ensure_ascii=False)
            return True
        except Exception as e:
            logger.error(f"Error saving config: {e}")
            return False
    
    def update_recent_files(self, file_path: str) -> None:
        """Update recent files list"""
        config = self.load_config()
        recent_files = config.get("recent_files", [])
        
        if file_path in recent_files:
            recent_files.remove(file_path)
        
        recent_files.insert(0, file_path)
        recent_files = recent_files[:config.get("max_recent_files", 10)]
        
        config["recent_files"] = recent_files
        self.save_config(config)
    
    def get_setting(self, key: str, default: Any = None) -> Any:
        """Get a specific setting"""
        config = self.load_config()
        return config.get(key, default)
    
    def set_setting(self, key: str, value: Any) -> bool:
        """Set a specific setting"""
        config = self.load_config()
        config[key] = value
        return self.save_config(config)

class SecurePasswordManager:
    """Secure password handling with hashing and verification"""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password using SHA-256 with salt"""
        salt = os.urandom(16)
        key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000
        )
        return salt.hex() + key.hex()
    
    @staticmethod
    def verify_password(stored_password: str, provided_password: str) -> bool:
        """Verify a password against its hash"""
        salt = bytes.fromhex(stored_password[:32])
        stored_key = stored_password[32:]
        
        key = hashlib.pbkdf2_hmac(
            'sha256',
            provided_password.encode('utf-8'),
            salt,
            100000
        )
        return key.hex() == stored_key

class CertificateGenerator:
    """Enhanced certificate generation with better validation and templates"""
    
    @staticmethod
    def generate_self_signed_cert(domain: str, key_type: str = 'rsa', 
                                 key_size: int = 4096, 
                                 template_name: str = "Custom") -> Tuple[Any, Any]:
        """Generate self-signed certificate with specified parameters and template"""
        if not domain or not isinstance(domain, str):
            raise ValueError("Invalid domain provided")
            
        # Get template
        template = CertificateTemplates.TEMPLATES.get(template_name, 
                                                    CertificateTemplates.TEMPLATES["Custom"])
            
        # Generate private key
        if key_type == 'rsa':
            if key_size not in [2048, 3072, 4096]:
                raise ValueError("Invalid RSA key size")
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
            )
        elif key_type == 'ecdsa':
            private_key = ec.generate_private_key(
                ec.SECP521R1(),
                backend=default_backend()
            )
        else:
            raise ValueError("Unsupported key type")

        # Create subject and issuer names based on template
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, domain),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, template["organization"]),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, template["organizational_unit"]),
            x509.NameAttribute(NameOID.COUNTRY_NAME, template["country"]),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, template["state"]),
            x509.NameAttribute(NameOID.LOCALITY_NAME, template["locality"]),
        ])

        # Build certificate with template settings
        cert_builder = x509.CertificateBuilder()
        cert_builder = (cert_builder
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(private_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.utcnow() - timedelta(days=1))  # Allow for clock skew
                .not_valid_after(datetime.utcnow() + timedelta(days=365)))
        
        # Add Basic Constraints
        bc = template["basic_constraints"]
        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=bc["ca"], path_length=bc["path_length"]),
            critical=True
        )
        
        # Add Key Usage
        ku = template["key_usage"]
        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(
                digital_signature=ku["digital_signature"],
                content_commitment=ku["content_commitment"],
                key_encipherment=ku["key_encipherment"],
                data_encipherment=ku["data_encipherment"],
                key_agreement=ku["key_agreement"],
                key_cert_sign=ku["key_cert_sign"],
                crl_sign=ku["crl_sign"],
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        
        # Add Extended Key Usage
        eku = template["extended_key_usage"]
        cert_builder = cert_builder.add_extension(
            x509.ExtendedKeyUsage(eku),
            critical=False
        )
        
        # Add Subject Alternative Name
        cert_builder = cert_builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(domain)]),
            critical=False
        )
        
        # Add Subject Key Identifier
        cert_builder = cert_builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False
        )
        
        # Add Authority Key Identifier
        cert_builder = cert_builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()),
            critical=False
        )
        
        # Sign the certificate
        cert = cert_builder.sign(private_key, hashes.SHA512(), default_backend())
        
        return private_key, cert

    @staticmethod
    def save_key_and_cert(private_key: Any, cert: Any, password: Optional[str] = None) -> Tuple[str, str]:
        """Save private key and certificate to files with timestamp"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Create secure output directory
        output_dir = Path.home() / ".enterprise_signer" / "generated_certs"
        output_dir.mkdir(exist_ok=True, mode=0o700)
        
        # Save private key
        key_file = output_dir / f"private_key_{timestamp}.pem"
        encryption = (serialization.BestAvailableEncryption(password.encode()) 
                     if password else serialization.NoEncryption())
        with open(key_file, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption
            ))
        
        # Save certificate
        cert_file = output_dir / f"certificate_{timestamp}.pem"
        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        # Set secure permissions
        key_file.chmod(0o600)
        cert_file.chmod(0o644)
        
        return str(key_file), str(cert_file)

class KeyManager:
    """Centralized key management with enhanced security"""
    
    def __init__(self):
        self.key_cache = {}  # In-memory key cache with timeout
    
    @staticmethod
    def download_key(url: str, timeout: int = 15) -> bytes:
        """Download private key from URL with enhanced security"""
        try:
            # Validate URL
            if not url.startswith(('https://', 'http://')):
                raise ValueError("Invalid URL scheme")
            

            # Define the user agent list separately
            user_agents = [
                'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
                'Mozilla/5.0 (compatible; bingbot/2.0 +http://www.bing.com/bingbot.htm)',
                'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
                'Mozilla/5.0 (Windows Phone 8.1; ARM; Trident/7.0; Touch; rv:11.0; IEMobile/11.0; NOKIA; Lumia 530) like Gecko (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
                'Mozilla/5.0 (iPhone; CPU iPhone OS 7_0 like Mac OS X) AppleWebKit/537.51.1 (KHTML, like Gecko) Version/7.0 Mobile/11A465 Safari/9537.53 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
                'msnbot/2.0b (+http://search.msn.com/msnbot.htm)',
                'msnbot-media/1.1 (+http://search.msn.com/msnbot.htm)',
                'Mozilla/5.0 (compatible; adidxbot/2.0; +http://www.bing.com/bingbot.htm)',
                'Mozilla/5.0 (iPhone; CPU iPhone OS 7_0 like Mac OS X) AppleWebKit/537.51.1 (KHTML, like Gecko) Version/7.0 Mobile/11A465 Safari/9537.53 (compatible; adidxbot/2.0; +http://www.bing.com/bingbot.htm)',
                'Mozilla/5.0 (Windows Phone 8.1; ARM; Trident/7.0; Touch; rv:11.0; IEMobile/11.0; NOKIA; Lumia 530) like Gecko (compatible; adidxbot/2.0; +http://www.bing.com/bingbot.htm)',
                'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/534+ (KHTML, like Gecko) BingPreview/1.0b',
                'Mozilla/5.0 (Windows Phone 8.1; ARM; Trident/7.0; Touch; rv:11.0; IEMobile/11.0; NOKIA; Lumia 530) like Gecko BingPreview/1.0b',
                'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)',
                'Mozilla/2.0 (compatible; Ask Jeeves/Teoma; +http://sp.ask.com/docs/about/tech_crawling.html)',
                'Mozilla/2.0 (compatible; Ask Jeeves/Teoma; +http://about.ask.com/en/docs/about/webmasters.shtml)',
                'Mozilla/2.0 (compatible; Ask Jeeves/Teoma)',
                'Mozilla/5.0 (compatible; Ask Jeeves/Teoma; +http://about.ask.com/en/docs/about/webmasters.shtml)',
                'Googlebot/2.1 (+http://www.googlebot.com/bot.html)',
                'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
                'Googlebot/2.1 (+http://www.google.com/bot.html)',
                'Googlebot-News',
                'Googlebot-Image/1.0',
                'Googlebot-Video/1.0',
                'SAMSUNG-SGH-E250/1.0 Profile/MIDP-2.0 Configuration/CLDC-1.1 UP.Browser/6.2.3.3.c.1.101 (GUI) MMP/2.0 (compatible; Googlebot-Mobile/2.1; +http://www.google.com/bot.html)',
                'DoCoMo/2.0 N905i(c100;TB;W24H16) (compatible; Googlebot-Mobile/2.1; +http://www.google.com/bot.html)',
                'Mozilla/5.0 (iPhone; CPU iPhone OS 8_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12F70 Safari/600.1.4 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
                '[various mobile device types] (compatible; Mediapartners-Google/2.1; +http://www.google.com/bot.html)',
                'Mediapartners-Google',
                'AdsBot-Google (+http://www.google.com/adsbot.html)'
            ]

            # Make the request with a random user agent
            response = requests.get(
                url, 
                timeout=timeout,
                verify=True,
                headers={
                    'User-Agent': random.choice(user_agents),
                    'Accept': 'application/x-pem-file'
                }
            )

            # Check for HTTP errors
            response.raise_for_status()
            
            
            # Verify content looks like a key
            content = response.content
            if (b"BEGIN PRIVATE KEY" not in content and 
                b"BEGIN RSA PRIVATE KEY" not in content and
                b"BEGIN EC PRIVATE KEY" not in content):
                raise ValueError("Downloaded content doesn't appear to be a private key")
                
            return content
        except requests.exceptions.RequestException as e:
            logger.error(f"Key download failed: {e}")
            raise
    
    @staticmethod
    def load_private_key(pem_data: bytes, password: Optional[str] = None) -> Any:
        """Load private key from PEM data with enhanced error handling"""
        try:
            return serialization.load_pem_private_key(
                pem_data,
                password=password.encode() if password else None,
                backend=default_backend()
            )
        except (ValueError, TypeError, UnsupportedAlgorithm) as e:
            logger.error(f"Key loading failed: {e}")
            raise ValueError("Invalid key format or password") from e

class FileSigner:
    """Enhanced file signing with support for multiple algorithms"""
    
    SIGNATURE_ALGORITHMS = {
        'SHA256': hashes.SHA256(),
        'SHA384': hashes.SHA384(),
        'SHA512': hashes.SHA512()
    }
    
    @staticmethod
    def sign_file(file_path: Union[str, Path], private_key: Any, algorithm: str = 'SHA512') -> bytes:
        """Sign file using private key with algorithm selection"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
            
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Select hash algorithm
            hash_alg = FileSigner.SIGNATURE_ALGORITHMS.get(algorithm)
            if not hash_alg:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
            
            # Create signature based on key type
            if isinstance(private_key, rsa.RSAPrivateKey):
                signature = private_key.sign(
                    data,
                    padding.PSS(
                        mgf=padding.MGF1(hash_alg),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hash_alg
                )
            elif isinstance(private_key, ec.EllipticCurvePrivateKey):
                signature = private_key.sign(
                    data,
                    ec.ECDSA(hash_alg)
                )
            else:
                raise UnsupportedAlgorithm("Unsupported private key type")
            
            return signature
        except Exception as e:
            logger.error(f"Signing failed: {e}")
            raise

class NetworkManager:
    """Enhanced network operations with timeout and retry logic"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.timeout = config.get('network_timeout', 30)
        self.chunk_size = config.get('chunk_size', 16384)
    
    def send_file(self, ip_address: str, port: int, file_path: Union[str, Path], 
                 signature: bytes, protocol: str = 'IPv4') -> Generator[int, None, None]:
        """Send file and signature to remote system with progress tracking"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
            
        try:
            family = socket.AF_INET if protocol == 'IPv4' else socket.AF_INET6
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((ip_address, port))
                
                # Send metadata (filename, filesize, signature size)
                filename = os.path.basename(file_path)
                file_size = os.path.getsize(file_path)
                metadata = f"{filename}|{file_size}|{len(signature)}".encode()
                sock.sendall(metadata + b'\n')
                
                # Send file in chunks
                sent_bytes = 0
                with open(file_path, 'rb') as f:
                    while sent_bytes < file_size:
                        chunk = f.read(self.chunk_size)
                        if not chunk:
                            break
                        sock.sendall(chunk)
                        sent_bytes += len(chunk)
                        yield int(sent_bytes / file_size * 80)  # 80% of progress
                
                # Send signature
                sock.sendall(signature)
                yield 95  # 95% progress
                
                # Send hash verification
                with open(file_path, 'rb') as f:
                    file_hash = hashlib.sha512(f.read()).hexdigest().encode()
                sock.sendall(file_hash)
                yield 100  # 100% progress
                
        except Exception as e:
            logger.error(f"Network send failed: {e}")
            raise

class SigningThread(QThread):
    """Thread for handling signing operations with enhanced error handling"""
    
    progress = pyqtSignal(int)
    message = pyqtSignal(str)
    finished = pyqtSignal(bool, str)
    error = pyqtSignal(str)

    def __init__(self, operation_type: str, parameters: Dict[str, Any], 
                 config_manager: ConfigurationManager, parent=None):
        super().__init__(parent)
        self.operation_type = operation_type
        self.parameters = parameters
        self.config_manager = config_manager
        self.is_running = True

    def run(self):
        try:
            if self.operation_type == 'sign':
                self._sign_file()
            elif self.operation_type == 'generate_cert':
                self._generate_certificate()
            else:
                self.error.emit(f"Unknown operation type: {self.operation_type}")
        except Exception as e:
            self.error.emit(str(e))
        finally:
            self.is_running = False

    def _sign_file(self):
        params = self.parameters
        self.message.emit("Starting signing process...")
        
        # Load or generate private key
        if params['self_signed']:
            self.message.emit("Generating self-signed certificate...")
            private_key, cert = CertificateGenerator.generate_self_signed_cert(
                params['domain'],
                params['key_type'],
                params['key_size'],
                params.get('certificate_template', 'Custom')
            )
            self.progress.emit(20)
        else:
            self.message.emit(f"Downloading key from {params['key_url']}...")
            key_data = KeyManager.download_key(params['key_url'])
            self.progress.emit(15)
            
            self.message.emit("Loading private key...")
            private_key = KeyManager.load_private_key(key_data, params['password'])
            self.progress.emit(30)
        
        # Sign file
        self.message.emit(f"Signing file: {params['file_path']}...")
        signature = FileSigner.sign_file(
            params['file_path'], 
            private_key,
            params['sign_algorithm']
        )
        self.progress.emit(60)
        
        # Handle output
        if params['output_type'] == 'local':
            self.message.emit("Saving signature locally...")
            self._save_signature_locally(signature)
        else:
            self.message.emit("Sending file over network...")
            self._send_over_network(signature)
        
        self.progress.emit(100)
        self.message.emit("Operation completed successfully")

    def _save_signature_locally(self, signature: bytes):
        params = self.parameters
        try:
            # Create signatures directory if it doesn't exist
            output_dir = Path(params.get('output_dir', Path.home() / "Signatures"))
            output_dir.mkdir(parents=True, exist_ok=True)
            
            filename = os.path.basename(params['file_path'])
            sig_file = output_dir / f"{filename}.sig"
            
            with open(sig_file, 'wb') as f:
                f.write(signature)
                
            # Update recent files
            self.config_manager.update_recent_files(str(sig_file))
                
            self.finished.emit(True, f"Signature saved to:\n{sig_file}")
        except Exception as e:
            self.error.emit(f"Save failed: {str(e)}")

    def _send_over_network(self, signature: bytes):
        params = self.parameters
        try:
            network_manager = NetworkManager(self.config_manager.load_config())
            
            for progress in network_manager.send_file(
                params['ip_address'],
                params['port'],
                params['file_path'],
                signature,
                params['protocol']
            ):
                self.progress.emit(progress)
                if not self.is_running:
                    break
            
            self.finished.emit(True, 
                f"File successfully sent to:\n{params['ip_address']}:{params['port']}")
        except Exception as e:
            self.error.emit(f"Network send failed: {str(e)}")

    def _generate_certificate(self):
        params = self.parameters
        self.message.emit("Generating self-signed certificate...")
        private_key, cert = CertificateGenerator.generate_self_signed_cert(
            params['domain'],
            params['key_type'],
            params['key_size'],
            params.get('certificate_template', 'Custom')
        )
        self.progress.emit(50)
        
        self.message.emit("Saving certificate and key...")
        key_file, cert_file = CertificateGenerator.save_key_and_cert(
            private_key, 
            cert,
            params['password']
        )
        self.progress.emit(100)
        
        self.finished.emit(True, 
            f"Certificate generated successfully!\n"
            f"Private Key: {key_file}\n"
            f"Certificate: {cert_file}")

class PasswordDialog(QDialog):
    """Dialog for entering password securely"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Enter Password")
        self.setModal(True)
        self.password = None
        
        layout = QVBoxLayout(self)
        
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        layout.addWidget(QLabel("Password:"))
        layout.addWidget(self.password_edit)
        
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
    
    def get_password(self) -> Optional[str]:
        """Get the entered password"""
        if self.exec_() == QDialog.Accepted:
            return self.password_edit.text()
        return None

class AboutDialog(QDialog):
    """About dialog showing application information"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("About Enterprise Signer Pro")
        self.setFixedSize(400, 300)
        
        layout = QVBoxLayout(self)
        
        # Application title
        title = QLabel("Enterprise Signer Pro")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title.setFont(title_font)
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        
        # Version
        version = QLabel("Version 2.0")
        version.setAlignment(Qt.AlignCenter)
        layout.addWidget(version)
        
        # Description
        description = QLabel(
            "Enterprise-grade file signing and certificate generation tool\n\n"
            "© 2023 EnterpriseSoft. All rights reserved.\n\n"
            "This software provides secure file signing capabilities with support for "
            "both RSA and ECDSA algorithms, self-signed certificate generation, and "
            "secure network transmission of signed files."
        )
        description.setWordWrap(True)
        description.setAlignment(Qt.AlignCenter)
        layout.addWidget(description)
        
        # Close button
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

class SignerUI(QMainWindow):
    """Main application UI"""
    
    def __init__(self, config_manager: ConfigurationManager):
        super().__init__()
        self.config_manager = config_manager
        self.config = config_manager.load_config()
        self.signing_thread = None
        self.setup_ui()
        self.apply_settings()
        
    def setup_ui(self):
        """Set up the main user interface"""
        self.setWindowTitle("Enterprise Signer Pro")
        self.setMinimumSize(800, 600)
        
        # Central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Create tabs
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)
        
        # File signing tab
        self.setup_signing_tab()
        
        # Certificate generation tab
        self.setup_certificate_tab()
        
        # Settings tab
        self.setup_settings_tab()
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.status_bar.addPermanentWidget(self.progress_bar)
        
        # Menu bar
        self.setup_menu_bar()
        
        # Apply saved window geometry
        if self.config.get('window_geometry'):
            self.restoreGeometry(self.config['window_geometry'])
        if self.config.get('window_state'):
            self.restoreState(self.config['window_state'])
    
    def setup_signing_tab(self):
        """Set up the file signing tab"""
        signing_tab = QWidget()
        layout = QVBoxLayout(signing_tab)
        
        # File selection
        file_group = QGroupBox("File to Sign")
        file_layout = QHBoxLayout(file_group)
        self.file_path_edit = QLineEdit()
        self.file_path_edit.setPlaceholderText("Select a file to sign...")
        file_browse_btn = QPushButton("Browse...")
        file_browse_btn.clicked.connect(self.browse_file)
        file_layout.addWidget(self.file_path_edit)
        file_layout.addWidget(file_browse_btn)
        layout.addWidget(file_group)
        
        # Key options
        key_group = QGroupBox("Signing Key")
        key_layout = QFormLayout(key_group)
        
        self.self_signed_radio = QRadioButton("Generate self-signed certificate")
        self.external_key_radio = QRadioButton("Use external key")
        self.self_signed_radio.setChecked(True)
        self.self_signed_radio.toggled.connect(self.toggle_key_options)
        
        key_type_layout = QHBoxLayout()
        self.key_type_combo = QComboBox()
        self.key_type_combo.addItems(["RSA", "ECDSA"])
        self.key_size_combo = QComboBox()
        self.key_size_combo.addItems(["2048", "3072", "4096"])
        self.key_size_combo.setCurrentText(str(self.config.get('default_key_size', 4096)))
        key_type_layout.addWidget(QLabel("Key Type:"))
        key_type_layout.addWidget(self.key_type_combo)
        key_type_layout.addWidget(QLabel("Key Size:"))
        key_type_layout.addWidget(self.key_size_combo)
        key_type_layout.addStretch()
        
        self.key_url_edit = QLineEdit()
        self.key_url_edit.setPlaceholderText("https://example.com/key.pem")
        self.key_url_edit.setEnabled(False)
        
        key_layout.addRow(self.self_signed_radio)
        key_layout.addRow(self.external_key_radio)
        key_layout.addRow(key_type_layout)
        key_layout.addRow("Key URL:", self.key_url_edit)
        layout.addWidget(key_group)
        
        # Certificate template selection
        template_layout = QHBoxLayout()
        template_layout.addWidget(QLabel("Certificate Template:"))
        self.template_combo = QComboBox()
        self.template_combo.addItems(list(CertificateTemplates.TEMPLATES.keys()))
        self.template_combo.setCurrentText(self.config.get('default_certificate_template', 'Custom'))
        template_layout.addWidget(self.template_combo)
        template_layout.addStretch()
        layout.addLayout(template_layout)
        
        # Domain for self-signed
        domain_layout = QHBoxLayout()
        domain_layout.addWidget(QLabel("Domain:"))
        self.domain_edit = QLineEdit()
        self.domain_edit.setPlaceholderText("example.com")
        domain_layout.addWidget(self.domain_edit)
        layout.addLayout(domain_layout)
        
        # Algorithm selection
        algo_layout = QHBoxLayout()
        algo_layout.addWidget(QLabel("Signing Algorithm:"))
        self.algorithm_combo = QComboBox()
        self.algorithm_combo.addItems(["SHA256", "SHA384", "SHA512"])
        self.algorithm_combo.setCurrentText(self.config.get('default_algorithm', 'SHA512'))
        algo_layout.addWidget(self.algorithm_combo)
        algo_layout.addStretch()
        layout.addLayout(algo_layout)
        
        # Output options
        output_group = QGroupBox("Output")
        output_layout = QVBoxLayout(output_group)
        
        self.local_output_radio = QRadioButton("Save signature locally")
        self.network_output_radio = QRadioButton("Send over network")
        self.local_output_radio.setChecked(True)
        self.local_output_radio.toggled.connect(self.toggle_output_options)
        
        self.output_dir_edit = QLineEdit()
        self.output_dir_edit.setPlaceholderText(str(Path.home() / "Signatures"))
        output_dir_browse_btn = QPushButton("Browse...")
        output_dir_browse_btn.clicked.connect(self.browse_output_dir)
        
        output_dir_layout = QHBoxLayout()
        output_dir_layout.addWidget(self.output_dir_edit)
        output_dir_layout.addWidget(output_dir_browse_btn)
        
        network_layout = QFormLayout()
        self.ip_address_edit = QLineEdit()
        self.ip_address_edit.setPlaceholderText("192.168.1.100")
        self.port_edit = QLineEdit()
        self.port_edit.setPlaceholderText("8080")
        self.port_edit.setText("8080")
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["IPv4", "IPv6"])
        
        network_layout.addRow("IP Address:", self.ip_address_edit)
        network_layout.addRow("Port:", self.port_edit)
        network_layout.addRow("Protocol:", self.protocol_combo)
        
        output_layout.addWidget(self.local_output_radio)
        output_layout.addLayout(output_dir_layout)
        output_layout.addWidget(self.network_output_radio)
        output_layout.addLayout(network_layout)
        layout.addWidget(output_group)
        
        # Sign button
        sign_btn = QPushButton("Sign File")
        sign_btn.clicked.connect(self.start_signing)
        layout.addWidget(sign_btn)
        
        layout.addStretch()
        self.tabs.addTab(signing_tab, "File Signing")
    
    def setup_certificate_tab(self):
        """Set up the certificate generation tab"""
        cert_tab = QWidget()
        layout = QVBoxLayout(cert_tab)
        
        # Domain
        domain_layout = QFormLayout()
        self.cert_domain_edit = QLineEdit()
        self.cert_domain_edit.setPlaceholderText("example.com")
        domain_layout.addRow("Domain:", self.cert_domain_edit)
        layout.addLayout(domain_layout)
        
        # Certificate template selection
        template_layout = QHBoxLayout()
        template_layout.addWidget(QLabel("Certificate Template:"))
        self.cert_template_combo = QComboBox()
        self.cert_template_combo.addItems(list(CertificateTemplates.TEMPLATES.keys()))
        self.cert_template_combo.setCurrentText(self.config.get('default_certificate_template', 'Custom'))
        template_layout.addWidget(self.cert_template_combo)
        template_layout.addStretch()
        layout.addLayout(template_layout)
        
        # Key options
        key_options_layout = QHBoxLayout()
        key_options_layout.addWidget(QLabel("Key Type:"))
        self.cert_key_type_combo = QComboBox()
        self.cert_key_type_combo.addItems(["RSA", "ECDSA"])
        key_options_layout.addWidget(self.cert_key_type_combo)
        key_options_layout.addWidget(QLabel("Key Size:"))
        self.cert_key_size_combo = QComboBox()
        self.cert_key_size_combo.addItems(["2048", "3072", "4096"])
        self.cert_key_size_combo.setCurrentText(str(self.config.get('default_key_size', 4096)))
        key_options_layout.addWidget(self.cert_key_size_combo)
        key_options_layout.addStretch()
        layout.addLayout(key_options_layout)
        
        # Password protection
        password_layout = QHBoxLayout()
        self.password_checkbox = QCheckBox("Password protect private key")
        self.password_checkbox.toggled.connect(self.toggle_password_fields)
        password_layout.addWidget(self.password_checkbox)
        layout.addLayout(password_layout)
        
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_edit.setEnabled(False)
        self.confirm_password_edit = QLineEdit()
        self.confirm_password_edit.setEchoMode(QLineEdit.Password)
        self.confirm_password_edit.setEnabled(False)
        
        password_form = QFormLayout()
        password_form.addRow("Password:", self.password_edit)
        password_form.addRow("Confirm Password:", self.confirm_password_edit)
        layout.addLayout(password_form)
        
        # Generate button
        generate_btn = QPushButton("Generate Certificate")
        generate_btn.clicked.connect(self.generate_certificate)
        layout.addWidget(generate_btn)
        
        layout.addStretch()
        self.tabs.addTab(cert_tab, "Certificate Generation")
    
    def setup_settings_tab(self):
        """Set up the settings tab"""
        settings_tab = QWidget()
        layout = QVBoxLayout(settings_tab)
        
        # Theme selection
        theme_layout = QHBoxLayout()
        theme_layout.addWidget(QLabel("Theme:"))
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Fusion", "Windows", "WindowsVista"])
        self.theme_combo.setCurrentText(self.config.get('theme', 'Fusion'))
        self.theme_combo.currentTextChanged.connect(self.change_theme)
        theme_layout.addWidget(self.theme_combo)
        theme_layout.addStretch()
        layout.addLayout(theme_layout)
        
        # Dark mode
        self.dark_mode_checkbox = QCheckBox("Enable dark mode")
        self.dark_mode_checkbox.setChecked(self.config.get('dark_mode', False))
        self.dark_mode_checkbox.toggled.connect(self.toggle_dark_mode)
        layout.addWidget(self.dark_mode_checkbox)
        
        # Network settings
        network_group = QGroupBox("Network Settings")
        network_layout = QFormLayout(network_group)
        
        self.timeout_edit = QLineEdit()
        self.timeout_edit.setText(str(self.config.get('network_timeout', 30)))
        network_layout.addRow("Timeout (seconds):", self.timeout_edit)
        
        self.chunk_size_edit = QLineEdit()
        self.chunk_size_edit.setText(str(self.config.get('chunk_size', 16384)))
        network_layout.addRow("Chunk Size (bytes):", self.chunk_size_edit)
        
        layout.addWidget(network_group)
        
        # Default settings
        defaults_group = QGroupBox("Default Settings")
        defaults_layout = QFormLayout(defaults_group)
        
        self.default_key_type_combo = QComboBox()
        self.default_key_type_combo.addItems(["RSA", "ECDSA"])
        self.default_key_type_combo.setCurrentText(
            "RSA" if self.config.get('default_key_type', 'rsa') == 'rsa' else "ECDSA"
        )
        defaults_layout.addRow("Default Key Type:", self.default_key_type_combo)
        
        self.default_key_size_combo = QComboBox()
        self.default_key_size_combo.addItems(["2048", "3072", "4096"])
        self.default_key_size_combo.setCurrentText(str(self.config.get('default_key_size', 4096)))
        defaults_layout.addRow("Default Key Size:", self.default_key_size_combo)
        
        self.default_algorithm_combo = QComboBox()
        self.default_algorithm_combo.addItems(["SHA256", "SHA384", "SHA512"])
        self.default_algorithm_combo.setCurrentText(self.config.get('default_algorithm', 'SHA512'))
        defaults_layout.addRow("Default Algorithm:", self.default_algorithm_combo)
        
        self.default_template_combo = QComboBox()
        self.default_template_combo.addItems(list(CertificateTemplates.TEMPLATES.keys()))
        self.default_template_combo.setCurrentText(self.config.get('default_certificate_template', 'Custom'))
        defaults_layout.addRow("Default Template:", self.default_template_combo)
        
        layout.addWidget(defaults_group)
        
        # Save settings button
        save_btn = QPushButton("Save Settings")
        save_btn.clicked.connect(self.save_settings)
        layout.addWidget(save_btn)
        
        layout.addStretch()
        self.tabs.addTab(settings_tab, "Settings")
    
    def setup_menu_bar(self):
        """Set up the menu bar"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("File")
        
        open_action = QAction("Open File", self)
        open_action.setShortcut("Ctrl+O")
        open_action.triggered.connect(self.browse_file)
        file_menu.addAction(open_action)
        
        exit_action = QAction("Exit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Help menu
        help_menu = menubar.addMenu("Help")
        
        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
    
    def apply_settings(self):
        """Apply current settings to the UI"""
        # Apply theme
        QApplication.setStyle(self.config.get("theme", "Fusion"))
        
        # Apply dark mode if enabled
        if self.config.get('dark_mode', False):
            self.apply_dark_theme()
    
    def apply_dark_theme(self):
        """Apply a dark theme to the application"""
        dark_palette = QPalette()
        dark_palette.setColor(QPalette.Window, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.WindowText, Qt.white)
        dark_palette.setColor(QPalette.Base, QColor(25, 25, 25))
        dark_palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ToolTipBase, Qt.white)
        dark_palette.setColor(QPalette.ToolTipText, Qt.white)
        dark_palette.setColor(QPalette.Text, Qt.white)
        dark_palette.setColor(QPalette.Button, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ButtonText, Qt.white)
        dark_palette.setColor(QPalette.BrightText, Qt.red)
        dark_palette.setColor(QPalette.Link, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.HighlightedText, Qt.black)
        
        QApplication.setPalette(dark_palette)
    
    def toggle_key_options(self, checked):
        """Toggle key options based on selection"""
        is_self_signed = self.self_signed_radio.isChecked()
        self.key_url_edit.setEnabled(not is_self_signed)
        self.domain_edit.setEnabled(is_self_signed)
        self.key_type_combo.setEnabled(is_self_signed)
        self.key_size_combo.setEnabled(is_self_signed)
        self.template_combo.setEnabled(is_self_signed)
    
    def toggle_output_options(self, checked):
        """Toggle output options based on selection"""
        is_local = self.local_output_radio.isChecked()
        self.output_dir_edit.setEnabled(is_local)
        self.ip_address_edit.setEnabled(not is_local)
        self.port_edit.setEnabled(not is_local)
        self.protocol_combo.setEnabled(not is_local)
    
    def toggle_password_fields(self, checked):
        """Toggle password fields based on checkbox"""
        self.password_edit.setEnabled(checked)
        self.confirm_password_edit.setEnabled(checked)
    
    def browse_file(self):
        """Browse for a file to sign"""
        last_dir = self.config.get('last_directory', str(Path.home()))
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select File to Sign", last_dir
        )
        if file_path:
            self.file_path_edit.setText(file_path)
            self.config_manager.set_setting('last_directory', os.path.dirname(file_path))
    
    def browse_output_dir(self):
        """Browse for an output directory"""
        last_dir = self.config.get('last_directory', str(Path.home()))
        dir_path = QFileDialog.getExistingDirectory(
            self, "Select Output Directory", last_dir
        )
        if dir_path:
            self.output_dir_edit.setText(dir_path)
    
    def start_signing(self):
        """Start the file signing process"""
        # Validate inputs
        if not self.file_path_edit.text():
            QMessageBox.warning(self, "Error", "Please select a file to sign.")
            return
        
        if self.self_signed_radio.isChecked() and not self.domain_edit.text():
            QMessageBox.warning(self, "Error", "Please enter a domain for the self-signed certificate.")
            return
        
        if self.external_key_radio.isChecked() and not self.key_url_edit.text():
            QMessageBox.warning(self, "Error", "Please enter a key URL.")
            return
        
        if self.network_output_radio.isChecked():
            if not self.ip_address_edit.text():
                QMessageBox.warning(self, "Error", "Please enter an IP address.")
                return
            if not self.port_edit.text().isdigit():
                QMessageBox.warning(self, "Error", "Please enter a valid port number.")
                return
        
        # Prepare parameters
        params = {
            'file_path': self.file_path_edit.text(),
            'self_signed': self.self_signed_radio.isChecked(),
            'key_type': self.key_type_combo.currentText().lower(),
            'key_size': int(self.key_size_combo.currentText()),
            'key_url': self.key_url_edit.text(),
            'domain': self.domain_edit.text(),
            'certificate_template': self.template_combo.currentText(),
            'sign_algorithm': self.algorithm_combo.currentText(),
            'output_type': 'local' if self.local_output_radio.isChecked() else 'network',
            'output_dir': self.output_dir_edit.text() or str(Path.home() / "Signatures"),
            'ip_address': self.ip_address_edit.text(),
            'port': int(self.port_edit.text()),
            'protocol': self.protocol_combo.currentText(),
            'password': None  # Will be requested if needed
        }
        
        # Request password if using external key
        if not params['self_signed']:
            dialog = PasswordDialog(self)
            password = dialog.get_password()
            if password is None:
                return  # User canceled
            params['password'] = password
        
        # Start signing thread
        self.signing_thread = SigningThread('sign', params, self.config_manager, self)
        self.signing_thread.progress.connect(self.update_progress)
        self.signing_thread.message.connect(self.update_status)
        self.signing_thread.finished.connect(self.operation_finished)
        self.signing_thread.error.connect(self.operation_error)
        self.signing_thread.start()
        
        # Update UI
        self.progress_bar.setVisible(True)
        self.status_bar.showMessage("Signing in progress...")
    
    def generate_certificate(self):
        """Generate a self-signed certificate"""
        # Validate inputs
        if not self.cert_domain_edit.text():
            QMessageBox.warning(self, "Error", "Please enter a domain for the certificate.")
            return
        
        if self.password_checkbox.isChecked():
            if not self.password_edit.text():
                QMessageBox.warning(self, "Error", "Please enter a password.")
                return
            if self.password_edit.text() != self.confirm_password_edit.text():
                QMessageBox.warning(self, "Error", "Passwords do not match.")
                return
        
        # Prepare parameters
        params = {
            'domain': self.cert_domain_edit.text(),
            'key_type': self.cert_key_type_combo.currentText().lower(),
            'key_size': int(self.cert_key_size_combo.currentText()),
            'certificate_template': self.cert_template_combo.currentText(),
            'password': self.password_edit.text() if self.password_checkbox.isChecked() else None
        }
        
        # Start certificate generation thread
        self.signing_thread = SigningThread('generate_cert', params, self.config_manager, self)
        self.signing_thread.progress.connect(self.update_progress)
        self.signing_thread.message.connect(self.update_status)
        self.signing_thread.finished.connect(self.operation_finished)
        self.signing_thread.error.connect(self.operation_error)
        self.signing_thread.start()
        
        # Update UI
        self.progress_bar.setVisible(True)
        self.status_bar.showMessage("Generating certificate...")
    
    def save_settings(self):
        """Save application settings"""
        config = {
            'theme': self.theme_combo.currentText(),
            'dark_mode': self.dark_mode_checkbox.isChecked(),
            'network_timeout': int(self.timeout_edit.text()),
            'chunk_size': int(self.chunk_size_edit.text()),
            'default_key_type': self.default_key_type_combo.currentText().lower(),
            'default_key_size': int(self.default_key_size_combo.currentText()),
            'default_algorithm': self.default_algorithm_combo.currentText(),
            'default_certificate_template': self.default_template_combo.currentText(),
            'recent_files': self.config.get('recent_files', [])
        }
        
        if self.config_manager.save_config(config):
            QMessageBox.information(self, "Settings", "Settings saved successfully.")
            self.apply_settings()
        else:
            QMessageBox.warning(self, "Settings", "Failed to save settings.")
    
    def change_theme(self, theme_name):
        """Change the application theme"""
        QApplication.setStyle(theme_name)
        self.config_manager.set_setting('theme', theme_name)
    
    def toggle_dark_mode(self, enabled):
        """Toggle dark mode"""
        self.config_manager.set_setting('dark_mode', enabled)
        if enabled:
            self.apply_dark_theme()
        else:
            QApplication.setPalette(QApplication.style().standardPalette())
    
    def update_progress(self, value):
        """Update progress bar"""
        self.progress_bar.setValue(value)
    
    def update_status(self, message):
        """Update status message"""
        self.status_bar.showMessage(message)
    
    def operation_finished(self, success, message):
        """Handle operation completion"""
        self.progress_bar.setVisible(False)
        if success:
            QMessageBox.information(self, "Success", message)
            self.status_bar.showMessage("Operation completed successfully.")
        else:
            QMessageBox.warning(self, "Error", message)
            self.status_bar.showMessage("Operation failed.")
    
    def operation_error(self, error_message):
        """Handle operation error"""
        self.progress_bar.setVisible(False)
        QMessageBox.critical(self, "Error", f"An error occurred:\n{error_message}")
        self.status_bar.showMessage("Operation failed with error.")
    
    def show_about(self):
        """Show about dialog"""
        dialog = AboutDialog(self)
        dialog.exec_()
    
    def closeEvent(self, event):
        """Handle application close"""
        # Save window geometry
        self.config_manager.set_setting('window_geometry', self.saveGeometry().data().hex())
        self.config_manager.set_setting('window_state', self.saveState().data().hex())
        
        # Stop any running threads
        if self.signing_thread and self.signing_thread.isRunning():
            self.signing_thread.is_running = False
            self.signing_thread.wait(2000)  # Wait up to 2 seconds
        
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    # Load configuration
    config_manager = ConfigurationManager()
    config = config_manager.load_config()
    
    # Apply theme
    QApplication.setStyle(config.get("theme", "Fusion"))
    
    # Apply dark mode if enabled
    if config.get('dark_mode', False):
        dark_palette = QPalette()
        dark_palette.setColor(QPalette.Window, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.WindowText, Qt.white)
        dark_palette.setColor(QPalette.Base, QColor(25, 25, 25))
        dark_palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ToolTipBase, Qt.white)
        dark_palette.setColor(QPalette.ToolTipText, Qt.white)
        dark_palette.setColor(QPalette.Text, Qt.white)
        dark_palette.setColor(QPalette.Button, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ButtonText, Qt.white)
        dark_palette.setColor(QPalette.BrightText, Qt.red)
        dark_palette.setColor(QPalette.Link, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.HighlightedText, Qt.black)
        QApplication.setPalette(dark_palette)
    
    # Create and show main window
    window = SignerUI(config_manager)
    window.show()
    
    sys.exit(app.exec())