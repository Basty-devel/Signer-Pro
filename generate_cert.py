import sys
import socket
import ssl
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime
import idna
import requests

def generate_self_signed_cert(domain):
    # Create private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Get original certificate info
    try:
        # Get certificate from domain
        cert_pem = ssl.get_server_certificate((domain, 443))
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        
        # Extract subject info
        subject = cert.subject
        issuer = subject  # Self-signed, so issuer=subject
        
        # Extract validity period (1 year from now)
        not_valid_before = datetime.datetime.utcnow()
        not_valid_after = not_valid_before + datetime.timedelta(days=365)
        
        # Extract SANs if available
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_names = san_ext.value if san_ext else []
        
    except Exception as e:
        print(f"Couldn't fetch certificate for {domain}: {e}")
        print("Using default certificate attributes")
        
        # Fallback values if we can't get the domain's cert
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, domain),
        ])
        not_valid_before = datetime.datetime.utcnow()
        not_valid_after = not_valid_before + datetime.timedelta(days=365)
        san_names = [x509.DNSName(domain)]

    # Create self-signed certificate
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.not_valid_before(not_valid_before)
    builder = builder.not_valid_after(not_valid_after)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(private_key.public_key())
    
    # Add extensions
    builder = builder.add_extension(
        x509.SubjectAlternativeName(san_names),
        critical=False
    )
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None), 
        critical=True
    )
    
    # Sign the certificate
    certificate = builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256(),
    )
    
    # Save private key
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    
    # Save certificate
    with open("certificate.pem", "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
    
    print(f"Generated self-signed certificate for {domain}")
    print("Private key saved to: private_key.pem")
    print("Certificate saved to: certificate.pem")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python generate_cert.py <domain>")
        sys.exit(1)
    
    domain = sys.argv[1]
    generate_self_signed_cert(domain)