# key_x509_manager.py

import os
import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from anchorforge.config import Config

# REQ: Config.X509_KEYPAIR_STORE_FILE = "../config/local_x509_keys.json" # see Config.

def load_x509_key_store(file_path: str) -> Dict:
    """Loads X.509 key and certificate pairs from a JSON file."""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"x509_key_pairs": []}

def save_x509_key_store(key_pairs: Dict, file_path: str):
    """Saves X.509 key and certificate pairs to a JSON file."""

    #  Ensure directory exists before saving
    directory = os.path.dirname(file_path)
    if directory and not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)
    with open(file_path, 'w') as f:
        json.dump(key_pairs, f, indent=4)

def generate_x509_key_pair(
    label: str,
    common_name: str,
    country: str,
    state: str,
    locality: str,
    organization: str,
    file_path: Optional[str] = None
) -> Dict:
    """
    Generates a new RSA private key and a self-signed X.509 certificate.

    Args:
        label (str): A label for easy identification of the key.
        common_name (str): The common name for the certificate (e.g., "example.com").
        country (str): The country code (e.g., "DE").
        state (str): The state or province (e.g., "Hessen").
        locality (str): The locality or city (e.g., "Gründau").
        organization (str): The organization name (e.g., "VAI Project").
        file_path (Optional[str]): Path to the key store file. If None,
                                   it uses a default path (to be defined in config).

    Returns:
        Dict: The newly generated key pair and certificate data.
    """
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Generate a self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime(2050, 12, 31, tzinfo=timezone.utc)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(common_name)]),
        critical=False,
    ).sign(private_key, hashes.SHA256(), default_backend())

    # Serialize keys and certificate to PEM format
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    certificate_pem = cert.public_bytes(
        encoding=serialization.Encoding.PEM
    ).decode('utf-8')

    # Get the current UTC date
    generation_date = datetime.now(timezone.utc).strftime('%Y-%m-%d')

    # Create the key pair data dictionary
    key_pair_data = {
        "label": label,
        "generation_date_utc": generation_date,
        "common_name": common_name,
        "private_key_pem": private_key_pem,
        "public_key_pem": public_key_pem,
        "certificate_pem": certificate_pem,
        "issuer": str(cert.issuer),
        "subject": str(cert.subject),
        "serial_number": cert.serial_number,
        "not_valid_before": cert.not_valid_before_utc.isoformat(),
        "not_valid_after": cert.not_valid_after_utc.isoformat()
    }

    # Load existing keys, add the new one, and save
    store_file_path = file_path if file_path else Config.X509_KEYPAIR_STORE_FILE
    
    assert store_file_path is not None
    
    key_store = load_x509_key_store(store_file_path)
    key_store["x509_key_pairs"].append(key_pair_data)
    save_x509_key_store(key_store, store_file_path)

    print(f"New X.509 key pair and certificate generated and saved to {store_file_path}:")
    print(f"  Label: {label}")
    print(f"  Common Name: {common_name}")
    
    return key_pair_data

def get_x509_key_pair_by_label(label: str, file_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Retrieves the full X.509 key pair and certificate data from the store file by its label.
    """
    store_file_path = file_path if file_path else Config.X509_KEYPAIR_STORE_FILE
    
    assert store_file_path is not None

    key_store = load_x509_key_store(store_file_path)
    
    for key_pair in key_store.get("x509_key_pairs", []):
        if key_pair.get("label") == label:
            return key_pair
            
    return None

if __name__ == "__main__":
    # Example usage
    # 1. You need to add 'X509_KEYPAIR_STORE_FILE' to your config.py
    # 2. You need to install the 'cryptography' library: pip install cryptography

    # Check if the store file path is configured
    if not hasattr(Config, 'X509_KEYPAIR_STORE_FILE') or not Config.X509_KEYPAIR_STORE_FILE:
        print("Please configure X509_KEYPAIR_STORE_FILE in your config.py before running this module.")
        # You could also add a placeholder for demo purposes if Config is not available
        # Config.X509_KEYPAIR_STORE_FILE = "local_x509_keys.json"
        
    ''' 
    new_cert = generate_x509_key_pair(
        label='anchor_test_certificate',
        common_name='www.example.com',
        country='DE',
        state='Baden-Württemberg',
        locality='Freiburg',
        organization='AnchorForge Project'
    )

    '''
    
    print("Only showing one certificate.")
    # Retrieve the certificate using its label
    cert_info = get_x509_key_pair_by_label('anchor_test_certificate')
    if cert_info:
        print("\n--- Retrieved Full X.509 Certificate Info ---")
        print(f"Label: {cert_info.get('label')}")
        print(f"Common Name: {cert_info.get('common_name')}")
        print(f"Not Valid Before: {cert_info.get('not_valid_before')}")
        print(f"Not Valid After: {cert_info.get('not_valid_after')}")
    else:
        print("\nCould not find full X.509 certificate info with the label 'test_certificate'.")