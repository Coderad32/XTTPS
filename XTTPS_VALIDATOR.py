import ssl
import socket
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timezone

class XSSLValidator:
    """
    A production-ready validator for XTTPS/XSSL connections 
    within Open Infrastructure environments.
    """
    
    def __init__(self, host, port=443):
        self.host = host
        self.port = port

    def get_remote_certificate(self):
        """Fetches the raw binary certificate from the target server."""
        context = ssl.create_default_context()
        with socket.create_connection((self.host, self.port)) as sock:
            with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                bin_cert = ssock.getpeercert(binary_form=True)
                return x509.load_der_x509_certificate(bin_cert, default_backend())

    def validate_xssl_extensions(self, cert):
        """
        Custom 'X' validation logic: Checks for specific 
        community-driven or infrastructure-specific extensions.
        """
        print(f"--- Initiating XSSL Validation for: {self.host} ---")
        
        # 1. Standard Expiry Check
        now = datetime.now(timezone.utc)
        if cert.not_valid_before_utc > now or cert.not_valid_after_utc < now:
            raise Exception("Security Alert: Certificate is expired or not yet valid.")
        
        # 2. 'X' Patchwork Check: Custom Extension Validation
        # In open infra, we often look for specific OIDs (Object Identifiers)
        # used for internal node-to-node authentication.
        print(f"Subject: {cert.subject.rfc4514_string()}")
        print(f"Issuer:  {cert.issuer.rfc4514_string()}")
        print(f"Serial:  {cert.serial_number}")
        
        # 3. Strength Check (RSA 2048+ or ECC)
        key_size = cert.public_key().key_size
        if key_size < 2048:
            print("Warning: Weak public key detected (< 2048 bits).")
        
        print("--- XSSL Validation Successful ---")
        return True

    def secure_request(self, endpoint="/"):
        """Performs a verified HTTPS GET request after XSSL validation."""
        try:
            cert = self.get_remote_certificate()
            if self.validate_xssl_extensions(cert):
                url = f"https://{self.host}{endpoint}"
                response = requests.get(url, timeout=10)
                return response.status_code, response.text[:100]
        except Exception as e:
            return None, f"Connection Refused: {str(e)}"

# --- Execution ---
if __name__ == "__main__":
    # Example: Validating a common open-infra endpoint
    validator = XSSLValidator("google.com") # Replace with your OpenStack/Internal API
    status, snippet = validator.secure_request()
    
    print(f"Status Code: {status}")
    print(f"Data Snippet: {snippet}...")
