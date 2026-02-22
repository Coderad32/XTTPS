import hashlib
import hmac
import secrets
import os

class XSSLCore:
    """
    Enhanced Security Layer for the XTTPS Protocol.
    Replaces raw SHA-256 with HMAC for authenticity.
    """
    
    def __init__(self, secret_key: bytes):
        # The secret_key should be a long, random byte string
        self.secret_key = secret_key
        self.hash_algo = hashlib.sha256

    def generate_packet_auth(self, payload: bytes) -> bytes:
        """
        Generates a Message Authentication Code (MAC) for a packet.
        This prevents 'Length Extension Attacks' common in raw SHA-256.
        """
        return hmac.new(self.secret_key, payload, self.hash_algo).digest()

    def verify_packet(self, payload: bytes, provided_mac: bytes) -> bool:
        """
        Verifies the packet integrity using Constant-Time comparison.
        This prevents attackers from 'guessing' the hash character by character.
        """
        expected_mac = self.generate_packet_auth(payload)
        
        # secrets.compare_digest is essential to prevent timing attacks
        return secrets.compare_digest(expected_mac, provided_mac)

    @staticmethod
    def generate_session_salt(length=16) -> bytes:
        """Generates a cryptographically secure random salt for XSSL sessions."""
        return os.urandom(length)

# --- Example Usage for XTTPS ---
if __name__ == "__main__":
    # 1. Setup a secure key for the session
    server_key = b"XTTPS_SUPER_SECRET_KEY_CHANGE_ME"
    xssl = XSSLCore(server_key)

    # 2. Simulate an XTTPS Packet
    packet_data = b"GET /index.xttps HTTP/X.1"
    
    # 3. Create the Signature
    signature = xssl.generate_packet_auth(packet_data)
    print(f"XSSL Signature (SHA-256 HMAC): {signature.hex()}")

    # 4. Verification Logic
    is_valid = xssl.verify_packet(packet_data, signature)
    print(f"Packet Integrity Verified: {is_valid}")
