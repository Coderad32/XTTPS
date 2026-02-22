from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os

class XSSLHandshake:
    """
    Implements Elliptic Curve Diffie-Hellman (ECDH) for XTTPS.
    This allows two parties to agree on a SHA-256 key securely.
    """

    def __init__(self):
        # 1. Generate a private key for this session (Ephemeral)
        # We use SECP256R1 (NIST P-256), a widely trusted curve.
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()

    def get_public_bytes(self) -> bytes:
        """Returns the public key to be sent to the other party."""
        from cryptography.hazmat.primitives import serialization
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )

    def derive_shared_key(self, peer_public_key_bytes: bytes) -> bytes:
        """
        Combines our private key with the peer's public key to 
        create a unique SHA-256 session key.
        """
        from cryptography.hazmat.primitives import serialization
        
        # Load the peer's public key
        peer_public_key = serialization.load_der_public_key(peer_public_key_bytes) if b"BEGIN" in peer_public_key_bytes else \
                          ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_public_key_bytes)

        # Calculate the raw shared secret
        shared_secret = self.private_key.exchange(ec.ECDH(), peer_public_key)

        # 2. Key Derivation Function (KDF)
        # We don't use the raw secret directly; we run it through HKDF-SHA256
        # to ensure the resulting key is perfectly random and high-entropy.
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None, # In XTTPS, you could pass a session ID here as salt
            info=b"XSSL-Session-Key",
        ).derive(shared_secret)

        return derived_key

# --- Simulation of an XTTPS Connection ---
if __name__ == "__main__":
    # CLIENT SIDE
    client = XSSLHandshake()
    client_pub = client.get_public_bytes()

    # SERVER SIDE
    server = XSSLHandshake()
    server_pub = server.get_public_bytes()

    # --- THE EXCHANGE ---
    # Client sends client_pub to Server
    # Server sends server_pub to Client

    # BOTH SIDES CALCULATE THE KEY
    key_at_client = client.derive_shared_key(server_pub)
    key_at_server = server.derive_shared_key(client_pub)

    print(f"Client Session Key: {key_at_client.hex()}")
    print(f"Server Session Key: {key_at_server.hex()}")
    
    if key_at_client == key_at_server:
        print("\nSUCCESS: Both parties have the same secure XSSL key!")
