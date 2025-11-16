from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import os

# Generate a 32-byte key (ChaCha20 uses 256-bit keys)
key = ChaCha20Poly1305.generate_key()
aead = ChaCha20Poly1305(key)

# Nonce must be 12 bytes (96 bits)
nonce = os.urandom(12)

# Message and optional associated data
plaintext = b"Hello Cody, this is a secure message!"
aad = b"XTTPS-header: session=42"

# Encrypt
ciphertext = aead.encrypt(nonce, plaintext, aad)
print("Ciphertext:", ciphertext.hex())

# Decrypt
decrypted = aead.decrypt(nonce, ciphertext, aad)
print("Decrypted:", decrypted.decode())
