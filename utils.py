"""
utils.py — Key generation, encoding, and padding helpers for XTTPS/XSSL.

Provides:
- Key generation (Ed25519, ECDSA, X25519, AES/ChaCha20)
- Encoding/decoding (PEM, DER, Base64, Hex)
- Padding helpers (PKCS#7, Zero, ISO/IEC 7816-4)
"""

import os
import base64
import binascii
from typing import Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, ec, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305


# ============================================================
# Key generation
# ============================================================

def generate_ed25519() -> Tuple[bytes, bytes]:
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )
    pub_pem = pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv_pem, pub_pem


def generate_ecdsa_p256() -> Tuple[bytes, bytes]:
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )
    pub_pem = pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv_pem, pub_pem


def generate_x25519() -> Tuple[bytes, bytes]:
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )
    pub_pem = pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv_pem, pub_pem


def generate_aes_key(bits: int = 256) -> bytes:
    return AESGCM.generate_key(bit_length=bits)


def generate_chacha20_key() -> bytes:
    return ChaCha20Poly1305.generate_key()


# ============================================================
# Encoding / Decoding
# ============================================================

def to_base64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")

def from_base64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def to_hex(data: bytes) -> str:
    return binascii.hexlify(data).decode("ascii")

def from_hex(s: str) -> bytes:
    return binascii.unhexlify(s.encode("ascii"))


# ============================================================
# Padding helpers
# ============================================================

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid PKCS#7 padding")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid PKCS#7 padding bytes")
    return data[:-pad_len]

def zero_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + b"\x00" * pad_len

def zero_unpad(data: bytes) -> bytes:
    return data.rstrip(b"\x00")

def iso7816_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + b"\x80" + b"\x00" * (pad_len - 1)

def iso7816_unpad(data: bytes) -> bytes:
    # Remove trailing zeros until 0x80 marker
    i = len(data) - 1
    while i >= 0 and data[i] == 0x00:
        i -= 1
    if i < 0 or data[i] != 0x80:
        raise ValueError("Invalid ISO/IEC 7816-4 padding")
    return data[:i]


# ============================================================
# Quick self-test
# ============================================================

if __name__ == "__main__":
    print("== Keygen ==")
    ed_priv, ed_pub = generate_ed25519()
    print("Ed25519 pub:", ed_pub.decode().splitlines()[0])

    aes_key = generate_aes_key()
    print("AES-256 key (hex):", to_hex(aes_key))

    print("\n== Encoding ==")
    data = b"hello world"
    b64 = to_base64(data)
    print("Base64:", b64, "->", from_base64(b64))

    hexed = to_hex(data)
    print("Hex:", hexed, "->", from_hex(hexed))

    print("\n== Padding ==")
    msg = b"YELLOW SUBMARINE"
    padded = pkcs7_pad(msg, 16)
    print("PKCS#7 padded:", to_hex(padded))
    print("Unpadded:", pkcs7_unpad(padded, 16))
