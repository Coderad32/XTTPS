[index.md](https://github.com/user-attachments/files/23782648/index.md)
# Welcome Users
## XTTPS-XSSL Suite

This suite provides a secure protocol implementation with custom certificate handling, cryptographic primitives, and debugging tools.

## 👋 Welcome Users

Welcome to our project! We’re thrilled to have you here. Whether you're a developer, researcher, or enthusiast, your curiosity and contributions are valued. This initiative is built on collaboration, innovation, and a shared commitment to secure, sustainable technology.

## 🌱 About the Project

This project explores the intersection of:

• 	Sustainability: Tools and systems designed for off-grid localhost living and resource efficiency.
• 	Security: Protocols and frameworks that prioritize privacy, integrity, and decentralized trust.
• 	Automation: Intelligent agents that streamline workflows and optimize resource allocation.

## 🔐 Network Security

Our protocol stack includes:
• 	XTTPS/XSSL: A custom encrypted transport layer with decentralized certificate validation.
• 	Session Management: Secure handshake, certificate exchange, and encrypted payload delivery.
• 	Privacy-First Design: No third-party tracking, minimal metadata exposure, and robust timeout handling.

## This suite includes:

- **XTTPS Runtime**: Manages secure sessions with custom headers and encrypted payloads
- **XSSL Certification**: Issues and verifies decentralized certificates with pluggable authority logic
- **Security Primitives**: Implements hashing, signing, and encryption algorithms
- **Tooling & Docs**: Includes test runners, packet inspectors, and onboarding guides

## 🔧 XTTPS Runtime

The **XTTPS Runtime** is the engine that drives secure communication sessions. It handles:

- **Session Lifecycle**: Initiates, maintains, and terminates encrypted sessions using custom handshake logic.
- **Header Management**: Parses and validates XTTP headers, supporting custom fields like `X-Session-Token`, `X-Cert-Hash`, and `X-Nonce`.
- **Payload Encryption**: Encrypts/decrypts payloads using primitives like AES-GCM or ChaCha20, optionally supporting layered encryption (e.g., onion-style).
- **Stateful Context**: Maintains session state, including tokens, timestamps, and peer metadata.
- **Extensibility Hooks**: Allows injection of middleware for logging, rate-limiting, or protocol upgrades.

🛠️ *Suggested Modules*:
- `xttps_core.py`: Session orchestration and packet routing
- `xttp_headers.py`: Header schema, validation, and formatting
- `session_store.py`: In-memory or persistent session tracking

---

## 🏛️ XSSL Certification

The **XSSL Certification Framework** replaces centralized authorities with decentralized or pluggable trust models:

- **Certificate Issuance**: Generates XSSL certificates with fields like identity hash, public key, expiry, and optional metadata.
- **Verification Logic**: Validates certificate chains using trust anchors, revocation checks, and signature verification.
- **Decentralized Authority**: Supports models like Web of Trust, blockchain anchoring, or quorum-based endorsement.
- **Schema Definition**: Certificates follow a JSON schema for interoperability and validation.

🛠️ *Suggested Modules*:
- `issuer.py`: Certificate generation and signing
- `verifier.py`: Chain validation and trust logic
- `schema.json`: Certificate format and constraints

---

## 🔐 Security Primitives

This layer provides the cryptographic backbone for both transport and certification:

- **Hashing**: SHA-3, Blake3, and optionally custom domain-separated hashes
- **Signing**: ECDSA, Ed25519, and post-quantum options (e.g., Dilithium)
- **Encryption**: AES-GCM, ChaCha20-Poly1305, and hybrid schemes (e.g., ECIES)
- **Benchmarking**: Performance and reliability tests across platforms and payload sizes

🛠️ *Suggested Modules*:
- `primitives.py`: Core cryptographic functions
- `tests/`: Unit tests and benchmarks
- `utils.py`: Key generation, encoding, and padding helpers

---

## 🧪 Tooling & Docs

Developer experience is key—this layer ensures visibility, testability, and onboarding:

- **Test Runner**: CLI tool to execute protocol tests, validate headers, and simulate sessions
- **Packet Inspector**: Visualizes XTTP packets, headers, and payloads with debug mode and hex dumps
- **Integration Guides**: Step-by-step docs for runtime setup, certificate handling, and protocol flows
- **Examples**: Sample configs, test packets, and annotated flows for quick prototyping

🛠️ *Suggested Modules*:
- `test_runner.py`: CLI test suite
- `packet_inspector.py`: XTTP packet visualization
- `docs/`: Markdown guides and specs
- `examples/`: Sample flows and configs

## 📬 Contact Information

For questions, contributions, or collaboration inquiries:
• 	GitHub: @Coderad32
• 	X (Twitter): @Coderad32
• 	YouTube: Coderad32
• 	LinkedIn: Cody Bunnell
• 	Email: Reach out via GitHub profile or repository contact links

---

## A Work In Progress

## Installation 

Install github cli simply clone the URL.

```
git clone https://github.com/Coderad32/XTTPS.git


```
Then change directories to XTTPS.
```

cd XTTPS

```

## Init
```py
# tests/__init__.py
# Placeholder for reliability and performance tests

# tests/__init__.py

# Optional: shared test fixtures or configuration
import logging

logging.basicConfig(level=logging.DEBUG)

# tests/__init__.py

# This file can be empty unless you need shared fixtures or setup


# tests/__init__.py

def normalize_string(s):
    return s.strip().lower()

# tests/test_init.py

import unittest
from tests import normalize_string

class TestInitHelpers(unittest.TestCase):
    def test_normalize_string(self):
        self.assertEqual(normalize_string("  Hello "), "hello")
        self.assertEqual(normalize_string("WORLD"), "world")
        self.assertEqual(normalize_string("  Mixed Case  "), "mixed case")

if __name__ == "__main__":
    unittest.main()

```

## Cert
```py
# xssl/cert.py
from crypto_core import Hasher, HashAlg, Signer, SignAlg
from contexts import XSSL_CTX

class CertificateAuthority:
    def __init__(self, sign_alg=SignAlg.ED25519):
        self.h_body = Hasher(HashAlg.SHA3_256)
        self.h_ext = Hasher(HashAlg.SHA3_512)
        self.signer = Signer(sign_alg).generate()

    def sign_certificate(self, cert_body: bytes, extensions: bytes, issuer_bind: bytes=b""):
        body_digest = self.h_body.digest(cert_body, context=XSSL_CTX["CERT_BODY"])
        ext_digest = self.h_ext.digest(extensions, context=XSSL_CTX["CERT_EXT"])
        issuer_digest = self.h_body.digest(issuer_bind, context=XSSL_CTX["ISSUER_BIND"])

        # Canonical to-be-signed data structure
        tbs = body_digest + ext_digest + issuer_digest
        sig = self.signer.sign(tbs, context=XSSL_CTX["CERT_CHAIN"])

        return {
            "cert_body": cert_body,
            "extensions": extensions,
            "issuer_bind": issuer_bind,
            "body_digest": body_digest,
            "ext_digest": ext_digest,
            "issuer_digest": issuer_digest,
            "signature": sig.sig,
            "issuer_pub": sig.pubkey,
        }

class CertificateVerifier:
    def __init__(self, sign_alg=SignAlg.ED25519):
        self.h_body = Hasher(HashAlg.SHA3_256)
        self.h_ext = Hasher(HashAlg.SHA3_512)

    def verify(self, signed_cert: dict):
        tbs = signed_cert["body_digest"] + signed_cert["ext_digest"] + signed_cert["issuer_digest"]
        signer = Signer(SignAlg.ED25519)  # algorithm must match issuer
        # We only need a public key to verify; set it temporarily
        return signer.verify(
            signed_cert["signature"],
            tbs,
            context=b"XSSL:cert:chain",
            pubkey_pem=signed_cert["issuer_pub"]
        )

```
## Context_Registry
```py
# context_registry.py
ALLOWED_CTX = set([
    b"XTTPS:frame:hdr", b"XTTPS:frame:body", b"XTTPS:frame:meta",
    b"XTTPS:hs:init", b"XTTPS:hs:accept", b"XTTPS:key:update", b"XTTPS:stream:ctrl",
    b"XSSL:cert:body", b"XSSL:cert:ext", b"XSSL:cert:chain",
    b"XSSL:rev:crl", b"XSSL:rev:ocsp:req", b"XSSL:rev:ocsp:resp", b"XSSL:issuer:bind",
])

def assert_context(ctx: bytes):
    if ctx not in ALLOWED_CTX:
        raise ValueError(f"Unknown context tag: {ctx!r}")

```
## Context
```py
# contexts.py
XTTPS_CTX = {
    "FRAME_HDR": b"XTTPS:frame:hdr",
    "FRAME_BODY": b"XTTPS:frame:body",
    "FRAME_META": b"XTTPS:frame:meta",
    "HANDSHAKE_INIT": b"XTTPS:hs:init",
    "HANDSHAKE_ACCEPT": b"XTTPS:hs:accept",
    "KEY_UPDATE": b"XTTPS:key:update",
    "STREAM_CTRL": b"XTTPS:stream:ctrl",
}

XSSL_CTX = {
    "CERT_BODY": b"XSSL:cert:body",
    "CERT_EXT": b"XSSL:cert:ext",
    "CERT_CHAIN": b"XSSL:cert:chain",
    "CRL_ENTRY": b"XSSL:rev:crl",
    "OCSP_REQ": b"XSSL:rev:ocsp:req",
    "OCSP_RESP": b"XSSL:rev:ocsp:resp",
    "ISSUER_BIND": b"XSSL:issuer:bind",
}

```
## Crypto_Core
```py
"""
crypto_core.py — Modular cryptographic backbone for XTTPS (transport) & XSSL (certification).

Primitives:
- Hashing: SHA3-256/512, BLAKE3 (optional), domain-separated
- Signing: Ed25519, ECDSA (P-256), PQ placeholder (Dilithium)
- AEAD: AES-GCM, ChaCha20-Poly1305
- Hybrid ECIES: X25519 + HKDF-SHA256 + AEAD
- Benchmarks: latency & throughput scaffolds

Dependencies:
- cryptography>=41.0.0
- blake3 (optional; pip install blake3)
"""

from __future__ import annotations
import os
import time
import enum
from dataclasses import dataclass
from typing import Optional, Tuple, Callable

# Hashes
import hashlib
try:
    import blake3  # optional acceleration & extendable outputs
except ImportError:
    blake3 = None

# Crypto (sign/AEAD/KDF/ECDH)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, ec, x25519
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


# ============================================================
# Context tags (single source of truth)
# ============================================================

XTTPS_CTX = {
    "FRAME_HDR": b"XTTPS:frame:hdr",
    "FRAME_BODY": b"XTTPS:frame:body",
    "FRAME_META": b"XTTPS:frame:meta",
    "HS_INIT": b"XTTPS:hs:init",
    "HS_ACCEPT": b"XTTPS:hs:accept",
    "KEY_UPDATE": b"XTTPS:key:update",
    "STREAM_CTRL": b"XTTPS:stream:ctrl",
}

XSSL_CTX = {
    "CERT_BODY": b"XSSL:cert:body",
    "CERT_EXT": b"XSSL:cert:ext",
    "CERT_CHAIN": b"XSSL:cert:chain",
    "ISSUER_BIND": b"XSSL:issuer:bind",
    "CRL_ENTRY": b"XSSL:rev:crl",
    "OCSP_REQ": b"XSSL:rev:ocsp:req",
    "OCSP_RESP": b"XSSL:rev:ocsp:resp",
}

ALLOWED_CTX = set(XTTPS_CTX.values()) | set(XSSL_CTX.values())


def assert_context(ctx: Optional[bytes]):
    if ctx is None:
        return
    if ctx not in ALLOWED_CTX:
        raise ValueError(f"Unknown context tag: {ctx!r}")


# ============================================================
# Domain separation helper
# ============================================================

def ds_tag(context: Optional[bytes]) -> bytes:
    """
    Domain-separate all operations. Context must be a known tag or None.
    When None, we still add a generic tag to avoid collisions by accident.
    """
    if context is None:
        return b"XCORE:default:"
    assert_context(context)
    return b"XCORE:" + context + b":"


# ============================================================
# Hashing
# ============================================================

class HashAlg(enum.Enum):
    SHA3_256 = "sha3-256"
    SHA3_512 = "sha3-512"
    BLAKE3 = "blake3"  # optional

class Hasher:
    def __init__(self, alg: HashAlg):
        self.alg = alg
        if self.alg == HashAlg.BLAKE3 and blake3 is None:
            raise RuntimeError("blake3 module not available; pip install blake3")

    def digest(self, data: bytes, context: Optional[bytes] = None, outlen: int = 32) -> bytes:
        """
        Domain-separated digest. 'outlen' applies to BLAKE3 only; SHA3 uses fixed sizes.
        """
        tag = ds_tag(context)
        msg = tag + data
        if self.alg == HashAlg.SHA3_256:
            return hashlib.sha3_256(msg).digest()
        elif self.alg == HashAlg.SHA3_512:
            return hashlib.sha3_512(msg).digest()
        elif self.alg == HashAlg.BLAKE3:
            h = blake3.blake3(msg)
            return h.digest(outlen)
        else:
            raise ValueError("Unsupported hash algorithm")

    def hexdigest(self, data: bytes, context: Optional[bytes] = None, outlen: int = 32) -> str:
        return self.digest(data, context, outlen).hex()


# ============================================================
# Signing
# ============================================================

class SignAlg(enum.Enum):
    ED25519 = "ed25519"
    ECDSA_P256 = "ecdsa-p256"
    DILITHIUM = "dilithium"  # placeholder interface

@dataclass
class SignatureResult:
    sig: bytes
    pubkey: bytes  # serialized public key (PEM SPKI)

class Signer:
    def __init__(self, alg: SignAlg):
        self.alg = alg
        self._priv = None
        self._pub = None

    # --- key generation / import / export ---
    def generate(self):
        if self.alg == SignAlg.ED25519:
            self._priv = ed25519.Ed25519PrivateKey.generate()
            self._pub = self._priv.public_key()
        elif self.alg == SignAlg.ECDSA_P256:
            self._priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
            self._pub = self._priv.public_key()
        elif self.alg == SignAlg.DILITHIUM:
            raise NotImplementedError("Dilithium: integrate via PQC library.")
        else:
            raise ValueError("Unsupported signing algorithm")
        return self

    def load_private_pkcs8(self, key_pem: bytes, password: Optional[bytes] = None):
        self._priv = serialization.load_pem_private_key(key_pem, password=password, backend=default_backend())
        self._pub = self._priv.public_key()
        return self

    def export_private_pkcs8(self, password: Optional[bytes] = None) -> bytes:
        enc = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
        return self._priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            enc
        )

    def export_public_spki(self) -> bytes:
        return self._pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )

    # --- sign / verify ---
    def sign(self, data: bytes, context: Optional[bytes] = None) -> SignatureResult:
        tag = ds_tag(context)
        msg = tag + data
        if self.alg == SignAlg.ED25519:
            sig = self._priv.sign(msg)
        elif self.alg == SignAlg.ECDSA_P256:
            # ECDSA: prehash with SHA-256 to stabilize size
            digest = hashlib.sha256(msg).digest()
            sig = self._priv.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        elif self.alg == SignAlg.DILITHIUM:
            raise NotImplementedError("Dilithium: implement sign with domain-separated msg.")
        else:
            raise ValueError("Unsupported signing algorithm")
        return SignatureResult(sig=sig, pubkey=self.export_public_spki())

    def verify(self, sig: bytes, data: bytes, context: Optional[bytes] = None, pubkey_pem: Optional[bytes] = None) -> bool:
        tag = ds_tag(context)
        msg = tag + data
        pub = self._pub
        if pubkey_pem:
            pub = serialization.load_pem_public_key(pubkey_pem, backend=default_backend())
        try:
            if self.alg == SignAlg.ED25519:
                pub.verify(sig, msg)
                return True
            elif self.alg == SignAlg.ECDSA_P256:
                digest = hashlib.sha256(msg).digest()
                pub.verify(sig, digest, ec.ECDSA(Prehashed(hashes.SHA256())))
                return True
            elif self.alg == SignAlg.DILITHIUM:
                raise NotImplementedError("Dilithium: implement verify accordingly.")
        except Exception:
            return False
        raise ValueError("Unsupported signing algorithm")


# ============================================================
# AEAD encryption (AES-GCM, ChaCha20-Poly1305)
# ============================================================

class AeadAlg(enum.Enum):
    AES_GCM = "aes-gcm"
    CHACHA20_POLY1305 = "chacha20-poly1305"

@dataclass
class Ciphertext:
    nonce: bytes
    ct: bytes
    aad: Optional[bytes]

class Aead:
    def __init__(self, alg: AeadAlg, key: bytes):
        self.alg = alg
        self.key = key
        if alg == AeadAlg.AES_GCM:
            self._aead = AESGCM(key)
            self.nlen = 12
        elif alg == AeadAlg.CHACHA20_POLY1305:
            self._aead = ChaCha20Poly1305(key)
            self.nlen = 12
        else:
            raise ValueError("Unsupported AEAD algorithm")

    def encrypt(self, plaintext: bytes, context: Optional[bytes] = None, aad: Optional[bytes] = None, nonce: Optional[bytes] = None) -> Ciphertext:
        tag = ds_tag(context)
        _aad = (tag + aad) if aad else tag
        nonce = nonce or os.urandom(self.nlen)
        ct = self._aead.encrypt(nonce, plaintext, _aad)
        return Ciphertext(nonce=nonce, ct=ct, aad=_aad)

    def decrypt(self, c: Ciphertext) -> bytes:
        return self._aead.decrypt(c.nonce, c.ct, c.aad)


# ============================================================
# ECIES-style hybrid encryption (X25519 + HKDF + AEAD)
# ============================================================

@dataclass
class HybridCiphertext:
    eph_pub: bytes
    nonce: bytes
    ct: bytes
    aad: Optional[bytes]
    kdf_info: bytes

class ECIES:
    """
    Ephemeral X25519 -> HKDF-SHA256 -> AEAD (AES-GCM or ChaCha20-Poly1305).
    Use AAD to bind certificate/issuer/client identifiers for onboarding.
    """
    def __init__(self, aead_alg: AeadAlg = AeadAlg.CHACHA20_POLY1305, kdf_salt: Optional[bytes] = None, kdf_info: Optional[bytes] = None):
        self.aead_alg = aead_alg
        self.salt = kdf_salt or b"XCORE:KDF:default"
        self.info = kdf_info or b"XCORE:ECIES:v1"

    def encrypt(self, recipient_pub_pem: bytes, plaintext: bytes, context: Optional[bytes] = None, aad: Optional[bytes] = None) -> HybridCiphertext:
        recip_pub = serialization.load_pem_public_key(recipient_pub_pem, backend=default_backend())
        if not isinstance(recip_pub, x25519.X25519PublicKey):
            raise TypeError("recipient_pub_pem must be X25519 public key")

        eph_priv = x25519.X25519PrivateKey.generate()
        shared = eph_priv.exchange(recip_pub)

        aead_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            info=self.info,
            backend=default_backend()
        ).derive(shared)

        a = Aead(self.aead_alg, aead_key)
        c = a.encrypt(plaintext, context=context, aad=aad)
        eph_pub_bytes = eph_priv.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return HybridCiphertext(eph_pub=eph_pub_bytes, nonce=c.nonce, ct=c.ct, aad=c.aad, kdf_info=self.info)

    def decrypt(self, recipient_priv_pem: bytes, hc: HybridCiphertext) -> bytes:
        recip_priv = serialization.load_pem_private_key(recipient_priv_pem, password=None, backend=default_backend())
        if not isinstance(recip_priv, x25519.X25519PrivateKey):
            raise TypeError("recipient_priv_pem must be X25519 private key")

        eph_pub = serialization.load_pem_public_key(hc.eph_pub, backend=default_backend())
        shared = recip_priv.exchange(eph_pub)

        aead_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            info=hc.kdf_info,
            backend=default_backend()
        ).derive(shared)

        a = Aead(self.aead_alg, aead_key)
        return a.decrypt(Ciphertext(nonce=hc.nonce, ct=hc.ct, aad=hc.aad))


# ============================================================
# Benchmark scaffolding
# ============================================================

@dataclass
class BenchResult:
    op_name: str
    items: int
    total_ms: float
    avg_us: float
    throughput_mb_s: Optional[float]  # for bulk ops

class Bench:
    @staticmethod
    def timeit(op_name: str, fn: Callable[[], None], items: int) -> BenchResult:
        t0 = time.perf_counter()
        for _ in range(items):
            fn()
        t1 = time.perf_counter()
        total_ms = (t1 - t0) * 1000.0
        avg_us = (total_ms * 1000.0) / items
        return BenchResult(op_name=op_name, items=items, total_ms=total_ms, avg_us=avg_us, throughput_mb_s=None)

    @staticmethod
    def bulk(op_name: str, fn: Callable[[], bytes], items: int, payload_len: int) -> BenchResult:
        t0 = time.perf_counter()
        total_bytes = 0
        for _ in range(items):
            out = fn()
            total_bytes += payload_len if out is None else len(out)
        t1 = time.perf_counter()
        total_ms = (t1 - t0) * 1000.0
        seconds = (t1 - t0)
        mb = total_bytes / (1024 * 1024)
        thr = mb / seconds if seconds > 0 else None
        avg_us = (total_ms * 1000.0) / items
        return BenchResult(op_name=op_name, items=items, total_ms=total_ms, avg_us=avg_us, throughput_mb_s=thr)


# ============================================================
# Utilities for X25519 key serialization (for ECIES)
# ============================================================

def x25519_generate() -> Tuple[bytes, bytes]:
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


# ============================================================
# Quick self-test / example usage
# ============================================================

if __name__ == "__main__":
    print("== Hashing ==")
    h = Hasher(HashAlg.SHA3_256)
    d = h.hexdigest(b"hello", context=XTTPS_CTX["FRAME_HDR"])
    print("SHA3-256:", d)

    if blake3 is not None:
        hb3 = Hasher(HashAlg.BLAKE3)
        print("BLAKE3-32:", hb3.hexdigest(b"hello", context=XSSL_CTX["CERT_BODY"], outlen=32))

    print("\n== Signing ==")
    s_ed = Signer(SignAlg.ED25519).generate()
    msg = b"cert-body-bytes"
    sig_res = s_ed.sign(msg, context=XSSL_CTX["CERT_CHAIN"])
    ok = s_ed.verify(sig_res.sig, msg, context=XSSL_CTX["CERT_CHAIN"], pubkey_pem=sig_res.pubkey)
    print("Ed25519 verify:", ok)

    s_ec = Signer(SignAlg.ECDSA_P256).generate()
    sig2 = s_ec.sign(msg, context=XSSL_CTX["CERT_CHAIN"])
    ok2 = s_ec.verify(sig2.sig, msg, context=XSSL_CTX["CERT_CHAIN"], pubkey_pem=s_ec.export_public_spki())
    print("ECDSA-P256 verify:", ok2)

    print("\n== AEAD ==")
    key_gcm = AESGCM.generate_key(bit_length=256)
    a_gcm = Aead(AeadAlg.AES_GCM, key_gcm)
    c1 = a_gcm.encrypt(b"payload", context=XTTPS_CTX["FRAME_BODY"], aad=b"v1")
    p1 = a_gcm.decrypt(c1)
    print("AES-GCM roundtrip:", p1 == b"payload")

    key_ch = ChaCha20Poly1305.generate_key()
    a_ch = Aead(AeadAlg.CHACHA20_POLY1305, key_ch)
    blob = os.urandom(2048)
    c2 = a_ch.encrypt(blob, context=XTTPS_CTX["FRAME_BODY"])
    p2 = a_ch.decrypt(c2)
    print("ChaCha20-Poly1305 roundtrip:", p2 == blob)

    print("\n== ECIES ==")
    priv_pem, pub_pem = x25519_generate()
    ecies = ECIES(aead_alg=AeadAlg.CHACHA20_POLY1305)
    hc = ecies.encrypt(pub_pem, b"onboarding-secret", context=XSSL_CTX["ISSUER_BIND"], aad=b"client-123")
    plain = ecies.decrypt(priv_pem, hc)
    print("ECIES roundtrip:", plain == b"onboarding-secret")

    print("\n== Benchmarks ==")
    # hash bench
    br = Bench.timeit("sha3-256(1KB)x1000", lambda: Hasher(HashAlg.SHA3_256).digest(os.urandom(1024), XTTPS_CTX["FRAME_META"]), 1000)
    print(br)

    # aead bulk bench
    bulk_plain = os.urandom(1024 * 64)  # 64KB
    br2 = Bench.bulk(
        "chacha20-poly1305(64KB)x200",
        lambda: Aead(AeadAlg.CHACHA20_POLY1305, ChaCha20Poly1305.generate_key()).encrypt(bulk_plain, XTTPS_CTX["FRAME_BODY"]).ct,
        200,
        len(bulk_plain)
    )
    print(br2)

```
## Crypto_MSG
```py
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

```
## File_En_De_Crypt
```py
# Sure! Below is a Python script for a simple encrypted file management system that can:

# - Encrypt and decrypt files.
# - List encrypted files.
# - Delete encrypted files.

# It uses the `cryptography` library (`pip install cryptography`) and basic CLI interface.  
# **For demo purposes, symmetric encryption with a password-derived key is used.**
```
```python name=encrypted_file_manager.py
import os
import sys
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from getpass import getpass

STORAGE_DIR = "encrypted_storage"
SALT_FILE = ".salt"

def _init_storage():
    os.makedirs(STORAGE_DIR, exist_ok=True)
    salt_path = os.path.join(STORAGE_DIR, SALT_FILE)
    if not os.path.exists(salt_path):
        with open(salt_path, "wb") as f:
            f.write(os.urandom(16))

def _get_salt():
    with open(os.path.join(STORAGE_DIR, SALT_FILE), "rb") as f:
        return f.read()

def _derive_key(password: str):
    salt = _get_salt()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_file(src_path, password):
    _init_storage()
    key = _derive_key(password)
    fernet = Fernet(key)
    filename = os.path.basename(src_path)
    dst_path = os.path.join(STORAGE_DIR, filename + ".enc")
    with open(src_path, "rb") as fr:
        data = fr.read()
    enc_data = fernet.encrypt(data)
    with open(dst_path, "wb") as fw:
        fw.write(enc_data)
    print(f"Encrypted and stored as {dst_path}")

def decrypt_file(filename, password, outpath=None):
    _init_storage()
    key = _derive_key(password)
    fernet = Fernet(key)
    enc_path = os.path.join(STORAGE_DIR, filename)
    if not enc_path.endswith(".enc"):
        enc_path += ".enc"
    with open(enc_path, "rb") as fr:
        enc_data = fr.read()
    data = fernet.decrypt(enc_data)
    if outpath is None:
        outpath = filename.replace(".enc", ".dec")
    with open(outpath, "wb") as fw:
        fw.write(data)
    print(f"Decrypted and saved as {outpath}")

def list_files():
    _init_storage()
    files = [f for f in os.listdir(STORAGE_DIR) 
             if f.endswith(".enc")]
    print("Encrypted files:")
    for f in files:
        print(" -", f)

def delete_file(filename):
    _init_storage()
    path = os.path.join(STORAGE_DIR, filename)
    if not path.endswith(".enc"):
        path += ".enc"
    try:
        os.remove(path)
        print(f"Deleted {path}")
    except FileNotFoundError:
        print(f"No such file: {path}")

def usage():
    print("Encrypted File Manager")
    print("Usage:")
    print("  python encrypted_file_manager.py encrypt <source_file>")
    print("  python encrypted_file_manager.py decrypt <filename.enc> [output_file]")
    print("  python encrypted_file_manager.py list")
    print("  python encrypted_file_manager.py delete <filename.enc>")

def main():
    if len(sys.argv) < 2:
        usage()
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == "encrypt" and len(sys.argv) == 3:
        password = getpass("Password: ")
        encrypt_file(sys.argv[2], password)
    elif cmd == "decrypt" and (len(sys.argv) == 3 or len(sys.argv) == 4):
        password = getpass("Password: ")
        out = sys.argv[3] if len(sys.argv) == 4 else None
        decrypt_file(sys.argv[2], password, out)
    elif cmd == "list":
        list_files()
    elif cmd == "delete" and len(sys.argv) == 3:
        delete_file(sys.argv[2])
    else:
        usage()

if __name__ == "__main__":
    main()
```

## **How to use:**

```sh
python encrypted_file_manager.py encrypt secret.txt
python encrypted_file_manager.py decrypt secret.txt.enc
python encrypted_file_manager.py list
python encrypted_file_manager.py delete secret.txt.enc

## **Requirements:**  
## Install via:  
```sh
pip install cryptography
```

```


```
## Frame
```py
# xttps/frame.py
from crypto_core import Hasher, HashAlg, Aead, AeadAlg
from contexts import XTTPS_CTX

class FrameBuilder:
    def __init__(self, aead_alg=AeadAlg.CHACHA20_POLY1305, key: bytes=None):
        self.hdr_hasher = Hasher(HashAlg.SHA3_256)
        self.body_hasher = Hasher(HashAlg.BLAKE3) if hasattr(__import__('builtins'), 'blake3') else Hasher(HashAlg.SHA3_512)
        self.aead = Aead(aead_alg, key)

    def build(self, header: bytes, body: bytes, meta: bytes=b""):
        hdr_digest = self.hdr_hasher.digest(header, context=XTTPS_CTX["FRAME_HDR"])
        body_digest = self.body_hasher.digest(body, context=XTTPS_CTX["FRAME_BODY"])
        meta_digest = self.hdr_hasher.digest(meta, context=XTTPS_CTX["FRAME_META"])

        # AAD binds header + meta digests; ciphertext binds to body context
        aad = hdr_digest + meta_digest
        c = self.aead.encrypt(body, context=XTTPS_CTX["FRAME_BODY"], aad=aad)

        return {
            "header": header,
            "ciphertext": c.ct,
            "nonce": c.nonce,
            "aad": c.aad,
            "hdr_digest": hdr_digest,
            "body_digest": body_digest,
            "meta_digest": meta_digest,
        }

class FrameParser:
    def __init__(self, aead_alg=AeadAlg.CHACHA20_POLY1305, key: bytes=None):
        self.hdr_hasher = Hasher(HashAlg.SHA3_256)
        self.body_hasher = Hasher(HashAlg.BLAKE3) if hasattr(__import__('builtins'), 'blake3') else Hasher(HashAlg.SHA3_512)
        self.aead = Aead(aead_alg, key)

    def parse(self, packet):
        # Recompute AAD and decrypt
        hdr_digest = self.hdr_hasher.digest(packet["header"], context=XTTPS_CTX["FRAME_HDR"])
        meta_digest = packet.get("meta_digest") or self.hdr_hasher.digest(b"", context=XTTPS_CTX["FRAME_META"])
        aad = hdr_digest + meta_digest

        plaintext = self.aead.decrypt(
            type("C", (), {"nonce": packet["nonce"], "ct": packet["ciphertext"], "aad": (XTTPS_CTX["FRAME_BODY"] + aad)})
        )
        # Optional body integrity verification
        body_digest = self.body_hasher.digest(plaintext, context=XTTPS_CTX["FRAME_BODY"])
        if body_digest != packet["body_digest"]:
            raise ValueError("Body digest mismatch")
        return {"header": packet["header"], "body": plaintext, "meta_digest": meta_digest}


```
## Handshake
```py
# xttps/handshake.py
from crypto_core import Hasher, HashAlg, Signer, SignAlg
from contexts import XTTPS_CTX

class Handshake:
    def __init__(self):
        self.h = Hasher(HashAlg.SHA3_256)
        self.signer = Signer(SignAlg.Ed25519).generate()

    def init_message(self, payload: bytes):
        d = self.h.digest(payload, context=XTTPS_CTX["HANDSHAKE_INIT"])
        sig = self.signer.sign(d, context=XTTPS_CTX["HANDSHAKE_INIT"])
        return {"payload": payload, "digest": d, "sig": sig.sig, "pub": sig.pubkey}

    def accept_message(self, init_digest: bytes, payload: bytes):
        bind = init_digest + payload
        d = self.h.digest(bind, context=XTTPS_CTX["HANDSHAKE_ACCEPT"])
        sig = self.signer.sign(d, context=XTTPS_CTX["HANDSHAKE_ACCEPT"])
        return {"payload": payload, "digest": d, "sig": sig.sig, "pub": sig.pubkey}


```
## Issuer
```py

# issuer.py
# Issues XSSL certificates

import json
import uuid
from datetime import datetime, timedelta

class CertificateIssuer:
    def issue_certificate(self, subject):
        cert = {
            "subject": subject,
            "issuer": "XSSL-CA",
            "valid_from": datetime.utcnow().isoformat(),
            "valid_to": (datetime.utcnow() + timedelta(days=365)).isoformat(),
            "signature": str(uuid.uuid4())
        }
        return json.dumps(cert, indent=2)


```
## Overlay_Renderer
```h
#pragma once
#include <windows.h>
#include "XTTPSession.h"

class OverlayRenderer {
public:
    static void Init(HWND hwnd);
    static void Render(HWND hwnd);
    static void DrawSessionInfo(HDC hdc, const XTTPSession& session);
};


```
## Packet_Inspector
```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
packet_inspector.py — XTTP packet visualization

- Parse XTTP frames from PCAP or hex logs
- Validate fields against a schema
- Render timelines and per-field diffs
- Export JSON for downstream tooling

Usage:
  python packet_inspector.py --pcap capture.pcap
  python packet_inspector.py --hex logs/xttp_hex.txt
  python packet_inspector.py --method QUERY --out packets.json
"""

import argparse
import binascii
import json
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# Optional dependencies gated to run without them when parsing hex logs only.
try:
    from scapy.all import rdpcap, Raw
except Exception:
    rdpcap = None
    Raw = None

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
except Exception:
    Console = None
    Table = None
    Panel = None
    box = None

# -------------------------
# XTTP schema (adjust as needed)
# -------------------------

# Simple helpers for typed reads from a bytes cursor
def read_u8(buf, off):
    return buf[off], off + 1

def read_u16(buf, off):
    return int.from_bytes(buf[off:off+2], "big"), off + 2

def read_u32(buf, off):
    return int.from_bytes(buf[off:off+4], "big"), off + 4

def read_len_prefixed_str(buf, off):
    """Reads: u16 length, then UTF-8 bytes"""
    ln, off = read_u16(buf, off)
    s = buf[off:off+ln]
    try:
        val = s.decode("utf-8", errors="replace")
    except Exception:
        val = s.hex()
    return val, off + ln

def read_len_prefixed_bytes(buf, off):
    ln, off = read_u16(buf, off)
    return buf[off:off+ln], off + ln

# Define the protocol fields and parsers.
# Tailor this to your wire format.
XTTP_SCHEMA = [
    ("version", read_u8),
    ("flags", read_u8),
    ("session_id", read_u32),
    ("seq", read_u32),
    ("method", read_len_prefixed_str),   # e.g., QUERY, SEND, ACK
    ("status", read_u16),                # e.g., 0, 200, 404 (optional for responses)
    ("path", read_len_prefixed_str),     # e.g., /resource/sub
    ("header_count", read_u16),
    ("headers", "headers"),              # k/v pairs (header_count items)
    ("payload_len", read_u32),
    ("payload", "payload"),
    ("aead_tag_len", read_u16),
    ("aead_tag", "aead"),
]

ALLOWED_METHODS = {"QUERY", "SEND", "ACK", "PING", "PONG"}

@dataclass
class XTTPPacket:
    raw: bytes
    fields: Dict[str, Any]
    src: Optional[str] = None
    dst: Optional[str] = None
    sport: Optional[int] = None
    dport: Optional[int] = None
    ts: Optional[float] = None
    flow_key: Optional[Tuple[str, int, str, int]] = None

# -------------------------
# Parsing
# -------------------------

class XTTPParser:
    def parse(self, raw: bytes) -> XTTPPacket:
        off = 0
        fields: Dict[str, Any] = {}

        # Basic sequential parsing
        for name, reader in XTTP_SCHEMA:
            if reader == "headers":
                hc = fields.get("header_count", 0)
                headers = []
                for _ in range(hc):
                    k, off = read_len_prefixed_str(raw, off)
                    v, off = read_len_prefixed_str(raw, off)
                    headers.append((k, v))
                fields["headers"] = headers
                continue
            elif reader == "payload":
                # Uses payload_len
                ln = fields.get("payload_len", 0)
                payload = raw[off:off+ln]
                fields["payload"] = payload
                off += ln
                continue
            elif reader == "aead":
                ln = fields.get("aead_tag_len", 0)
                aead = raw[off:off+ln]
                fields["aead_tag"] = aead
                off += ln
                continue
            else:
                val, off = reader(raw, off)
                fields[name] = val

        self._validate(fields, raw_len=len(raw))
        return XTTPPacket(raw=raw, fields=fields)

    def _validate(self, fields: Dict[str, Any], raw_len: int):
        # Version bounds
        ver = fields.get("version", 0)
        if ver not in (1, 2):  # tweak as needed
            fields["_warn_version"] = f"Unexpected version: {ver}"

        # Method check
        method = fields.get("method", "")
        if method and method not in ALLOWED_METHODS:
            fields["_warn_method"] = f"Unknown method: {method}"

        # Payload length consistency
        plen = fields.get("payload_len", 0)
        payload = fields.get("payload", b"")
        if plen != len(payload):
            fields["_warn_payload_len"] = f"Declared {plen}, actual {len(payload)}"

        # AEAD tag sanity
        tlen = fields.get("aead_tag_len", 0)
        aead = fields.get("aead_tag", b"")
        if tlen != len(aead):
            fields["_warn_aead_len"] = f"Declared {tlen}, actual {len(aead)}"

# -------------------------
# Sources: PCAP or hex log
# -------------------------

def load_hex_lines(path: str) -> List[bytes]:
    packets = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            try:
                packets.append(binascii.unhexlify(s))
            except Exception:
                # Allow spaced hex
                s2 = s.replace(" ", "")
                packets.append(binascii.unhexlify(s2))
    return packets

def load_pcap(path: str) -> List[Tuple[bytes, float, str, int, str, int]]:
    if rdpcap is None:
        raise RuntimeError("PCAP parsing requires scapy. Please: pip install scapy")
    pkts = rdpcap(path)
    out = []
    for p in pkts:
        ts = float(getattr(p, "time", 0.0))
        raw = None
        src = dst = None
        sport = dport = None
        try:
            if Raw in p:
                raw = bytes(p[Raw].load)
            # Try to infer addresses/ports
            if hasattr(p, "haslayer"):
                if p.haslayer("IP"):
                    src = p["IP"].src
                    dst = p["IP"].dst
                if p.haslayer("TCP"):
                    sport = p["TCP"].sport
                    dport = p["TCP"].dport
                elif p.haslayer("UDP"):
                    sport = p["UDP"].sport
                    dport = p["UDP"].dport
        except Exception:
            pass
        if raw:
            out.append((raw, ts, src, sport, dst, dport))
    return out

# -------------------------
# Rendering
# -------------------------

def fmt_bytes(b: bytes, max_len: int = 64) -> str:
    if not b:
        return ""
    h = b.hex()
    if len(h) > max_len:
        return h[:max_len] + "...+" + str(len(b)) + "B"
    return h

def safe_text(b: bytes, max_len: int = 96) -> str:
    try:
        s = b.decode("utf-8", errors="replace")
    except Exception:
        s = b.hex()
    if len(s) > max_len:
        return s[:max_len] + "..."
    return s

def make_flow_key(pkt: XTTPPacket) -> Optional[Tuple[str, int, str, int]]:
    if pkt.src and pkt.dst and pkt.sport and pkt.dport:
        return (pkt.src, pkt.sport, pkt.dst, pkt.dport)
    return None

def render_packets(console: Optional[Any], packets: List[XTTPPacket], title: str = "XTTP Packets"):
    # Fallback to plain text if rich is unavailable
    if console is None or Table is None or Panel is None:
        print(f"=== {title} ===")
        for i, p in enumerate(packets):
            f = p.fields
            print(f"[{i}] ts={p.ts} {p.src}:{p.sport} -> {p.dst}:{p.dport} seq={f.get('seq')} method={f.get('method')} status={f.get('status')}")
            print(f"   path={f.get('path')} payload={fmt_bytes(f.get('payload', b''))} aead={fmt_bytes(f.get('aead_tag', b''))}")
            for k in sorted(f.keys()):
                if k.startswith("_warn"):
                    print(f"   WARN {k}: {f[k]}")
        return

    table = Table(title=title, box=box.MINIMAL_HEAVY_HEAD)
    table.add_column("Idx", style="bold cyan", width=4)
    table.add_column("Time", style="magenta", width=10)
    table.add_column("Flow", style="green")
    table.add_column("Seq", style="yellow", width=7)
    table.add_column("Method", style="bold")
    table.add_column("Status", style="bold")
    table.add_column("Path")
    table.add_column("Payload")
    table.add_column("AEAD")

    for i, p in enumerate(packets):
        f = p.fields
        flow = f"{p.src}:{p.sport} → {p.dst}:{p.dport}" if all([p.src, p.sport, p.dst, p.dport]) else "—"
        table.add_row(
            str(i),
            f"{p.ts:.3f}" if p.ts else "—",
            flow,
            str(f.get("seq", "—")),
            str(f.get("method", "—")),
            str(f.get("status", "—")),
            f.get("path", "—"),
            fmt_bytes(f.get("payload", b"")),
            fmt_bytes(f.get("aead_tag", b""))
        )

    console.print(table)

    # Per-field warnings panel
    warns = []
    for p in packets:
        for k, v in p.fields.items():
            if k.startswith("_warn"):
                warns.append((k, v))
    if warns:
        content = "\n".join([f"{k}: {v}" for (k, v) in warns])
        console.print(Panel(content, title="Validation warnings", border_style="red"))

def timeline_by_flow(console: Optional[Any], packets: List[XTTPPacket]):
    if console is None or Table is None:
        print("=== Timeline by flow ===")
        by_flow: Dict[str, List[XTTPPacket]] = {}
        for p in packets:
            key = p.flow_key or "unknown"
            by_flow.setdefault(str(key), []).append(p)
        for flow, items in by_flow.items():
            print(f"Flow {flow}:")
            for p in sorted(items, key=lambda x: (x.ts or 0.0, x.fields.get("seq", 0))):
                print(f"  t={p.ts} seq={p.fields.get('seq')} method={p.fields.get('method')} status={p.fields.get('status')} path={p.fields.get('path')}")
        return

    # Rich table grouped by flow
    grouped: Dict[str, List[XTTPPacket]] = {}
    for p in packets:
        key = p.flow_key or ("unknown", 0, "unknown", 0)
        grouped.setdefault(str(key), []).append(p)

    for flow, items in grouped.items():
        table = Table(title=f"Flow {flow}", box=box.SIMPLE)
        table.add_column("Time", width=10)
        table.add_column("Seq", width=7)
        table.add_column("Method", width=10)
        table.add_column("Status", width=8)
        table.add_column("Path")
        table.add_column("Headers")
        table.add_column("Payload (text)")
        for p in sorted(items, key=lambda x: (x.ts or 0.0, x.fields.get("seq", 0))):
            f = p.fields
            headers = ", ".join([f"{k}={v}" for k, v in f.get("headers", [])])
            table.add_row(
                f"{p.ts:.3f}" if p.ts else "—",
                str(f.get("seq", "—")),
                str(f.get("method", "—")),
                str(f.get("status", "—")),
                f.get("path", "—"),
                headers,
                safe_text(f.get("payload", b""))
            )
        console.print(table)

# -------------------------
# Diffing successive packets
# -------------------------

def field_diff(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Tuple[Any, Any]]:
    diff = {}
    keys = set(a.keys()) | set(b.keys())
    for k in keys:
        if a.get(k) != b.get(k):
            diff[k] = (a.get(k), b.get(k))
    return diff

def render_diffs(console: Optional[Any], packets: List[XTTPPacket]):
    if not packets:
        return
    # Group by flow and sort by seq/time, then show diffs
    flows: Dict[str, List[XTTPPacket]] = {}
    for p in packets:
        key = p.flow_key or "unknown"
        flows.setdefault(str(key), []).append(p)

    for flow, items in flows.items():
        items = sorted(items, key=lambda x: (x.ts or 0.0, x.fields.get("seq", 0)))
        if console is None or Table is None or Panel is None:
            print(f"=== Diffs for {flow} ===")
            for i in range(1, len(items)):
                d = field_diff(items[i-1].fields, items[i].fields)
                print(f"  [{i-1}→{i}] {len(d)} fields changed: {list(d.keys())}")
            continue

        table = Table(title=f"Diffs for {flow}", box=box.SIMPLE_HEAVY)
        table.add_column("Prev→Curr", width=10)
        table.add_column("Changed fields")
        for i in range(1, len(items)):
            d = field_diff(items[i-1].fields, items[i].fields)
            changed = ", ".join(sorted(d.keys()))
            table.add_row(f"{i-1}→{i}", changed or "—")
        console.print(table)

# -------------------------
# Aggregates
# -------------------------

def aggregates(console: Optional[Any], packets: List[XTTPPacket]):
    by_method: Dict[str, int] = {}
    statuses: Dict[int, int] = {}
    for p in packets:
        m = p.fields.get("method")
        if m:
            by_method[m] = by_method.get(m, 0) + 1
        s = p.fields.get("status")
        if isinstance(s, int):
            statuses[s] = statuses.get(s, 0) + 1

    if console is None or Table is None:
        print("=== Aggregates ===")
        print("By method:", by_method)
        print("By status:", statuses)
        return

    t1 = Table(title="By method", box=box.MINIMAL)
    t1.add_column("Method", style="bold")
    t1.add_column("Count", style="yellow")
    for k, v in sorted(by_method.items()):
        t1.add_row(k, str(v))

    t2 = Table(title="By status", box=box.MINIMAL)
    t2.add_column("Status", style="bold")
    t2.add_column("Count", style="yellow")
    for k, v in sorted(statuses.items()):
        t2.add_row(str(k), str(v))

    console.print(t1)
    console.print(t2)

# -------------------------
# CLI
# -------------------------

def parse_args():
    ap = argparse.ArgumentParser(description="XTTP packet inspector and visualization")
    ap.add_argument("--pcap", type=str, help="PCAP file containing XTTP payloads")
    ap.add_argument("--hex", type=str, help="Text file with newline-delimited hex frames")
    ap.add_argument("--method", type=str, help="Filter by method (e.g., QUERY)")
    ap.add_argument("--status", type=int, help="Filter by status code")
    ap.add_argument("--session", type=int, help="Filter by session_id")
    ap.add_argument("--out", type=str, help="Export parsed packets as JSON")
    ap.add_argument("--limit", type=int, default=0, help="Limit packet count")
    return ap.parse_args()

def main():
    args = parse_args()
    parser = XTTPParser()

    # Console for pretty output
    console_instance = Console() if Console else None

    raw_entries: List[Tuple[bytes, float, str, int, str, int]] = []

    if args.pcap:
        raw_entries = load_pcap(args.pcap)
    elif args.hex:
        raw_hex = load_hex_lines(args.hex)
        # synthesize minimal metadata
        raw_entries = [(b, None, None, None, None, None) for b in raw_hex]
    else:
        print("Provide --pcap or --hex.")
        sys.exit(1)

    packets: List[XTTPPacket] = []
    for (raw, ts, src, sport, dst, dport) in raw_entries:
        try:
            pkt = parser.parse(raw)
            pkt.ts = ts
            pkt.src = src
            pkt.sport = sport
            pkt.dst = dst
            pkt.dport = dport
            pkt.flow_key = make_flow_key(pkt)
            packets.append(pkt)
        except Exception as e:
            # Keep going; record malformed frames as warnings
            bad = XTTPPacket(raw=raw, fields={"_warn_parse": str(e)})
            bad.ts = ts
            packets.append(bad)

    # Filters
    def keep(p: XTTPPacket) -> bool:
        if args.method and p.fields.get("method") != args.method:
            return False
        if args.status is not None:
            if p.fields.get("status") != args.status:
                return False
        if args.session is not None:
            if p.fields.get("session_id") != args.session:
                return False
        return True

    packets = [p for p in packets if keep(p)]
    if args.limit and args.limit > 0:
        packets = packets[:args.limit]

    # Render
    render_packets(console_instance, packets, title="XTTP Packets")
    timeline_by_flow(console_instance, packets)
    render_diffs(console_instance, packets)
    aggregates(console_instance, packets)

    # Export
    if args.out:
        serial = []
        for p in packets:
            f = dict(p.fields)
            # Normalize bytes to hex
            for k in ("payload", "aead_tag"):
                if isinstance(f.get(k), (bytes, bytearray)):
                    f[k] = f[k].hex()
            serial.append({
                "ts": p.ts,
                "src": p.src,
                "sport": p.sport,
                "dst": p.dst,
                "dport": p.dport,
                "fields": f
            })
        with open(args.out, "w", encoding="utf-8") as fo:
            json.dump(serial, fo, indent=2)
        if console_instance:
            console_instance.print(Panel(f"Exported {len(serial)} packets to {args.out}", border_style="green"))
        else:
            print(f"Exported {len(serial)} packets to {args.out}")

if __name__ == "__main__":
    main()


```
## Primitives
```py
# primitives.py
# Cryptographic primitives: hashing, signing, encryption

import hashlib
import hmac
from cryptography.fernet import Fernet

def hash_data(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()

def sign_data(data: str, key: str) -> str:
    return hmac.new(key.encode(), data.encode(), hashlib.sha256).hexdigest()

def generate_key() -> str:
    return Fernet.generate_key().decode()

def encrypt_data(data: str, key: str) -> str:
    f = Fernet(key.encode())
    return f.encrypt(data.encode()).decode()

def decrypt_data(token: str, key: str) -> str:
    f = Fernet(key.encode())
    return f.decrypt(token.encode()).decode()

#
#
#

age = 30           # int
temp = 98.6        # float
active = False     # bool
greeting = "Hi!"   # str

int("42")       # 42
float("3.14")   # 3.14
str(100)        # "100"
bool(0)         # False

if "":         # False
    print("Won't run")
if "hello":    # True
    print("Will run")

```
## Protocol_Handler
```h
#pragma once
#include "XTTPSession.h"

class ProtocolHandler {
public:
    static void ParseRequest(const std::string& raw);
    static void ParseResponse(const std::string& raw);
};


```
## Revocation
```py
# xssl/revocation.py
from crypto_core import Hasher, HashAlg, Signer, SignAlg
from contexts import XSSL_CTX

class RevocationService:
    def __init__(self, issuer_signer: Signer):
        self.h = Hasher(HashAlg.SHA3_256)
        self.signer = issuer_signer

    def crl_entry(self, cert_body_digest: bytes, reason_code: bytes):
        payload = cert_body_digest + reason_code
        d = self.h.digest(payload, context=XSSL_CTX["CRL_ENTRY"])
        sig = self.signer.sign(d, context=XSSL_CTX["CRL_ENTRY"])
        return {"digest": d, "sig": sig.sig, "pub": sig.pubkey}

    def ocsp_response(self, ocsp_req_bytes: bytes, status: bytes):
        bind = ocsp_req_bytes + status
        d = self.h.digest(bind, context=XSSL_CTX["OCSP_RESP"])
        sig = self.signer.sign(d, context=XSSL_CTX["OCSP_RESP"])
        return {"digest": d, "sig": sig.sig, "pub": sig.pubkey}


```
## Runtime
```py
# XTTPS session manager and protocol handler

import urllib.parse
import uuid
import time

# Session Manager for XTTPS
class XTTPSessionManager:
    def __init__(self, url):
        self.url = url
        self.session_id = str(uuid.uuid4())
        self.parsed = urllib.parse.urlparse(url)
        self.active = False

    def initiate_session(self):
        print(f"[XTTPS] Initiating session with {self.parsed.netloc}")
        print(f"[XTTPS] Session ID: {self.session_id}")
        self.handshake()
        self.active = True

    def handshake(self):
        print("[XTTPS] Performing secure handshake...")
        time.sleep(0.5)
        print("[XTTPS] Handshake complete. Secure channel established.")

    def terminate_session(self):
        print(f"[XTTPS] Terminating session {self.session_id}")
        self.active = False

# XTTP Protocol Handler
class XTTPHandler:
    def __init__(self, session_manager):
        self.session = session_manager

    def request(self, method="GET", headers=None, payload=None):
        if not self.session.active:
            print("[XTTP] No active session. Aborting request.")
            return
        print(f"[XTTP] Making {method} request to {self.session.parsed.netloc}")
        if headers:
            print(f"[XTTP] Headers: {headers}")
        if payload:
            print(f"[XTTP] Payload: {payload}")
        print("[XTTP] Request sent.")
        print("[XTTP] Response received: <xttp-response>Success</xttp-response>")

# Protocol Dispatcher
def handle_custom_protocol(url, method="GET", headers=None, payload=None):
    scheme = urllib.parse.urlparse(url).scheme
    if scheme == "xttps":
        session = XTTPSessionManager(url)
        session.initiate_session()
        handler = XTTPHandler(session)
        handler.request(method=method, headers=headers, payload=payload)
        session.terminate_session()
    else:
        print(f"[Dispatcher] Unsupported protocol: {scheme}")

# Example usage
if __name__ == "__main__":
    handle_custom_protocol(
        "xttps://api.example.com",
        method="POST",
        headers={"Content-Type": "application/json"},
        payload='{"data":"Hello XTTPS"}'
    )

#
# # Alternative simplified implementation focusing on core logic
#

import json
import logging

# Setup basic logging
logging.basicConfig(level=logging.INFO)

def handle_custom_protocol(url, method="GET", headers=None, payload=None):
    """
    Simulates handling a custom XTTPS/XSSL protocol request.
    """
    logging.info(f"Handling {method} request to {url}")
    
    # Validate protocol
    if not url.startswith("xttps://"):
        raise ValueError("Invalid protocol. Expected 'xttps://'")

    # Simulate header parsing
    headers = headers or {}
    logging.debug(f"Headers: {headers}")

    # Simulate payload processing
    if payload:
        try:
            data = json.loads(payload)
            logging.info(f"Payload parsed: {data}")
        except json.JSONDecodeError:
            logging.error("Invalid JSON payload")
            return {"status": "error", "message": "Malformed JSON"}

    # Simulate response
    response = {
        "status": "success",
        "code": 200,
        "message": f"{method} request to {url} processed.",
        "echo": data if payload else None
    }
    logging.info(f"Response: {response}")
    return response


```
## Schema
```json
{
  "type": "object",
  "properties": {
    "subject": { "type": "string" },
    "issuer": { "type": "string" },
    "valid_from": { "type": "string", "format": "date-time" },
    "valid_to": { "type": "string", "format": "date-time" },
    "signature": { "type": "string" }
  },
  "required": ["subject", "issuer", "valid_from", "valid_to", "signature"]
}

// # 
// # Update Example Upgrade: v2.0.0json
// #

{
  "subject": "CN=Cody Bunnell, O=Top Code, OU=Protocol Dev, C=US",
  "issuer": "CN=Mars Preserve Foundation Root CA, O=MPF, C=US",
  "valid_from": "2025-11-16T00:00:00Z",
  "valid_to": "2026-11-16T23:59:59Z",
  "signature": "a9f3c8d7e2b1f4a6c3d8e9f0b7a6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8"
}
```
## Session Manager
```h
#pragma once
#include <string>

struct XTTPSession {
    std::string session_id;
    std::string client_id;
    bool active;
    std::string handshake_status;
    std::string cert_info;
};


```
## Session Store
```py
# session_store.py

import threading
import time
from typing import Dict, Optional
from uuid import uuid4

class Session:
    def __init__(self, client_id: str, timeout: int = 60):
        self.session_id = f"session-{uuid4().hex[:12]}"
        self.client_id = client_id
        self.created_at = time.time()
        self.last_active = self.created_at
        self.timeout = timeout
        self.data = {}  # Arbitrary session metadata
        self.lock = threading.Lock()

    def is_expired(self) -> bool:
        return time.time() - self.last_active > self.timeout

    def touch(self):
        with self.lock:
            self.last_active = time.time()

    def set(self, key: str, value):
        with self.lock:
            self.data[key] = value

    def get(self, key: str):
        with self.lock:
            return self.data.get(key)

class SessionStore:
    def __init__(self):
        self.sessions: Dict[str, Session] = {}
        self.lock = threading.Lock()

    def create_session(self, client_id: str, timeout: int = 60) -> Session:
        session = Session(client_id, timeout)
        with self.lock:
            self.sessions[session.session_id] = session
        return session

    def get_session(self, session_id: str) -> Optional[Session]:
        with self.lock:
            return self.sessions.get(session_id)

    def cleanup_expired(self):
        with self.lock:
            expired = [sid for sid, s in self.sessions.items() if s.is_expired()]
            for sid in expired:
                del self.sessions[sid]

    def terminate_session(self, session_id: str):
        with self.lock:
            if session_id in self.sessions:
                del self.sessions[session_id]

    def list_active_sessions(self) -> Dict[str, Session]:
        with self.lock:
            return {sid: s for sid, s in self.sessions.items() if not s.is_expired()}

```
## Session Trace
```log

[08:00:00] [INFO] XTTP Session initialized for client_id=client-12345
[08:00:01] [SEND] Client Hello → Headers: {X-Client-Hello, X-Timestamp}
[08:00:01] [RECV] Server Hello ← Session ID: session-abcde12345
[08:00:02] [INFO] Handshake complete. Secure channel established.

[08:00:03] [SEND] Certificate presented by client-12345
[08:00:03] [INFO] Certificate valid. Issuer: XSSL-CA

[08:00:05] [SEND] Encrypted packet sent
[08:00:05] [INFO] Payload: gAAAAABlYz...

[08:00:06] [RECV] Encrypted response received
[08:00:06] [INFO] Decrypted payload: {"status": "OK", "message": "Session active"}

[08:01:00] [INFO] Session timeout threshold reached
[08:01:01] [INFO] Session session-abcde12345 terminated


```
## TCP server
```pl
# server.pl
use strict;
use warnings;
use IO::Socket::INET;
use XTTP::Message;

my $hmac_key = 'supersecret'; # replace with proper key management

my $server = IO::Socket::INET->new(
    LocalAddr => '0.0.0.0',
    LocalPort => 8088,
    Proto     => 'tcp',
    Listen    => 5,
    Reuse     => 1,
) or die "Could not start server: $!";

print "XTTP server listening on 0.0.0.0:8088\n";

while (my $client = $server->accept) {
    $client->autoflush(1);

    # Read until we can parse headers and body length
    my $buf = '';
    while ($buf !~ /\r\n\r\n/) {
        my $read = <$client>;
        last unless defined $read;
        $buf .= $read;
    }
    # Extract Content-Length to read body
    my ($headers) = $buf =~ /\A.*?\r\n\r\n/s;
    my ($len) = $headers =~ /^Content-Length:\s*(\d+)/mi;
    $len ||= 0;

    my $body = '';
    read($client, $body, $len) if $len > 0;
    $buf .= $body;

    # Optionally read HMAC trailer line
    my $line = <$client>;
    $buf .= $line if defined $line;

    my $msg;
    eval { $msg = XTTP::Message->parse($buf, hmac_key => $hmac_key) };
    if ($@) {
        print $client "SEND /error xttp/1.0\r\nStatus: 400\r\nContent-Length: 0\r\n\r\n";
        close $client;
        next;
    }

    # Application logic
    my $reply_body = "ok";
    my $reply = XTTP::Message->new(
        method  => 'REPLY',
        path    => $msg->{path},
        headers => { Status => 200, 'Content-Type' => 'text/plain' },
        body    => $reply_body,
        hmac_key => $hmac_key,
    );

    print $client $reply->serialize;
    close $client;
}
```
## Test Primitives
```py
# test_primitives.py
# Unit tests for crypto primitives

from crypto import primitives

def test_hash():
    assert primitives.hash_data("test") == primitives.hash_data("test")

def test_sign():
    key = "secret"
    assert primitives.sign_data("data", key) == primitives.sign_data("data", key)

def test_encrypt_decrypt():
    key = primitives.generate_key()
    encrypted = primitives.encrypt_data("hello", key)
    decrypted = primitives.decrypt_data(encrypted, key)
    assert decrypted == "hello"

```
## Test Runner
```py
# test_runner.py
# CLI test runner for all modules

import unittest
import os

def discover_and_run_tests():
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir="crypto/tests", pattern="test_*.py")
    runner = unittest.TextTestRunner()
    runner.run(suite)

if __name__ == "__main__":
    discover_and_run_tests()


```
## Traffic Log
```json
[
  {
    "timestamp": "2025-11-13T08:00:01Z",
    "direction": "outbound",
    "type": "handshake",
    "headers": {
      "X-Client-Hello": "Hello from client-12345",
      "X-Timestamp": "2025-11-13T08:00:01Z"
    },
    "payload": ""
  },
  {
    "timestamp": "2025-11-13T08:00:01Z",
    "direction": "inbound",
    "type": "handshake_response",
    "headers": {
      "X-Server-Hello": "session-abcde12345",
      "X-Timestamp": "2025-11-13T08:00:01Z"
    },
    "payload": ""
  },
  {
    "timestamp": "2025-11-13T08:00:03Z",
    "direction": "outbound",
    "type": "certificate",
    "headers": {
      "X-Session-ID": "session-abcde12345",
      "X-Timestamp": "2025-11-13T08:00:03Z"
    },
    "payload": "{...certificate_sample.json...}"
  },
  {
    "timestamp": "2025-11-13T08:00:05Z",
    "direction": "outbound",
    "type": "data",
    "headers": {
      "X-Session-ID": "session-abcde12345",
      "X-Timestamp": "2025-11-13T08:00:05Z"
    },
    "payload": "gAAAAABlYz..."
  },
  {
    "timestamp": "2025-11-13T08:00:06Z",
    "direction": "inbound",
    "type": "data_response",
    "headers": {
      "X-Session-ID": "session-abcde12345",
      "X-Timestamp": "2025-11-13T08:00:06Z"
    },
    "payload": "gAAAAABlYz... (encrypted response)"
  }
]


```
## Utils
```py
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

```
## Verifier
```py
# verifier.py
# Verifies certificate validity

import json
from datetime import datetime

class CertificateVerifier:
    def verify_chain(self, cert_json):
        try:
            cert = json.loads(cert_json)
            now = datetime.utcnow()
            valid_from = datetime.fromisoformat(cert["valid_from"])
            valid_to = datetime.fromisoformat(cert["valid_to"])
            return valid_from <= now <= valid_to
        except Exception:
            return False


```
## Web Server
```py
# Python 3 server example
from http.server import BaseHTTPRequestHandler, HTTPServer
import time

hostName = "localhost"
serverPort = 8080

class MyServer(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(bytes("<html><head><title>https://pythonbasics.org</title></head>", "utf-8"))
        self.wfile.write(bytes("<p>Request: %s</p>" % self.path, "utf-8"))
        self.wfile.write(bytes("<body>", "utf-8"))
        self.wfile.write(bytes("<p>This is an example web server.</p>", "utf-8"))
        self.wfile.write(bytes("</body></html>", "utf-8"))

if __name__ == "__main__":        
    webServer = HTTPServer((hostName, serverPort), MyServer)
    print("Server started http://%s:%s" % (hostName, serverPort))

    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
    print("Server stopped.")

```
## Xttps Client
```py
# client.pl
use strict;
use warnings;
use IO::Socket::INET;
use XTTP::Message;

my $hmac_key = 'supersecret'; # match server's for demo

my $sock = IO::Socket::INET->new(
    PeerAddr => '127.0.0.1',
    PeerPort => 8088,
    Proto    => 'tcp',
) or die "Connect failed: $!";

my $msg = XTTP::Message->new(
    method  => 'SEND',
    path    => '/ping',
    headers => { 'Content-Type' => 'text/plain' },
    body    => 'ping',
    hmac_key => $hmac_key,
);

print $sock $msg->serialize;

# Read response
my $resp = '';
while (my $line = <$sock>) {
    $resp .= $line;
    last if $line =~ /^HMAC:/; # simplistic read for demo
}
close $sock;

my $parsed = XTTP::Message->parse($resp, hmac_key => $hmac_key);
print "Status: $parsed->{headers}{Status}\n";
print "Body: $parsed->{body}\n";
```
## Xttps Core
```py
# xttps_core.py
# Manages session lifecycle, handshake, and packet parsing

import uuid
import time
from .xttp_headers import HeaderValidator

class Session:
    def __init__(self, client_id):
        self.session_id = str(uuid.uuid4())
        self.client_id = client_id
        self.start_time = time.time()
        self.handshake_complete = False

    def perform_handshake(self, client_hello):
        # Simulate handshake logic
        if "X-Client-Hello" in client_hello:
            self.handshake_complete = True
            return {"X-Server-Hello": self.session_id}
        return {"error": "Invalid handshake"}

    def parse_packet(self, packet):
        if not self.handshake_complete:
            raise Exception("Handshake not completed")
        headers = packet.get("headers", {})
        payload = packet.get("payload", "")
        if not HeaderValidator().validate(headers):
            raise Exception("Invalid headers")
        return f"Payload received: {payload}"


```
## Xttps Headers

```py
# xttp_headers.py
# Defines and validates custom XTTP headers

class HeaderValidator:
    REQUIRED_HEADERS = ["X-Session-ID", "X-Timestamp"]

    def validate(self, headers):
        for key in self.REQUIRED_HEADERS:
            if key not in headers:
                return False
        return True
#
# xttp_headers.py update && upgrade
#
import logging
from datetime import datetime, timedelta

class HeaderValidator:
    REQUIRED_HEADERS = ["X-Session-ID", "X-Timestamp"]
    OPTIONAL_HEADERS = ["X-Client-Hello", "X-Certificate", "X-Signature"]
    TIMESTAMP_TOLERANCE_SECONDS = 60  # Acceptable clock skew

    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)

    def validate(self, headers):
        self.logger.debug("Validating headers: %s", headers)

        # Check required headers
        missing = [key for key in self.REQUIRED_HEADERS if key not in headers]
        if missing:
            self.logger.warning("Missing required headers: %s", missing)
            return False

        # Validate timestamp freshness
        if not self._is_timestamp_valid(headers.get("X-Timestamp")):
            self.logger.warning("Invalid or expired timestamp")
            return False

        # Optional: Validate header types
        if not self._validate_types(headers):
            self.logger.warning("Header type mismatch")
            return False

        self.logger.info("Header validation passed")
        return True

    def _is_timestamp_valid(self, timestamp_str):
        try:
            ts = datetime.fromisoformat(timestamp_str)
            now = datetime.utcnow()
            delta = abs((now - ts).total_seconds())
            return delta <= self.TIMESTAMP_TOLERANCE_SECONDS
        except Exception as e:
            self.logger.error("Timestamp parsing failed: %s", e)
            return False

    def _validate_types(self, headers):
        # Example: enforce string types for all headers
        for key, value in headers.items():
            if not isinstance(value, str):
                self.logger.debug("Header %s has non-string value: %s", key, type(value))
                return False
        return True

    def list_missing_headers(self, headers):
        return [key for key in self.REQUIRED_HEADERS if key not in headers]

    def list_optional_headers_present(self, headers):
        return [key for key in self.OPTIONAL_HEADERS if key in headers]

```


## Xttps Module
```py
# lib/XTTP/Message.pm
package XTTP::Message;
use strict;
use warnings;
use Digest::SHA qw(hmac_sha256_hex);

sub new {
    my ($class, %args) = @_;
    my $self = {
        method  => $args{method}  || 'SEND',
        path    => $args{path}    || '/',
        version => $args{version} || 'xttp/1.0',
        headers => $args{headers} || {},
        body    => $args{body}    || '',
        hmac_key => $args{hmac_key},  # undef for none
        hmac     => undef,
    };
    bless $self, $class;
    return $self;
}

sub set_header {
    my ($self, $key, $val) = @_;
    $self->{headers}{$key} = $val;
}

sub serialize {
    my ($self) = @_;
    my $body = $self->{body} // '';
    $self->{headers}{'Content-Length'} = length($body);

    my $start = join(' ', $self->{method}, $self->{path}, $self->{version}) . "\r\n";
    my $hdrs  = '';
    for my $k (sort keys %{$self->{headers}}) {
        $hdrs .= "$k: $self->{headers}{$k}\r\n";
    }
    my $frame = $start . $hdrs . "\r\n" . $body;

    if (defined $self->{hmac_key}) {
        $self->{hmac} = hmac_sha256_hex($frame, $self->{hmac_key});
        $frame .= "\r\nHMAC: $self->{hmac}\r\n";
    }
    return $frame;
}

sub parse {
    my ($class, $buf, %opts) = @_;
    my ($start, $rest) = split(/\r\n/, $buf, 2);
    die "Invalid start line" unless defined $start && $start =~ /^(\S+)\s+(\S+)\s+(\S+)$/;
    my ($method, $path, $version) = ($1, $2, $3);

    my ($headers_str, $after_hdrs) = split(/\r\n\r\n/, $rest, 2);
    die "Missing header separator" unless defined $after_hdrs;

    my %headers;
    for my $line (split /\r\n/, $headers_str) {
        next unless length $line;
        my ($k, $v) = $line =~ /^([^:]+):\s*(.*)$/;
        die "Invalid header: $line" unless defined $k;
        $headers{$k} = $v;
    }

    my $len = $headers{'Content-Length'} // 0;
    my $body = substr($after_hdrs, 0, $len);
    my $tail = substr($after_hdrs, $len);

    my $hmac;
    if ($tail =~ /\r\nHMAC:\s*([0-9a-fA-F]+)\r\n/) {
        $hmac = $1;
        if (defined $opts{hmac_key}) {
            my $check = hmac_sha256_hex(join(' ', $method, $path, $version) . "\r\n"
                . join('', map { "$_: $headers{$_}\r\n" } sort keys %headers)
                . "\r\n" . $body, $opts{hmac_key});
            die "HMAC mismatch" unless lc($check) eq lc($hmac);
        }
    }

    return bless {
        method  => $method,
        path    => $path,
        version => $version,
        headers => \%headers,
        body    => $body,
        hmac    => $hmac,
        hmac_key => $opts{hmac_key},
    }, $class;
}

1;
```
