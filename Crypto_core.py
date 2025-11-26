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
