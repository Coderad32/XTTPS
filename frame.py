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
