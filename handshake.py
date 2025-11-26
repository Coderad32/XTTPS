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
