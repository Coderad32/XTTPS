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
