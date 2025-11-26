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
