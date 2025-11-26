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
