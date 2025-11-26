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
