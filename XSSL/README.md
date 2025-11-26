# Welcome 

## 🏛️ XSSL Custom Validation Certificate Authority

A Certificate Authority (CA) in your XSSL framework issues, signs, and validates certificates. 
Since you’re working with decentralized trust, we’ll make the CA pluggable and extensible.

## Example Source Code

```pl

package XSSL::CA;
use strict;
use warnings;
use JSON;
use Crypt::Ed25519;

sub new {
    my ($class, $keypair) = @_;
    my $self = { keypair => $keypair };
    bless $self, $class;
    return $self;
}

sub issue_cert {
    my ($self, $subject, $validity, $extensions) = @_;
    my $serial = time . int(rand(1000));
    my $cert = {
        issuer => "XSSL-CA",
        serial => $serial,
        subject => $subject,
        validity => $validity,
        publicKey => $self->{keypair}->{public},
        signatureAlgorithm => "Ed25519",
        extensions => $extensions
    };

    # Sign certificate
    my $data = encode_json($cert);
    my $sig = Crypt::Ed25519::sign($self->{keypair}->{private}, $data);
    $cert->{signature} = unpack("H*", $sig);

    return encode_json($cert);
}

sub verify_cert {
    my ($self, $cert_json) = @_;
    my $cert = decode_json($cert_json);

    # Check validity period
    my $now = time;
    return 0 if $now < str2time($cert->{validity}->{notBefore});
    return 0 if $now > str2time($cert->{validity}->{notAfter});

    # Verify signature
    my $sig = pack("H*", $cert->{signature});
    my $data = encode_json({ %$cert, signature => undef });
    return Crypt::Ed25519::verify($cert->{publicKey}, $data, $sig);
}
1;



```

## Json Source Code Example
## Validation Work Flow

- Signature Check → Ensure certificate integrity.
- Validity Period → Reject expired/not-yet-valid certs.
- Revocation Check → Query CRL or OCSP.
- Extensions → Enforce roles/usage (e.g., only clientAuth allowed).
- Decentralized Authority → Plug in multiple issuers or threshold signatures.


```json


{
  "issuer": "XSSL-CA",
  "serial": "ABC123456789",
  "subject": {
    "commonName": "client.example",
    "organization": "Top Code Labs",
    "country": "US"
  },
  "validity": {
    "notBefore": "2025-11-26T00:00:00Z",
    "notAfter": "2026-11-26T00:00:00Z"
  },
  "publicKey": "BASE64_ENCODED_PUBLIC_KEY",
  "signatureAlgorithm": "Ed25519",
  "signature": "BASE64_SIGNATURE",
  "extensions": {
    "usage": ["clientAuth", "serverAuth"],
    "roles": ["developer", "tester"],
    "revocation": {
      "crl_url": "https://ca.example/crl.json",
      "ocsp_url": "https://ca.example/ocsp"
    }
  }
}

```
