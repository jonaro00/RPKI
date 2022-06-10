#!/usr/bin/env python3
"""
Verify an RPKI chain of certificates.

Usage:
```
$ ./certs.py [rsync_path]
```

Author: Johan Berg, 2022-06-08
"""

import base64
from pathlib import Path
import sys

from Crypto.Util import asn1 # pip install pycryptodome
from cryptography import x509 # pip install cryptography
from cryptography.hazmat.backends.openssl.rsa import _RSAPublicKey
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)
import sysrsync # pip install sysrsync


# Where to store RPKI objects
OBJ_DIR = Path('objects')
# Where TAL files are stored
TAL_DIR = Path('tal')


def verify_ta(path: str, cert: x509.Certificate) -> Path:
    """Looks through files in the TAL directory for a certificate
    with a matching `path`, and verifies that the TAL's public key
    matches the one of `cert`."""
    for tal_file in TAL_DIR.iterdir():
        text = tal_file.read_text()
        if path in text:
            tal_pk_der = base64.b64decode(text.split('\n\n')[-1])
            cert_pk_der = cert.public_key().public_bytes(
                Encoding.DER,
                PublicFormat.SubjectPublicKeyInfo,
            )
            if not tal_pk_der == cert_pk_der:
                raise ValueError('TAL Public keys did not match.')
            return tal_file
    raise ValueError(
        'Did not find provided root certificate URI in any TAL file.'
    )


def print_cert(cert: x509.Certificate) -> None:
    """Prints out various properties of a certificate."""
    print(
        '[CERTIFICATE'
        f' {cert.subject.rfc4514_string().removeprefix("CN=")}]'
    )
    print(f'  Serial: {cert.serial_number}')
    print(f'  Not valid before: {cert.not_valid_before}')
    print(f'  Not valid after: {cert.not_valid_after}')
    print(f'  Issuer: {cert.issuer.rfc4514_string()}')
    print(f'  Subject: {cert.subject.rfc4514_string()}')
    print(f'  Algorithm: {cert.signature_algorithm_oid._name}')
    print(f'  Public Key bit length: {cert.public_key().key_size}')
    print(f'  Number of Extentions: {len(cert.extensions)}')
    print( '  Extensions (not all shown):')
    for e in cert.extensions._extensions:
        match e.oid.dotted_string:
            case '1.3.6.1.5.5.7.1.1' | '1.3.6.1.5.5.7.1.11':
                print(f'    {e.oid._name}:')
                for desc in e.value:
                    print(
                        f'      {desc.access_method._name}:'
                        f' {desc.access_location.value}'
                    )
            case '2.5.29.31':
                print(f'    {e.oid._name}:')
                print(f'      {e.value[0].full_name[0].value}')


def verify_signature(
        issuer_public_key: _RSAPublicKey,
        cert: x509.Certificate,
    ) -> None:
    """Verifies that the cert is signed by the issuer's private key."""
    issuer_public_key.verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm,
    )


def extract_cert(der: bytes) -> bytes:
    """Extracts the bytes containing the certificate from a .roa
    or .mft file, so that it can be parsed like a .cer file."""
    parsed_der = asn1.DerSequence()
    # skip to signedData sequence
    parsed_der.decode(der[19:])
    # choose 3rd element (certificates), and skip to sequence start
    parsed_der.decode(parsed_der[3][4:])
    return parsed_der.encode()


def fetch_rsync_resource(
        path: str,
        target_dir: Path | str = '.',
    ) -> None:
    """Downloads rsync path to target directory."""
    if not path.startswith('rsync://'):
        raise ValueError('Invalid rsync path')
    Path(target_dir).mkdir(exist_ok=True)
    sysrsync.run(
        source=path,
        destination=str(target_dir),
        options=['--no-motd'],
        sync_source_contents=False,
    )


def validate_cert_chain(
        path: str,
        chain: list = [],
        prev_cert: x509.Certificate = None,
    ) -> None:
    """Recursively fetches and validates a chain of signed objects or
    certificates until a self-signed certificate is encountered."""
    print()
    if path in chain:
        raise ValueError('Loop detected')
    chain.append(path)
    fetch_rsync_resource(path, OBJ_DIR)
    der = (OBJ_DIR / path.split('/')[-1]).read_bytes()
    try:
        cert = x509.load_der_x509_certificate(der)
    except ValueError:
        cert = x509.load_der_x509_certificate(extract_cert(der))
    if prev_cert:
        verify_signature(cert.public_key(), prev_cert)
        print(
            f'Valid signature: The private key of {cert.serial_number}'
            f' signed {prev_cert.serial_number}'
            '\n'
        )
    print_cert(cert)
    if cert.issuer == cert.subject:
        print('\nArrived at self-signed certificate')
        found_tal = verify_ta(path, cert)
        print(
            '\nRoot certificate URI and '
            'its public key matches TAL file:'
        )
        print(f'{path!r} found in {found_tal}')
        return
    for e in cert.extensions._extensions:
        if e.oid.dotted_string == '1.3.6.1.5.5.7.1.1':
            validate_cert_chain(
                e.value[0].access_location.value,
                chain,
                cert,
            )
            break
    else:
        raise ValueError('Issuer not found')


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Please provide an rsync path to an RPKI object.')
        exit()
    print(f'Checking certificate chain starting from {sys.argv[1]}')
    validate_cert_chain(sys.argv[1])
