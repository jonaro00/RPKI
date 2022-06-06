#!/usr/bin/env python3

from pathlib import Path
import sys

import sysrsync
from cryptography import x509
from cryptography.hazmat.backends.openssl.rsa import _RSAPublicKey
from cryptography.hazmat.primitives.asymmetric import padding


OBJ_DIR = Path('objects')


def print_cert(cert: x509.Certificate) -> None:
    print('CERTIFICATE:')
    print(f'  Serial: {cert.serial_number}')
    print(f'  Not valid before: {cert.not_valid_before}')
    print(f'  Not valid after: {cert.not_valid_after}')
    print(f'  Issuer: {cert.issuer.rfc4514_string()}')
    print(f'  Subject: {cert.subject.rfc4514_string()}')
    print(f'  Algorithm: {cert.signature_algorithm_oid._name}')
    print(f'  Public Key: {cert.public_key()}')
    print(f'  # of Extentions: {len(cert.extensions)}')
    # print(f'  {cert.extensions=}')
    for e in cert.extensions._extensions:
        match e.oid.dotted_string:
            case '1.3.6.1.5.5.7.1.1' | '1.3.6.1.5.5.7.1.11':
                print(f'    {e.oid._name}:')
                for desc in e.value:
                    print(f'      {desc.access_method._name}: {desc.access_location.value}')
            case '2.5.29.31':
                print(f'    {e.oid._name}:')
                print(f'      {e.value[0].full_name[0].value}')


def verify_signature(issuer_public_key: _RSAPublicKey, cert: x509.Certificate) -> None:
    issuer_public_key.verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm,
    )


def validate_cert_chain(path: str, chain: list = [], prev_cert: x509.Certificate = None) -> None:
    if not path.startswith('rsync://'):
        raise ValueError('Invalid rsync path')
    if path in chain:
        raise ValueError('Loop detected')
    print()
    chain.append(path)
    OBJ_DIR.mkdir(exist_ok=True)
    sysrsync.run(
        source=path,
        destination=str(OBJ_DIR),
        options=['--no-motd'],
        sync_source_contents=False,
    )
    der = (OBJ_DIR / path.split('/')[-1]).read_bytes()
    cert = x509.load_der_x509_certificate(der)
    if prev_cert:
        verify_signature(cert.public_key(), prev_cert)
        print(f'Valid signature: The private key of {cert.serial_number} signed {prev_cert.serial_number}')
        print()
    print_cert(cert)
    if cert.issuer == cert.subject:
        print('Self-signed certificate')
        return
    for e in cert.extensions._extensions:
        match e.oid.dotted_string:
            case '1.3.6.1.5.5.7.1.1':
                validate_cert_chain(e.value[0].access_location.value, chain, cert)
                break
    else:
        raise ValueError('Issuer not found')


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Please provide an rsync path to an RPKI certificate.')
        exit()
    print(f'Checking certificate chain starting from {sys.argv[1]}')
    validate_cert_chain(sys.argv[1])
