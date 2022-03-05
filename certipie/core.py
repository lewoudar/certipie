import ipaddress
import re
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Union, Protocol, runtime_checkable, AnyStr

import idna
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key, Encoding, PrivateFormat, BestAvailableEncryption, NoEncryption, PublicFormat
)
from cryptography.x509 import CertificateSigningRequest, Certificate
from cryptography.x509.oid import NameOID
from pydantic import validate_arguments, constr, conint, FilePath, Field

from . import types


@validate_arguments
def create_private_key(
        filename: constr(strict=True, min_length=1),
        key_size: conint(ge=512) = 2048,
        passphrase: AnyStr = b''
) -> rsa.RSAPrivateKey:
    """Creates an RSA private key given the filename, key size and optional passphrase."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    if not passphrase:
        encryption_algorithm = NoEncryption()
    else:
        encryption_algorithm = BestAvailableEncryption(passphrase)
    with open(filename, 'wb') as f:
        f.write(key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=encryption_algorithm,
        ))

    return key


@validate_arguments(config={'arbitrary_types_allowed': True})
def get_public_key_from_private_key(file_path: Path, private_key: rsa.RSAPrivateKey) -> None:
    """Retrieves public key from private key file and saves it in a file."""
    with file_path.open('wb') as f:
        f.write(private_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))


# shamefully copied from the validators library
domain_pattern = re.compile(
    r'^(?:[a-zA-Z0-9]'  # First character of the domain
    r'(?:[a-zA-Z0-9-_]{0,61}[A-Za-z0-9])?\.)'  # Sub domain + hostname
    r'+[A-Za-z0-9][A-Za-z0-9-_]{0,61}'  # First 61 characters of the gTLD
    r'[A-Za-z]$'  # Last character of the gTLD
)


def get_idn_domain_name(domain_name: str) -> str:
    if domain_name.startswith('*.'):
        idn = b'*.' + idna.encode(domain_name[2:], uts46=True)
        return idn.decode('ascii')
    return idna.encode(domain_name, uts46=True).decode('ascii')


def is_domain_name(domain_name: str) -> bool:
    domain_name = domain_name[2:] if domain_name.startswith('*.') else domain_name
    try:
        return domain_pattern.match(get_idn_domain_name(domain_name)) is not None
    except idna.IDNAError:
        return False


@runtime_checkable
class PrivateKey(Protocol):
    def public_key(self):  # pragma: no cover
        ...


def _get_name_attributes(
        country: str,
        state_or_province: str,
        city: str,
        organization: str,
        common_name: str
) -> list[x509.NameAttribute]:
    return [
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_or_province),
        x509.NameAttribute(NameOID.LOCALITY_NAME, city),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ]


def _get_private_key(
        filename: str, private_key: Union[Path, PrivateKey] = None, passphrase: AnyStr = b''
) -> types.PrivateKey:
    file_path = Path(filename)
    private_key_path = file_path.parent / f'{uuid.uuid4()}-key.pem'
    if private_key is None:
        return create_private_key(f'{private_key_path}')

    # we use the protocol version to avoid list entirely all cryptography private key classes
    if isinstance(private_key, PrivateKey):
        return private_key  # type: ignore
    else:
        return load_pem_private_key(private_key.read_bytes(), passphrase or None)


@validate_arguments(config={'arbitrary_types_allowed': True})
def create_csr(
        filename: constr(strict=True, min_length=1),
        country: constr(strict=True),
        state_or_province: constr(strict=True),
        city: constr(strict=True),
        organization: constr(strict=True),
        common_name: constr(strict=True, max_length=255),
        alternative_names: list[constr(strict=True, max_length=255)] = None,
        private_key: Union[FilePath, PrivateKey] = None,
        passphrase: AnyStr = b''
) -> CertificateSigningRequest:
    """Creates a certificate signing request and eventually an RSA private key if it is not given as input."""
    if not is_domain_name(common_name):
        raise ValueError(f'{common_name} is not a valid domain name')

    alternative_names = alternative_names if alternative_names is not None else [common_name]
    incorrect = []
    for alternative_name in alternative_names:
        if not is_domain_name(alternative_name):
            incorrect.append(alternative_name)
    if incorrect:
        raise ValueError(f'the following alternative names are not valid domain names: {", ".join(incorrect)}')

    key = _get_private_key(filename, private_key, passphrase)

    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(
        # Provide various details about the organization.
        _get_name_attributes(country, state_or_province, city, organization, common_name)
    )).add_extension(
        x509.SubjectAlternativeName([
            # Describe what sites we want this certificate for.
            x509.DNSName(get_idn_domain_name(alt_name)) for alt_name in alternative_names
        ]),
        critical=False,
    ).sign(key, hashes.SHA256())

    with open(filename, 'wb') as f:
        f.write(csr.public_bytes(Encoding.PEM))

    return csr


# we don't use this function in create_csr for speed improvement
# normally for a csr, you provide only domain names
# this function is inspired by the trustme library
def normalize_alternative_name(value: str) -> x509.GeneralName:
    if '@' in value:
        return x509.RFC822Name(value)

    try:
        return x509.IPAddress(ipaddress.ip_address(value))
    except ValueError:
        try:
            return x509.IPAddress(ipaddress.ip_network(value))
        except ValueError:
            pass

    return x509.DNSName(get_idn_domain_name(value))


def _default_end_datetime() -> datetime:
    return datetime.utcnow() + timedelta(days=365)


@validate_arguments(config={'arbitrary_types_allowed': True})
def create_auto_certificate(
        filename: constr(strict=True, min_length=1),
        country: constr(strict=True),
        state_or_province: constr(strict=True),
        city: constr(strict=True),
        organization: constr(strict=True),
        common_name: constr(strict=True, max_length=255) = 'localhost',
        alternative_names: list[constr(strict=True)] = None,
        private_key: Union[FilePath, PrivateKey] = None,
        passphrase: AnyStr = b'',
        end_validity: datetime = Field(default_factory=_default_end_datetime)
) -> Certificate:
    """Creates a self-signed certificate and eventually an RSA private key if it is not given as input."""
    if common_name.lower() != 'localhost' and not is_domain_name(common_name):
        raise ValueError(f'{common_name} is not a valid domain name')

    if alternative_names is None:
        alternative_names = ['localhost', '::1', '127.0.0.1']

    alternative_names = [normalize_alternative_name(alt_name) for alt_name in alternative_names]
    key = _get_private_key(filename, private_key, passphrase)
    subject = issuer = x509.Name(_get_name_attributes(country, state_or_province, city, organization, common_name))

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        # we put the base date on 2000-01-01, so we get cover!
        datetime(2000, 1, 1)
    ).not_valid_after(
        end_validity
    ).add_extension(
        x509.SubjectAlternativeName(alternative_names),
        critical=False,
        # Sign our certificate with our private key
    ).sign(key, hashes.SHA256())

    with open(filename, 'wb') as f:
        f.write(cert.public_bytes(Encoding.PEM))

    return cert
