import ipaddress
import logging
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Optional, Union, Literal

from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import APIRouter, BackgroundTasks, Depends, Form
from fastapi.responses import FileResponse

from .helpers import (
    create_public_key, create_zipfile, get_pk_info, delete_tmp_dir, get_private_key, get_passphrase, get_date_end
)
from .schemas import (
    PrivateKeyInput, DomainName, country_form, state_or_province_form, city_form, organization_form
)
from ..core import create_private_key, create_csr, create_auto_certificate
from ..types import PrivateKey

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post('/private-key', responses={200: {'content': {'application/zip': {}}}})
def get_rsa_private_key(background_tasks: BackgroundTasks, pk_info: PrivateKeyInput = Depends(get_pk_info)):
    """Creates a zip file containing an RSA private key with his public counterpart."""
    tmp_dir = tempfile.mkdtemp()
    tmp_path = Path(tmp_dir)
    key_path = tmp_path / f'{pk_info.filename_prefix}.pem'

    # we create the zip with private and public keys
    private_key = create_private_key(f'{key_path}', pk_info.key_size, str(pk_info.passphrase))
    public_key_path = create_public_key(tmp_path, private_key, pk_info)
    zip_path = tmp_path / f'{pk_info.filename_prefix}.zip'
    create_zipfile(zip_path, [key_path, public_key_path])

    background_tasks.add_task(delete_tmp_dir, tmp_dir)
    logger.info('returns a zip file %s with private and public keys', zip_path)
    return FileResponse(f'{zip_path}', media_type='application/zip')


@router.post('/csr', responses={200: {'content': {'application/zip': {}}}})
def get_csr(
        background_tasks: BackgroundTasks,
        private_key: Optional[PrivateKey] = Depends(get_private_key),
        passphrase: bytes = Depends(get_passphrase),
        filename_prefix: str = Form(
            'csr',
            description=(
                    'the prefix of the file created. For example if you pass "csr" you will receive a file "csr.pem". '
                    'If not provided, defaults to "csr".'
            ),
            example='csr'
        ),
        country: str = country_form(...),
        state_or_province: str = state_or_province_form(...),
        city: str = city_form(...),
        organization: str = organization_form(...),
        common_name: DomainName = Form(
            ...,
            description='The common name of the csr i.e the main domain name you want to provide a certificate.',
            example='site.com'
        ),
        alternative_names: Optional[list[DomainName]] = Form(
            [],
            description=(
                    'The list of domain names covered by the certificate. If not provided, defaults to'
                    'the "common_name" value passed as input.'
            ),
            example=['site.com', 'foo.site.com']
        )
):
    """
    Generates a certificate signing request given input data and returns it in a zip file.
    If you don't pass a private key, an RSA one will be created and returned to the resulting zip file.
    """
    tmp_dir = tempfile.mkdtemp()
    tmp_path = Path(tmp_dir)
    csr_path = tmp_path / f'{filename_prefix}.pem'
    zip_path = tmp_path / f'{filename_prefix}.zip'

    create_csr(
        f'{csr_path}', country, state_or_province, city, organization, common_name, alternative_names,
        private_key=private_key, passphrase=passphrase
    )
    create_zipfile(zip_path, [path for path in tmp_path.iterdir()])

    background_tasks.add_task(delete_tmp_dir, tmp_dir)
    logger.info('returns a zip file %s with certificate signing request', zip_path)
    return FileResponse(f'{zip_path}', media_type='application/zip')


AlternativeNameType = Union[
    DomainName, ipaddress.IPv4Address, ipaddress.IPv6Address, ipaddress.IPv4Network, ipaddress.IPv6Network,
    Literal['localhost']
]


@router.post('/auto-certificate', responses={200: {'content': {'application/zip': {}}}})
def get_auto_certificate(
        background_tasks: BackgroundTasks,
        private_key: Optional[rsa.RSAPrivateKey] = Depends(get_private_key),
        passphrase: bytes = Depends(get_passphrase),
        filename_prefix: str = Form(
            'cert',
            description=(
                    'the prefix of the file created. For example if you pass "cert" you will receive a file "cert.pem".'
                    ' If not provided, defaults to "cert".'
            ),
            example='csr'
        ),
        country: str = country_form(...),
        state_or_province: str = state_or_province_form(...),
        city: str = city_form(...),
        organization: str = organization_form(...),
        common_name: Union[Literal['localhost'], DomainName] = Form(
            'localhost',
            description=(
                    'The common name of the csr i.e the main domain name you want to provide a certificate. In case'
                    'of an auto-certificate, "localhost" is a valid value and it is the default if this field is not'
                    'provided.'
            ),
            example='site.com'
        ),
        alternative_names: Optional[list[AlternativeNameType]] = Form(
            ['localhost', '127.0.0.1', '::1'],
            description=(
                    'The list of domain names, ipv4/v6 addresses or networks covered by the certificate. If not '
                    'provided, defaults to "localhost", 127.0.0.1 and ::1.'
            ),
            example=['192.168.1.1', 'local.com']
        ),
        date_end: datetime = Depends(get_date_end)
):
    """
    Generates a self-signed certificate you can use for testing and development purposes.
    If you don't provide a private key, an RSA one will be created and returned to the resulting zip file.
    """
    tmp_dir = tempfile.mkdtemp()
    tmp_path = Path(tmp_dir)
    cert_path = tmp_path / f'{filename_prefix}.pem'
    zip_path = tmp_path / f'{filename_prefix}.zip'

    create_auto_certificate(
        f'{cert_path}', country, state_or_province, city, organization, common_name, alternative_names,
        private_key=private_key, passphrase=passphrase, end_validity=date_end
    )
    create_zipfile(zip_path, [path for path in tmp_path.iterdir()])

    background_tasks.add_task(delete_tmp_dir, tmp_dir)
    logger.info('returns a zip file %s with self-signed certificate', zip_path)
    return FileResponse(f'{zip_path}', media_type='application/zip')
