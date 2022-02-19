import tempfile
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import APIRouter, BackgroundTasks, Depends, Form
from fastapi.responses import FileResponse

from .helpers import create_public_key, create_zipfile, get_pk_info, delete_tmp_dir, get_private_key, get_passphrase
from .schemas import PrivateKeyInput, DomainName
from ..core import create_private_key, create_csr

router = APIRouter(tags=['certificate'])


@router.post('/private-key', response_class=FileResponse)
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
    return f'{zip_path}'


@router.post('/csr', response_class=FileResponse)
def get_csr(
        background_tasks: BackgroundTasks,
        private_key: Optional[rsa.RSAPrivateKey] = Depends(get_private_key),
        passphrase: bytes = Depends(get_passphrase),
        filename_prefix: str = Form(
            'csr',
            description=(
                    'the prefix of the file created. For example if you pass "csr" you will receive a file "csr.pem". '
                    'If not provided, defaults to "csr".'
            ),
            example='csr'
        ),
        country: str = Form(
            ..., description='Two letter code of your country', example='FR', min_length=2, max_length=2
        ),
        state_or_province: str = Form(..., description='the state or province information', example='Ile-de-France'),
        city: str = Form(..., description='the city information', example='Paris'),
        organization: str = Form(..., description='the organization information', example='Organization Inc.'),
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
    return f'{zip_path}'
