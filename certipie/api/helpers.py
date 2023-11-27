"""Some helper functions."""
import shutil
import zipfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Annotated, Optional

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from fastapi import Depends, File, Form
from pydantic import BeforeValidator, SecretBytes

from ..core import get_public_key_from_private_key
from ..types import PrivateKey
from .schemas import PrivateKeyInput


def delete_tmp_dir(tmp_dir: str) -> None:
    shutil.rmtree(tmp_dir)


def get_pk_info(pk_info: Optional[PrivateKeyInput] = None) -> PrivateKeyInput:
    return pk_info if pk_info is not None else PrivateKeyInput()


def transform_string_to_bytes(value: Optional[str]) -> Optional[bytes]:
    if value:
        return value.encode()


def get_passphrase(
    passphrase: Annotated[
        Optional[SecretBytes],
        BeforeValidator(transform_string_to_bytes),
        Form(
            description='passphrase used to encrypt the private key. Can be optional.', examples=['secret passphrase']
        ),
    ] = b'',
) -> bytes:
    return passphrase if isinstance(passphrase, bytes) else passphrase.get_secret_value()


def get_private_key(
    passphrase: Annotated[bytes, Depends(get_passphrase)],
    private_key: Annotated[
        Optional[bytes],
        File(
            description=(
                'The private key used to generate the certificate signing request. If not provided, an RSA key '
                'will be created (without passphrase) and returned in the response.'
            ),
        ),
    ] = None,
) -> Optional[PrivateKey]:
    if private_key is None:
        return
    return load_pem_private_key(private_key, passphrase or None)


def get_date_end(
    end_validity: Annotated[
        int, Form(description='The number of days the certificate will be valid.', gt=0, examples=[365])
    ] = 365,
) -> datetime:
    return datetime.utcnow() + timedelta(days=end_validity)


def create_public_key(tmp_path: Path, private_key: rsa.RSAPrivateKey, pk_info: PrivateKeyInput) -> Path:
    public_key_path = tmp_path / f'{pk_info.filename_prefix}.pub'
    get_public_key_from_private_key(public_key_path, private_key)

    return public_key_path


def create_zipfile(zip_path: Path, path_list: list[Path]) -> None:
    with zipfile.ZipFile(f'{zip_path}', 'w', compression=zipfile.ZIP_DEFLATED) as my_zip:
        for path in path_list:
            my_zip.write(str(path), path.name)
