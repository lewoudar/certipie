"""Some helper functions."""
import shutil
import zipfile
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_private_key
from fastapi import File, Form, Depends
from pydantic import SecretBytes

from .schemas import PrivateKeyInput


def delete_tmp_dir(tmp_dir: str) -> None:
    shutil.rmtree(tmp_dir)


def get_pk_info(pk_info: Optional[PrivateKeyInput] = None) -> PrivateKeyInput:
    return pk_info if pk_info is not None else PrivateKeyInput()


def get_passphrase(
        passphrase: Optional[SecretBytes] = Form(
            b'',
            description='passphrase used to encrypt the private key. Can be optional.',
            example='secret passphrase'
        ),
) -> bytes:
    return passphrase if isinstance(passphrase, bytes) else passphrase.get_secret_value()


def get_private_key(
        passphrase: bytes = Depends(get_passphrase),
        private_key: Optional[bytes] = File(
            None,
            description=(
                    'The private key used to generate the certificate signing request. If not provided, an RSA key '
                    'will be created (without passphrase) and returned in the response.'
            )
        )
) -> Optional[rsa.RSAPrivateKey]:
    if private_key is None:
        return
    return load_pem_private_key(private_key, passphrase or None)


def create_public_key(tmp_path: Path, private_key: rsa.RSAPrivateKey, pk_info: PrivateKeyInput) -> Path:
    public_key_path = tmp_path / f'{pk_info.filename_prefix}.pub'
    with public_key_path.open('wb') as f:
        f.write(private_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))

    return public_key_path


def create_zipfile(zip_path: Path, path_list: list[Path]) -> None:
    with zipfile.ZipFile(f'{zip_path}', 'w', compression=zipfile.ZIP_DEFLATED) as my_zip:
        for path in path_list:
            my_zip.write(str(path), path.name)
