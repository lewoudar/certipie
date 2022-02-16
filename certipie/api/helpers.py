"""Some helper functions."""
import shutil
import zipfile
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .schemas import PrivateKeyInput


def delete_tmp_dir(tmp_dir: str) -> None:
    shutil.rmtree(tmp_dir)


def get_pk_info(pk_info: Optional[PrivateKeyInput] = None) -> PrivateKeyInput:
    return pk_info if pk_info is not None else PrivateKeyInput()


def create_public_key(tmp_path: Path, private_key: rsa.RSAPrivateKey, pk_info: PrivateKeyInput) -> Path:
    public_key_path = tmp_path / f'{pk_info.filename_prefix}.pub'
    with public_key_path.open('wb') as f:
        f.write(private_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))

    return public_key_path


def create_zipfile(zip_path: Path, path_list: list[Path]) -> None:
    with zipfile.ZipFile(f'{zip_path}', 'w') as my_zip:
        for path in path_list:
            my_zip.write(str(path))
