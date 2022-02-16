import tempfile
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends
from fastapi.responses import FileResponse

from .helpers import create_public_key, create_zipfile, get_pk_info, delete_tmp_dir
from .schemas import PrivateKeyInput
from ..core import create_private_key

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
