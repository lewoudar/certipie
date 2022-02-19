import shutil
import zipfile
from pathlib import Path
from typing import Optional

import pytest
from fastapi.testclient import TestClient
from requests import Session

from certipie.api import app
from certipie.core import create_private_key


@pytest.fixture()
def private_key(tmp_path) -> Path:
    """A private key to use in tests"""
    key = tmp_path / 'key.pem'
    create_private_key(f'{key}', passphrase=b'passphrase')
    return key


@pytest.fixture()
def client() -> Session:
    """A test client for the REST API."""
    return TestClient(app, base_url='http://testserver')


@pytest.fixture()
def unzip_file():
    """Helper to unzip a zip file and returns a list of paths corresponding to the files inside the zip."""
    dir_path: Optional[Path] = None

    def _unzip_file(content: bytes, tmp_path: Path) -> list[Path]:
        nonlocal dir_path
        paths = []
        filename = tmp_path / 'file.zip'
        with filename.open('wb') as archive:
            archive.write(content)

        with zipfile.ZipFile(filename) as my_zip:
            for file in my_zip.namelist():
                my_zip.extract(file)
                paths.append(Path(file))
            # don't forget to set the root path of created files for deletion
            dir_path = paths[0].parents[1]
            return paths

    yield _unzip_file

    shutil.rmtree(dir_path)
