import zipfile
from pathlib import Path

import pytest
from click.testing import CliRunner
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
    to_delete: list[Path] = []

    def _unzip_file(content: bytes, tmp_path: Path) -> list[Path]:
        nonlocal to_delete
        paths = []
        filename = tmp_path / 'file.zip'
        with filename.open('wb') as archive:
            archive.write(content)

        with zipfile.ZipFile(filename) as my_zip:
            for file in my_zip.namelist():
                my_zip.extract(file)
                paths.append(Path(file))
            # don't forget to save a reference to the list to delete files after
            to_delete = paths[:]
            return paths

    yield _unzip_file

    for path in to_delete:
        path.unlink()


@pytest.fixture()
def runner():
    """CLI test runner"""
    return CliRunner()


@pytest.fixture()
def isolated_path(runner) -> Path:
    """Returns a path corresponding to an isolated folder suitable for file testing."""
    with runner.isolated_filesystem() as d:
        yield Path(d)
