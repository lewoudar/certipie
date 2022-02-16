from pathlib import Path

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
