from pathlib import Path

import pytest

from certipie.core import create_private_key


@pytest.fixture()
def private_key(tmp_path) -> Path:
    """A private key to use in tests"""
    key = tmp_path / 'key.pem'
    create_private_key(f'{key}', passphrase=b'passphrase')
    return key
