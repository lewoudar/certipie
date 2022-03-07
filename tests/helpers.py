import platform
from pathlib import Path

import pytest


def assert_private_key(paths: list[Path], prefix='id_rsa') -> None:
    for path in paths:
        assert path.stem == prefix
        if path.suffix == 'pub':
            assert path.read_text().startswith('-----BEGIN PUBLIC KEY-----')
        else:
            path.read_text().startswith('-----BEGIN RSA PRIVATE KEY-----')


def assert_csr(paths: list[Path], prefix='csr') -> None:
    for path in paths:
        if 'key' in path.name:
            assert path.read_text().startswith('-----BEGIN RSA PRIVATE KEY-----')
        else:
            assert path.name == f'{prefix}.pem'
            assert path.read_text().startswith('-----BEGIN CERTIFICATE REQUEST-----')


def assert_cert(paths: list[Path], prefix='cert') -> None:
    for path in paths:
        if 'key' in path.name:
            assert path.read_text().startswith('-----BEGIN RSA PRIVATE KEY-----')
        else:
            assert path.name == f'{prefix}.pem'
            assert path.read_text().startswith('-----BEGIN CERTIFICATE-----')


MAC_OS_SKIP = """
It seems there is an issue when changing current working directory to a temporary one using runner.isolated_filesystem()
function. It will probably don't affect real cli usage, so we can skip the tests for now and search latter for a better
solution.
"""

skip_mac_os = pytest.mark.skipif(platform.system() == 'Darwin', reason=MAC_OS_SKIP)
