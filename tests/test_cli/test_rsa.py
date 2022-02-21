import pytest

from certipie.cli.main import cert
from tests.helpers import assert_private_key


def test_should_print_error_when_key_size_is_less_than_512(runner):
    result = runner.invoke(cert, ['rsa', '-s', '40'])

    assert result.exit_code == 2
    assert "Invalid value for '-s' / '--size': 40 is not in the range x>=512." in result.output


@pytest.mark.parametrize('size_option', ['-s', '--size'])
@pytest.mark.parametrize('passphrase_option', ['-p', '--passphrase'])
def test_should_create_pair_of_keys(runner, isolated_path, size_option, passphrase_option):
    result = runner.invoke(cert, ['rsa', size_option, '3000', passphrase_option, 'foo'])
    private_key = isolated_path / 'id_rsa.pem'
    public_key = isolated_path / 'id_rsa.pub'

    assert private_key.is_file()
    assert public_key.is_file()
    assert_private_key([private_key, public_key], 'id_rsa')
    assert result.exit_code == 0
    assert result.output == f'The pair of keys was successfully in {isolated_path}\n'


@pytest.mark.parametrize('filename_option', ['-f', '--filename'])
@pytest.mark.parametrize('directory_option', ['-d', '--directory'])
def test_should_create_pair_of_keys_with_passphrase_prompt(runner, tmp_path, filename_option, directory_option):
    result = runner.invoke(cert, ['rsa', filename_option, 'key', directory_option, f'{tmp_path}'], input='foo\nfoo\n')
    private_key = tmp_path / 'key'
    public_key = tmp_path / 'key.pub'

    assert private_key.is_file()
    assert public_key.is_file()
    assert_private_key([private_key, public_key], 'key')
    assert result.exit_code == 0
    assert f'The pair of keys was successfully in {tmp_path}\n' in result.output
