import pytest

from certipie.cli.main import cert
from certipie.core import create_private_key
from tests.helpers import assert_cert, skip_mac_os


@pytest.fixture()
def base_arguments() -> list[str]:
    return ['auto-cert', '-c', 'FR', '-s', 'Ile-de-France', '-C', 'Paris', '-o', 'hell yeah', '-n', 'localhost']


@pytest.mark.parametrize('country', ['c', 'CAM'])
def test_should_print_error_when_country_is_not_correct(runner, base_arguments, country):
    base_arguments[2] = country
    result = runner.invoke(cert, base_arguments)

    assert result.exit_code == 2
    assert 'country must be a 2 letters string' in result.output


@pytest.mark.parametrize('validity', ['0', '4.5'])
def test_should_print_error_when_validity_is_not_valid_integer(runner, base_arguments, validity):
    base_arguments.extend(['-v', validity])
    result = runner.invoke(cert, base_arguments)

    assert result.exit_code == 2
    assert 'validity' in result.output


@pytest.mark.parametrize('domain', ['4', 'foo'])
def test_should_print_error_when_common_name_is_not_correct(runner, base_arguments, domain):
    base_arguments[10] = domain
    result = runner.invoke(cert, base_arguments)

    assert result.exit_code == 2
    assert f'{domain} is neither "localhost" nor a valid domain name' in result.output


@pytest.mark.parametrize('alternative_name', ['foo', 4])
def test_should_print_error_when_alt_nane_is_not_correct(runner, base_arguments, alternative_name):
    base_arguments.extend(['-a', f'foo.com,{alternative_name}'])
    result = runner.invoke(cert, base_arguments)

    assert result.exit_code == 2
    assert f"These items are not auto cert values: ['{alternative_name}']" in result.output


# noinspection DuplicatedCode
def test_should_print_error_if_key_does_not_exist(runner, base_arguments):
    base_arguments.extend(['-k', 'foo.key'])
    result = runner.invoke(cert, base_arguments)

    assert result.exit_code == 2
    assert 'key' in result.output
    assert 'foo.key' in result.output


def test_should_print_error_when_key_is_not_correct(tmp_path, runner, base_arguments):
    key_path = tmp_path / 'key.pem'
    key_path.write_text('fake private key')
    base_arguments.extend(['-k', f'{key_path}'])
    result = runner.invoke(cert, base_arguments, input='\n')

    assert result.exit_code == 2
    assert 'The key file is not valid or the algorithm used is unsupported.' in result.output


def test_should_print_error_if_directory_does_not_exist(runner, base_arguments):
    base_arguments.extend(['-d', 'fake_dir'])
    result = runner.invoke(cert, base_arguments)

    assert result.exit_code == 2
    assert 'directory' in result.output
    assert 'fake_dir' in result.output


TO_PARAMETRIZE = (
    'country_option',
    'state_option',
    'city_option',
    'organization_option',
    'common_name_option',
    'alt_name_option',
)


@skip_mac_os
@pytest.mark.parametrize(
    TO_PARAMETRIZE,
    [
        ('-c', '-s', '-C', '-o', '-n', '-a'),
        ('--country', '--state', '--city', '--organization', '--name', '--alt-names'),
    ],
)
def test_should_create_auto_cert_without_giving_private_key(
    runner,
    isolated_path,
    country_option,
    state_option,
    city_option,
    organization_option,
    common_name_option,
    alt_name_option,
):
    result = runner.invoke(
        cert,
        [
            'auto-cert',
            country_option,
            'FR',
            state_option,
            'Ile-de-France',
            city_option,
            'Paris',
            organization_option,
            'hell yeah',
            common_name_option,
            'foo.com',
            alt_name_option,
            'foo.com,*.bar.com,192.168.1.1,::1',
        ],
    )

    assert result.exit_code == 0
    assert result.output == f'The self-signed certificate has been successfully created in {isolated_path}\n'

    paths = [path for path in isolated_path.iterdir()]
    assert len(paths) == 2
    assert_cert(paths)


@pytest.mark.parametrize(('filename_option', 'directory_option'), [('-f', '-d'), ('--filename', '--directory')])
def test_should_create_auto_cert_with_given_private_key_and_passphrase(
    runner, tmp_path, private_key, base_arguments, filename_option, directory_option
):
    base_arguments.extend([filename_option, 'my_cert.pem', directory_option, tmp_path, '-k', private_key])
    result = runner.invoke(cert, base_arguments, input='passphrase\n')

    assert result.exit_code == 0
    assert f'The self-signed certificate has been successfully created in {tmp_path}\n' in result.output

    paths = [path for path in tmp_path.iterdir()]
    assert len(paths) == 2
    assert_cert(paths, 'my_cert')


def test_should_create_auto_cert_with_given_private_key_and_no_passphrase(runner, tmp_path, base_arguments):
    key_path = tmp_path / 'key.pem'
    create_private_key(f'{key_path}')
    base_arguments.extend(['-d', tmp_path, '-k', key_path])
    result = runner.invoke(cert, base_arguments, input='\n')

    assert result.exit_code == 0
    assert f'The self-signed certificate has been successfully created in {tmp_path}\n' in result.output

    paths = [path for path in tmp_path.iterdir()]
    assert len(paths) == 2
    assert_cert(paths)
