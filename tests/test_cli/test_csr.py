import pytest

from certipie.cli.main import cert
from certipie.core import create_private_key
from tests.helpers import assert_csr


@pytest.fixture()
def base_arguments() -> list[str]:
    return [
        'csr', '-c', 'FR', '-s', 'Ile-de-France', '-C', 'Paris', '-o', 'hell yeah', '-n', 'foo.com', '-a',
        'foo.com,*.bar.com'
    ]


@pytest.mark.parametrize('country', ['c', 'CAM'])
def test_should_print_error_when_country_is_not_correct(runner, base_arguments, country):
    base_arguments[2] = country
    result = runner.invoke(cert, base_arguments)

    assert result.exit_code == 2
    assert 'country must be a 2 letters string' in result.output


@pytest.mark.parametrize('domain', ['4', 'foo'])
def test_should_print_error_when_common_name_is_not_correct(runner, base_arguments, domain):
    base_arguments[10] = domain
    result = runner.invoke(cert, base_arguments)

    assert result.exit_code == 2
    assert f'{domain} is not a valid domain name' in result.output


@pytest.mark.parametrize('alternative_name', ['4', 'foo'])
def test_should_print_error_when_alternative_name_is_not_correct(runner, base_arguments, alternative_name):
    base_arguments[12] = f'bar.com,{alternative_name}'
    result = runner.invoke(cert, base_arguments)

    assert result.exit_code == 2
    assert f'These items are not domain names: {[alternative_name]}' in result.output


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
    'country_option', 'state_option', 'city_option', 'organization_option', 'common_name_option', 'alt_name_option'
)


@pytest.mark.parametrize(TO_PARAMETRIZE, [
    ('-c', '-s', '-C', '-o', '-n', '-a'),
    ('--country', '--state', '--city', '--organization', '--name', '--alt-names')
])
def test_should_create_csr_without_giving_private_key(
        runner, isolated_path, country_option, state_option, city_option, organization_option, common_name_option,
        alt_name_option
):
    result = runner.invoke(cert, [
        'csr',
        country_option, 'FR',
        state_option, 'Ile-de-France',
        city_option, 'Paris',
        organization_option, 'hell yeah',
        common_name_option, 'foo.com',
        alt_name_option, 'foo.com,*.bar.com'
    ])
    assert result.exit_code == 0
    assert result.output == f'The certificate signing request has been successfully created in {isolated_path}\n'

    paths = [path for path in isolated_path.iterdir()]
    assert len(paths) == 2
    assert_csr(paths)


@pytest.mark.parametrize(('filename_option', 'directory_option'), [
    ('-f', '-d'),
    ('--filename', '--directory')
])
def test_should_create_csr_with_given_private_key_and_passphrase(
        runner, tmp_path, private_key, base_arguments, filename_option, directory_option
):
    base_arguments.extend([filename_option, 'my_csr.pem', directory_option, tmp_path, '-k', private_key])
    result = runner.invoke(cert, base_arguments, input='passphrase\n')

    assert result.exit_code == 0
    assert f'The certificate signing request has been successfully created in {tmp_path}\n' in result.output

    paths = [path for path in tmp_path.iterdir()]
    assert len(paths) == 2
    assert_csr(paths, 'my_csr')


def test_should_create_csr_with_given_private_key_and_no_passphrase(
        runner, tmp_path, base_arguments
):
    key_path = tmp_path / 'key.pem'
    create_private_key(f'{key_path}')
    base_arguments.extend(['-d', tmp_path, '-k', key_path])
    result = runner.invoke(cert, base_arguments, input='\n')

    assert result.exit_code == 0
    assert f'The certificate signing request has been successfully created in {tmp_path}\n' in result.output

    paths = [path for path in tmp_path.iterdir()]
    assert len(paths) == 2
    assert_csr(paths)
