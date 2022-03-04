import pytest

from certipie.cli.main import cert


@pytest.mark.parametrize('host', ['foo', '4'])
def test_should_print_error_when_host_is_not_correct(runner, host):
    result = runner.invoke(cert, ['server', '-H', host])

    assert result.exit_code == 2
    assert f'{host} is neither "localhost" nor a valid ip address' in result.output


@pytest.mark.parametrize('port', [-1, 'foo'])
def test_should_print_error_when_port_is_not_correct(runner, port):
    result = runner.invoke(cert, ['server', '-p', port])

    assert result.exit_code == 2
    assert 'port' in result.output


def test_should_print_error_when_config_file_does_not_exist(runner):
    result = runner.invoke(cert, ['server', '-c', 'foo.toml'])

    assert result.exit_code == 2
    assert 'foo.toml' in result.output


def test_should_print_error_when_config_file_is_a_directory(runner, tmp_path):
    result = runner.invoke(cert, ['server', '-c', tmp_path])

    assert result.exit_code == 2
    assert f'{tmp_path}' in result.output
    assert 'is a directory' in result.output


def test_should_run_server_without_given_any_option(runner, mocker):
    run_mock = mocker.patch('trio.run')
    result = runner.invoke(cert, ['server'])

    assert result.exit_code == 0
    run_mock.assert_called_once()


@pytest.mark.parametrize(('host_option', 'port_option'), [
    ('-H', '-p'),
    ('--host', '--port')
])
def test_should_run_server_giving_host_and_port(runner, mocker, host_option, port_option):
    run_mock = mocker.patch('trio.run')
    result = runner.invoke(cert, ['server', host_option, '127.0.0.1', port_option, '3000'])

    assert result.exit_code == 0
    run_mock.assert_called_once()


CONFIG = """
websocket_ping_interval = 10
"""


@pytest.mark.parametrize('config_file_option', ['-c', '--config'])
def test_should_run_server_giving_config_file(tmp_path, runner, mocker, config_file_option):
    run_mock = mocker.patch('trio.run')
    config_file = tmp_path / 'config.toml'
    config_file.write_text(CONFIG)
    result = runner.invoke(cert, ['server', config_file_option, config_file])

    assert result.exit_code == 0
    run_mock.assert_called_once()
