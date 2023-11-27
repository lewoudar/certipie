# ruff: noqa: S602
import subprocess  # nosec
from pathlib import Path

import click
import shellingham

SHELLS = ['bash', 'zsh', 'fish']


def install_bash_zsh(bash: bool = True) -> None:
    home = Path.home()
    completion_dir = home / '.cli_completions'
    if bash:
        shell = 'bash'
        shell_config_file = home / '.bashrc'
    else:
        shell = 'zsh'
        shell_config_file = home / '.zshrc'

    if not completion_dir.exists():
        completion_dir.mkdir()

    try:
        command = f'_CERT_COMPLETE={shell}_source cert'
        # bandit complains about shell injection, but we are not using untrusted string here, so it is fine.
        result = subprocess.run(command, shell=True, capture_output=True, check=True)  # nosec
    except subprocess.CalledProcessError:
        click.secho('unable to get completion script for cert cli.', fg='red')
        raise click.Abort() from None

    completion_script = completion_dir / f'cert-complete.{shell}'
    completion_script.write_text(result.stdout.decode())

    with shell_config_file.open('a') as f:
        f.write(f'\n. {completion_script.absolute()}\n')


def install_fish() -> None:
    home = Path.home()
    completion_dir = home / '.config/fish/completions'
    if not completion_dir.exists():
        completion_dir.mkdir(parents=True)

    try:
        command = '_CERT_COMPLETE=fish_source cert'
        # bandit complains about shell injection, but we are not using untrusted string here, so it is fine.
        result = subprocess.run(command, shell=True, capture_output=True, check=True)  # nosec
    except subprocess.CalledProcessError:
        click.secho('unable to get completion script for cert cli.', fg='red')
        raise click.Abort() from None

    completion_script = completion_dir / 'cert.fish'
    completion_script.write_text(result.stdout.decode())


def _install_completion(shell: str) -> None:
    if shell == 'bash':
        install_bash_zsh()
    elif shell == 'zsh':
        install_bash_zsh(bash=False)
    else:
        install_fish()


@click.command('install-completion')
def install_completion():
    """
    Install completion script for bash, zsh and fish shells.
    You will need to restart the shell for the changes to be loaded.
    """
    try:
        shell, _ = shellingham.detect_shell()
    except shellingham.ShellDetectionFailure:
        click.secho('unable to detect the current shell', fg='red')
        raise click.Abort() from None
    except RuntimeError as e:
        click.echo(f'[error]{e}')
        raise click.Abort() from None

    if shell not in SHELLS:
        click.secho(f'Your shell is not supported. Shells supported are: {", ".join(SHELLS)}')
        raise click.Abort()

    _install_completion(shell)
