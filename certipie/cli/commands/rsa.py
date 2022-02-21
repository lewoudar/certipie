from pathlib import Path

import click

from certipie.core import create_private_key, get_public_key_from_private_key


def get_path(ctx, param, value):
    if value:
        return Path(value)
    return Path.cwd()


@click.command()
@click.option(
    '-f', '--filename',
    help='Name of the private key. The public key name will be derived from it and ends with a "pub" suffix.',
    default='id_rsa.pem',
    show_default=True
)
@click.option('-s', '--size', type=click.IntRange(min=512), help='The key size.', default=2048, show_default=True)
@click.password_option('-p', '--passphrase', prompt='Enter the passphrase', default='passphrase', show_default=True)
@click.option(
    '-d', '--directory',
    type=click.Path(exists=True, file_okay=False, writable=True),
    callback=get_path,
    help='The directory where the files will be created. Defaults to the current working directory if not provided.'
)
def rsa(filename: str, size: int, passphrase: str, directory: Path):
    """Creates a pair of private/public keys using the RSA algorithm."""
    # I make sure to take the name part of filename if somebody tries to give an awkward path like ../../etc/passwd
    private_key_path = directory / Path(filename).name
    public_key_path = directory / f'{private_key_path.stem}.pub'
    key = create_private_key(f'{private_key_path}', size, passphrase)
    get_public_key_from_private_key(public_key_path, key)

    click.secho(f'The pair of keys was successfully in {directory.absolute()}', fg='green')
