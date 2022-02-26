from pathlib import Path

import click
from cryptography.exceptions import UnsupportedAlgorithm

from certipie.cli.helpers import validate_country
from certipie.cli.options import directory_option
from certipie.cli.parameters import DOMAIN, DomainNameListParamType
from certipie.core import create_csr


@click.command()
@click.option('-f', '--filename', help='Name of the csr file', default='csr.pem', show_default=True)
@click.option('-c', '--country', prompt=True, help='Country code in two letters.', callback=validate_country)
@click.option('-s', '--state', prompt=True, help='State or province of the related organization.')
@click.option('-C', '--city', prompt=True, help='The city of the related organization.')
@click.option('-o', '--organization', prompt=True, help='The organization requesting a certificate.')
@click.option(
    '-n', '--name',
    type=DOMAIN,
    prompt=True,
    help='The common name i.e the main domain name covered by the certificate.'
)
@click.option(
    '-a', '--alt-names',
    type=DomainNameListParamType(),
    help='Alternative domain names covered by the certificate. If not provided, defaults to the common name.'
)
@click.option(
    '-k', '--key',
    type=click.Path(dir_okay=False, exists=True),
    help=(
            'The private key used to sign the certificate signing request. '
            'If not provided an RSA one with no passphrase will be created.'
    )
)
@directory_option
def csr(
        filename: str,
        country: str,
        state: str,
        city: str,
        organization: str,
        name: str,
        alt_names: list[str],
        directory: Path,
        key: str = None
):
    """
    Creates a certificate signing request file given user input.
    If you don't provide a private key, an RSA one will be created and saved in the same directory as the certificate
    signing request file.
    """
    passphrase = click.prompt('Passphrase', hide_input=True, default='') if key else b''
    csr_path = directory / Path(filename).name

    try:
        create_csr(
            f'{csr_path}', country, state, city, organization, name, alt_names, private_key=key, passphrase=passphrase
        )
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise click.UsageError('The key file is not valid or the algorithm used is unsupported.')

    click.secho(f'The certificate signing request has been successfully created in {directory}', fg='green')
