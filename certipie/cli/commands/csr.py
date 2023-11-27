from pathlib import Path
from typing import Optional

import click
from cryptography.exceptions import UnsupportedAlgorithm

from certipie.cli.options import common_certificate_options
from certipie.cli.parameters import DOMAIN, DomainNameListParamType
from certipie.core import create_csr


@click.command()
@click.option('-f', '--filename', help='Name of the csr file', default='csr.pem', show_default=True)
@common_certificate_options
@click.option(
    '-n',
    '--name',
    type=DOMAIN,
    prompt=True,
    help='The common name i.e the main domain name covered by the certificate.',
)
@click.option(
    '-a',
    '--alt-names',
    type=DomainNameListParamType(),
    help='Alternative domain names covered by the certificate. If not provided, defaults to the common name.',
)
def csr(
    filename: str,
    country: str,
    state: str,
    city: str,
    organization: str,
    name: str,
    alt_names: list[str],
    directory: Path,
    key: Optional[str] = None,
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
            f'{csr_path}',
            country,
            state,
            city,
            organization,
            name,
            alt_names,
            private_key=key,
            passphrase=passphrase.encode() if isinstance(passphrase, str) else passphrase,
        )
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise click.UsageError('The key file is not valid or the algorithm used is unsupported.') from None

    click.secho(f'The certificate signing request has been successfully created in {directory}', fg='green')
