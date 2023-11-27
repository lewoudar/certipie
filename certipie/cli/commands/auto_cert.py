from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import click
from cryptography.exceptions import UnsupportedAlgorithm

from certipie.cli.options import common_certificate_options
from certipie.cli.parameters import AutoCertDomainNameListParamType, validate_domain_name
from certipie.core import create_auto_certificate


@click.command('auto-cert')
@click.option('-f', '--filename', help='Name of the certificate file', default='cert.pem', show_default=True)
@common_certificate_options
@click.option(
    '-n',
    '--name',
    default='localhost',
    show_default=True,
    help=(
        'The common name i.e the main domain name covered by the certificate. '
        'In this particular case, since the certificate is mainly intended for tests, ip adresses and ip networks '
        'and the "localhost" value are also valid.'
    ),
    callback=validate_domain_name,
)
@click.option(
    '-a',
    '--alt-names',
    type=AutoCertDomainNameListParamType(),
    default='localhost,127.0.0.1,::1',
    show_default=True,
    help=(
        'Alternative domain names covered by the certificate. '
        'Ip addresses, ip networks and the "localhost" value are also supported.'
    ),
)
@click.option(
    '-v',
    '--validity',
    type=click.IntRange(min=1),
    help='Number of days the certificate will be valid starting from now.',
    default=365,
    show_default=True,
)
def auto_certificate(
    filename: str,
    country: str,
    state: str,
    city: str,
    organization: str,
    name: str,
    alt_names: list[str],
    validity: int,
    directory: Path,
    key: Optional[str] = None,
):
    """
    Creates a self-signed certificate useful for tests.
    If you don't provide a private key, an RSA one will be created and saved in the same directory as the certificate
    file.
    """
    passphrase = click.prompt('Passphrase', hide_input=True, default='') if key else b''
    cert_path = directory / Path(filename).name
    end_date = datetime.now() + timedelta(days=validity)

    try:
        create_auto_certificate(
            f'{cert_path}',
            country,
            state,
            city,
            organization,
            name,
            alt_names,
            private_key=key,
            passphrase=passphrase.encode() if isinstance(passphrase, str) else passphrase,
            end_validity=end_date,
        )
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise click.UsageError('The key file is not valid or the algorithm used is unsupported.') from None

    click.secho(f'The self-signed certificate has been successfully created in {directory}', fg='green')
