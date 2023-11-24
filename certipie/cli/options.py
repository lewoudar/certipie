"""This module groups commands used in many (sub) commands"""
from pathlib import Path
from typing import Any, Callable, Optional, TypeVar

import click

FC = TypeVar('FC', Callable[..., Any], click.Command)


def validate_country(ctx, param, value: str) -> Optional[str]:
    if len(value) != 2:
        raise click.BadParameter('country must be a 2 letters string')
    return value.upper()


def get_path(ctx, param, value: Optional[str]) -> Path:
    if value:
        return Path(value)
    return Path.cwd()


directory_option = click.option(
    '-d',
    '--directory',
    type=click.Path(exists=True, file_okay=False, writable=True),
    callback=get_path,
    help='The directory where the files will be created. Defaults to the current working directory if not provided.',
)
country_option = click.option(
    '-c', '--country', prompt=True, help='Country code in two letters.', callback=validate_country
)
state_option = click.option('-s', '--state', prompt=True, help='State or province of the related organization.')
city_option = click.option('-C', '--city', prompt=True, help='The city of the related organization.')
organization_option = click.option(
    '-o', '--organization', prompt=True, help='The organization requesting a certificate.'
)
key_option = click.option(
    '-k',
    '--key',
    type=click.Path(dir_okay=False, exists=True),
    help=(
        'The private key used to sign the certificate signing request. '
        'If not provided an RSA one with no passphrase will be created.'
    ),
)


def common_certificate_options(f: FC) -> FC:
    for option in [directory_option, city_option, country_option, state_option, organization_option, key_option]:
        f = option(f)
    return f
