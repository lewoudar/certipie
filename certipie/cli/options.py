"""This module groups commands used in many (sub) commands"""
from pathlib import Path

import click


def get_path(ctx, param, value):
    if value:
        return Path(value)
    return Path.cwd()


directory_option = click.option(
    '-d', '--directory',
    type=click.Path(exists=True, file_okay=False, writable=True),
    callback=get_path,
    help='The directory where the files will be created. Defaults to the current working directory if not provided.'
)
