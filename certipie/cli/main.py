import click
from click_didyoumean import DYMGroup

from .commands.rsa import rsa


@click.group(cls=DYMGroup)
def cert():
    """A cli to generate certificate csr and auto-certificate that can be used for testing purpose."""


for command in [rsa]:
    cert.add_command(command)
