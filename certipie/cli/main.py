import click
from click_didyoumean import DYMGroup

from .commands.csr import csr
from .commands.rsa import rsa


@click.version_option('0.1.0', message='%(prog)s version %(version)s')
@click.group(cls=DYMGroup)
def cert():
    """A cli to generate certificate csr and auto-certificate that can be used for testing purpose."""


for command in [rsa, csr]:
    cert.add_command(command)  # type: ignore
