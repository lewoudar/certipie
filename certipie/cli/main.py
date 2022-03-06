import click
from click_didyoumean import DYMGroup

from .commands.auto_cert import auto_certificate
from .commands.completion import install_completion
from .commands.csr import csr
from .commands.rsa import rsa
from .commands.server import server


@click.version_option('0.1.0', message='%(prog)s version %(version)s')
@click.group(cls=DYMGroup, context_settings={'help_option_names': ['-h', '--help']})
def cert():
    """
    A cli to generate certificate signing request and self-signed certificate that can be used for testing purpose.
    """


for command in [rsa, csr, auto_certificate, server, install_completion]:
    cert.add_command(command)  # type: ignore
