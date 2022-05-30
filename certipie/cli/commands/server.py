import click
import trio
from hypercorn import Config
from hypercorn.trio import serve

from certipie.api import app
from certipie.cli.parameters import validate_host


@click.command()
@click.option(
    '-H',
    '--host',
    help='The host to serve the application.',
    default='localhost',
    show_default=True,
    callback=validate_host,
)
@click.option(
    '-p',
    '--port',
    help='The port to bind the application to.',
    type=click.IntRange(min=0),
    default=8000,
    show_default=True,
)
@click.option(
    '-c',
    '--config',
    'config_file',
    help=(
        'Config file to.. configure the application. For all options available, see the documentation here: '
        'https://pgjones.gitlab.io/hypercorn/how_to_guides/configuring.html'
    ),
    type=click.Path(exists=True, dir_okay=False),
)
def server(host: str, port: int, config_file: str):
    """Serves a swagger UI where you can perform the same certificate operations from the CLI."""
    if config_file:
        config = Config.from_toml(config_file)
    else:
        config = Config()
        config.bind = [f'{host}:{port}']

    trio.run(serve, app, config)
