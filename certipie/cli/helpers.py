"""Helper functions used in different (sub) commands."""
from typing import Optional

import click


def validate_country(ctx, param, value: str) -> Optional[str]:
    if len(value) != 2:
        raise click.BadParameter('country must be a 2 letters string')
    return value.upper()
