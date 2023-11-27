"""Custom click parameters."""
import ipaddress
from typing import Literal, Union

import click
import pydantic
from click_params import ListParamType, ValidatorParamType

from certipie.core import is_domain_name


class IpModel(pydantic.BaseModel):
    ip: Union[ipaddress.IPv6Network, ipaddress.IPv4Network, ipaddress.IPv6Address, ipaddress.IPv4Address]


class HostModel(pydantic.BaseModel):
    host: Union[Literal['localhost'], ipaddress.IPv6Address, ipaddress.IPv4Address]

    @pydantic.field_validator('host', mode='before')
    @classmethod
    def lower_value(cls, value: str) -> str:
        return value.lower()


def auto_cert_domain_name(domain: str) -> bool:
    if domain.lower() == 'localhost' or is_domain_name(domain):
        return True

    try:
        IpModel(ip=domain)
        return True
    except pydantic.ValidationError:
        return False


# for the auto-cert command, the common name must be "localhost" or a domain name
# we don't accept ip address/network here
def validate_domain_name(ctx, param, value: str) -> str:
    value = value.lower()
    if value != 'localhost' and not is_domain_name(value):
        raise click.BadParameter(f'{value} is neither "localhost" nor a valid domain name')

    return value


def validate_host(ctx, param, value: str) -> str:
    try:
        HostModel(host=value)
        return value
    except pydantic.ValidationError:
        raise click.BadParameter(f'{value} is neither "localhost" nor a valid ip address') from None


# we don't use DomainParamType provided by click_params because it doesn't handle wildcards
class DomainNameParamType(ValidatorParamType):
    name = 'domain name'

    def __init__(self):
        super().__init__(callback=is_domain_name)


class AutoCertDomainNameParamType(ValidatorParamType):
    name = 'auto-cert domain name'

    def __init__(self):
        super().__init__(callback=auto_cert_domain_name)


class DomainNameListParamType(ListParamType):
    name = 'domain name list'

    def __init__(self, separator: str = ','):
        super().__init__(DOMAIN, separator=separator, name='domain names')


class AutoCertDomainNameListParamType(ListParamType):
    name = 'auto cert value list'

    def __init__(self, separator: str = ','):
        super().__init__(AutoCertDomainNameParamType(), separator=separator, name='auto cert values')


DOMAIN = DomainNameParamType()
