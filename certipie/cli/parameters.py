"""Custom click parameters."""
from click_params import ValidatorParamType, ListParamType

from certipie.core import is_domain_name


# we don't use DomainParamType provided by click_params because it doesn't handle wildcards
class DomainNameParamType(ValidatorParamType):
    name = 'domain name'

    def __init__(self):
        super().__init__(callback=is_domain_name)


class DomainNameListParamType(ListParamType):
    name = 'domain name list'

    def __init__(self, separator: str = ','):
        super().__init__(DOMAIN, separator=separator, name='domain names')


DOMAIN = DomainNameParamType()
