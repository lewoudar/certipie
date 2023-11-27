from functools import partial
from typing import Annotated, Optional

from fastapi import Form
from pydantic import AfterValidator, BaseModel, Field, SecretBytes, field_validator

from certipie.core import is_domain_name


class PrivateKeyInput(BaseModel):
    filename_prefix: str = Field(
        'id_rsa',
        description=(
            'The prefix if the files created. For example if you pass "id_rsa", you will have a zip with two files'
            '"id_rsa.pem" for the private key and "id_rsa.pub" for the public key.'
        ),
        examples=['id_rsa'],
    )
    key_size: int = Field(
        2048, description='Like te name said.. the key size for the private key.', ge=512, examples=[2048]
    )
    passphrase: SecretBytes = Field(
        b'', description='Passphrase used to encrypt the private_key, can be optional.', example='my passphrase'
    )
    model_config = {
        'json_schema_extra': {
            'examples': [{'filename_prefix': 'id_rsa', 'key_size': 2048, 'passphrase': 'my passphrase'}]
        }
    }

    @field_validator('passphrase', mode='before')
    @classmethod
    def transform_string_to_bytes(cls, value: Optional[str]) -> Optional[bytes]:
        if value:
            return value.encode()


def validate_domain_name(value: str) -> str:
    if not is_domain_name(value):
        raise ValueError('not a valid domain name')
    return value


DomainName = Annotated[str, AfterValidator(validate_domain_name)]
country_form = partial(Form, description='Two letter code of your country', examples=['FR'], min_length=2, max_length=2)
state_or_province_form = partial(Form, description='the state or province information', examples=['Ile-de-France'])
city_form = partial(Form, description='the city information', examples=['Paris'])
organization_form = partial(Form, description='the organization information', examples=['Organization Inc.'])
