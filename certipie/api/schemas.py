from typing import Optional

from pydantic import BaseModel, Field, SecretBytes


class PrivateKeyInput(BaseModel):
    filename_prefix: Optional[str] = Field(
        'id_rsa',
        description=(
            'the prefix if the files created. For example if you pass "id_rsa", you will have a zip with two files'
            '"id_rsa.pem" for the private key and "id_rsa.pub" for the public key'
        ),
        example='id_rsa'
    )
    key_size: Optional[int] = Field(
        2048, description='like te name said.. the key size', ge=512, example=2048
    )
    passphrase: Optional[SecretBytes] = Field(
        b'', description='passphrase used to encrypt the private_key', example='my passphrase'
    )
