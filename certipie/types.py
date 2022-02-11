from typing import Union

from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa, x25519, x448, dh
from typing_extensions import TypeAlias

PrivateKey: TypeAlias = Union[
    ed25519.Ed25519PrivateKey,
    ed448.Ed448PrivateKey,
    rsa.RSAPrivateKey,
    dsa.DSAPrivateKey,
    ec.EllipticCurvePrivateKey,
    x25519.X25519PrivateKey,
    x448.X448PrivateKey,
    dh.DHPrivateKey
]
