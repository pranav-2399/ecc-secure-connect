import sys
import os
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from client.crypto.ecc import (
    generate_key_pair,
    serialize_public_key,
    deserialize_public_key,
    serialize_private_key,
    deserialize_private_key
)
from cryptography.hazmat.primitives.asymmetric import ec

def test_generate_key_pair():
    priv_key, pub_key = generate_key_pair()
    assert isinstance(priv_key, ec.EllipticCurvePrivateKey)
    assert isinstance(pub_key, ec.EllipticCurvePublicKey)

def test_serialize_deserialize_public_key():
    _, pub_key = generate_key_pair()
    pem = serialize_public_key(pub_key)
    assert isinstance(pem, str)
    assert "-----BEGIN PUBLIC KEY-----" in pem
    
    reconstructed_pub_key = deserialize_public_key(pem)
    assert isinstance(reconstructed_pub_key, ec.EllipticCurvePublicKey)

def test_serialize_deserialize_private_key():
    priv_key, _ = generate_key_pair()
    pem = serialize_private_key(priv_key)
    assert isinstance(pem, str)
    assert "-----BEGIN PRIVATE KEY-----" in pem
    
    reconstructed_priv_key = deserialize_private_key(pem)
    assert isinstance(reconstructed_priv_key, ec.EllipticCurvePrivateKey)

def test_invalid_pem_public_key():
    with pytest.raises(Exception):
        deserialize_public_key("INVALID_PEM_DATA")
