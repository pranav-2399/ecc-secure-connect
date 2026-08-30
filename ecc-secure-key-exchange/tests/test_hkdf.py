import sys
import os
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from client.crypto.ecc import generate_key_pair
from client.crypto.ecdh import derive_shared_secret
from client.crypto.hkdf import derive_session_key

def test_hkdf_session_key_matching():
    priv_a, pub_a = generate_key_pair()
    priv_b, pub_b = generate_key_pair()

    shared_secret_a = derive_shared_secret(priv_a, pub_b)
    shared_secret_b = derive_shared_secret(priv_b, pub_a)

    key_a = derive_session_key(shared_secret_a)
    key_b = derive_session_key(shared_secret_b)

    assert key_a == key_b
    assert len(key_a) == 32  # 256 bits

def test_hkdf_different_info_or_salt():
    priv_a, pub_a = generate_key_pair()
    priv_b, pub_b = generate_key_pair()
    shared_secret = derive_shared_secret(priv_a, pub_b)

    key1 = derive_session_key(shared_secret, info=b"context-1")
    key2 = derive_session_key(shared_secret, info=b"context-2")

    assert key1 != key2
