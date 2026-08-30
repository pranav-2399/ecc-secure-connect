import sys
import os
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from client.crypto.ecc import generate_key_pair
from client.crypto.ecdh import derive_shared_secret

def test_ecdh_shared_secret_matching():
    # Client A (Alice)
    priv_a, pub_a = generate_key_pair()
    # Client B (Bob)
    priv_b, pub_b = generate_key_pair()

    # ECDH calculation
    shared_secret_a = derive_shared_secret(priv_a, pub_b)
    shared_secret_b = derive_shared_secret(priv_b, pub_a)

    assert shared_secret_a == shared_secret_b
    assert len(shared_secret_a) == 32  # 256 bits for SECP256R1

def test_ecdh_shared_secret_mismatch():
    priv_a, pub_a = generate_key_pair()
    priv_b, pub_b = generate_key_pair()
    priv_c, pub_c = generate_key_pair()

    shared_secret_ab = derive_shared_secret(priv_a, pub_b)
    shared_secret_ac = derive_shared_secret(priv_a, pub_c)

    assert shared_secret_ab != shared_secret_ac
