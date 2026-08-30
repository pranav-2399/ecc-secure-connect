import sys
import os
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from client.crypto.ecc import generate_key_pair
from client.crypto.ecdh import derive_shared_secret
from client.crypto.hkdf import derive_session_key
from client.crypto.aes import encrypt, decrypt

def test_aes_gcm_encryption_decryption():
    # End-to-End crypto setup
    priv_a, pub_a = generate_key_pair()
    priv_b, pub_b = generate_key_pair()

    shared_secret_a = derive_shared_secret(priv_a, pub_b)
    session_key_a = derive_session_key(shared_secret_a)

    shared_secret_b = derive_shared_secret(priv_b, pub_a)
    session_key_b = derive_session_key(shared_secret_b)

    original_message = "Hello Bob! End-to-End Encryption Works!"
    
    # Alice encrypts
    packet = encrypt(original_message, session_key_a)
    assert "ciphertext" in packet
    assert "nonce" in packet
    assert "tag" in packet

    # Bob decrypts
    decrypted_message = decrypt(
        ciphertext=packet["ciphertext"],
        nonce=packet["nonce"],
        tag=packet["tag"],
        session_key=session_key_b
    )

    assert decrypted_message == original_message

def test_aes_gcm_tampering_detection():
    priv_a, pub_a = generate_key_pair()
    priv_b, pub_b = generate_key_pair()
    session_key = derive_session_key(derive_shared_secret(priv_a, pub_b))

    packet = encrypt("Top Secret Payload", session_key)

    # Tamper with 1 byte of ciphertext
    ct_bytes = bytearray(bytes.fromhex(packet["ciphertext"]))
    ct_bytes[0] ^= 0xFF  # Flip bits of first byte
    tampered_ciphertext = ct_bytes.hex()

    with pytest.raises(ValueError, match="AES-GCM authentication failed"):
        decrypt(
            ciphertext=tampered_ciphertext,
            nonce=packet["nonce"],
            tag=packet["tag"],
            session_key=session_key
        )

def test_aes_gcm_wrong_key():
    priv_a, pub_a = generate_key_pair()
    priv_b, pub_b = generate_key_pair()
    priv_c, pub_c = generate_key_pair()

    session_key_ab = derive_session_key(derive_shared_secret(priv_a, pub_b))
    session_key_ac = derive_session_key(derive_shared_secret(priv_a, pub_c))

    packet = encrypt("Confidential", session_key_ab)

    with pytest.raises(ValueError, match="AES-GCM authentication failed"):
        decrypt(
            ciphertext=packet["ciphertext"],
            nonce=packet["nonce"],
            tag=packet["tag"],
            session_key=session_key_ac
        )
