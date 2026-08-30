from cryptography.hazmat.primitives.asymmetric import ec

def derive_shared_secret(private_key: ec.EllipticCurvePrivateKey, peer_public_key: ec.EllipticCurvePublicKey) -> bytes:
    """
    Derives an ECDH raw shared secret using local private key and peer's public key.
    
    Args:
        private_key (EllipticCurvePrivateKey): Client's ECC private key.
        peer_public_key (EllipticCurvePublicKey): Remote peer's ECC public key.
        
    Returns:
        bytes: Raw shared secret.
    """
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_secret
