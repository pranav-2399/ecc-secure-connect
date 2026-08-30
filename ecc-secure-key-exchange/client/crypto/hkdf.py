from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def derive_session_key(shared_secret: bytes, salt: bytes = None, info: bytes = b"handshake data", length: int = 32) -> bytes:
    """
    Derives a 256-bit symmetric session key from an ECDH shared secret using HKDF-SHA256.
    
    Args:
        shared_secret (bytes): The raw shared secret computed via ECDH.
        salt (bytes, optional): Optional salt value. If None, HKDF uses a string of zeros.
        info (bytes, optional): Context and application specific information.
        length (int): Length of derived key in bytes (default 32 bytes for 256-bit AES).
        
    Returns:
        bytes: Derived symmetric session key.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    session_key = hkdf.derive(shared_secret)
    return session_key
