import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

def encrypt(message: str, session_key: bytes, nonce: bytes = None) -> dict:
    """
    Encrypts a plaintext string message using AES-256-GCM.
    
    Args:
        message (str): Plaintext message to encrypt.
        session_key (bytes): 256-bit symmetric session key.
        nonce (bytes, optional): 12-byte nonce. If None, random nonce is generated.
        
    Returns:
        dict: Hex-encoded dictionary containing 'ciphertext', 'nonce', and 'tag'.
    """
    if len(session_key) != 32:
        raise ValueError("Session key must be 32 bytes (256 bits)")
        
    if nonce is None:
        nonce = os.urandom(12)  # Recommended 96-bit nonce for AES-GCM
    elif len(nonce) != 12:
        raise ValueError("Nonce must be 12 bytes")
        
    aesgcm = AESGCM(session_key)
    # cryptography package appends tag (16 bytes) at the end of the ciphertext
    ct_and_tag = aesgcm.encrypt(nonce, message.encode('utf-8'), None)
    
    ciphertext = ct_and_tag[:-16]
    tag = ct_and_tag[-16:]
    
    return {
        "ciphertext": ciphertext.hex(),
        "nonce": nonce.hex(),
        "tag": tag.hex()
    }

def decrypt(ciphertext: str | bytes, nonce: str | bytes, tag: str | bytes, session_key: bytes) -> str:
    """
    Decrypts an AES-256-GCM encrypted message packet.
    
    Args:
        ciphertext (str | bytes): Hex string or raw bytes of ciphertext.
        nonce (str | bytes): Hex string or raw bytes of 12-byte nonce.
        tag (str | bytes): Hex string or raw bytes of 16-byte authentication tag.
        session_key (bytes): 256-bit symmetric session key.
        
    Returns:
        str: Decrypted plaintext message.
        
    Raises:
        ValueError: If authentication fails (tampering/corruption) or invalid key length.
    """
    if len(session_key) != 32:
        raise ValueError("Session key must be 32 bytes (256 bits)")
        
    if isinstance(ciphertext, str):
        ciphertext_bytes = bytes.fromhex(ciphertext)
    else:
        ciphertext_bytes = ciphertext
        
    if isinstance(nonce, str):
        nonce_bytes = bytes.fromhex(nonce)
    else:
        nonce_bytes = nonce
        
    if isinstance(tag, str):
        tag_bytes = bytes.fromhex(tag)
    else:
        tag_bytes = tag

    if len(nonce_bytes) != 12:
        raise ValueError("Nonce must be 12 bytes")
    if len(tag_bytes) != 16:
        raise ValueError("Tag must be 16 bytes")

    aesgcm = AESGCM(session_key)
    ct_and_tag = ciphertext_bytes + tag_bytes

    try:
        plaintext_bytes = aesgcm.decrypt(nonce_bytes, ct_and_tag, None)
        return plaintext_bytes.decode('utf-8')
    except InvalidTag:
        raise ValueError("AES-GCM authentication failed! Message rejected or corrupted.")
