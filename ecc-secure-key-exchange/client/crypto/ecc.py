from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

def generate_key_pair():
    """
    Generates an ECC key pair using SECP256R1 (NIST P-256) curve.
    Returns:
        tuple: (private_key, public_key)
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key: ec.EllipticCurvePublicKey) -> str:
    """
    Serializes an ECC public key to a PEM formatted string.
    """
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode('utf-8')

def deserialize_public_key(pem_str: str) -> ec.EllipticCurvePublicKey:
    """
    Deserializes a PEM formatted string into an ECC public key object.
    """
    public_key = serialization.load_pem_public_key(pem_str.encode('utf-8'))
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ValueError("Provided PEM is not a valid Elliptic Curve Public Key")
    return public_key

def serialize_private_key(private_key: ec.EllipticCurvePrivateKey) -> str:
    """
    Serializes an ECC private key to an unencrypted PEM formatted string.
    """
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem.decode('utf-8')

def deserialize_private_key(pem_str: str) -> ec.EllipticCurvePrivateKey:
    """
    Deserializes a PEM formatted string into an ECC private key object.
    """
    private_key = serialization.load_pem_private_key(pem_str.encode('utf-8'), password=None)
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise ValueError("Provided PEM is not a valid Elliptic Curve Private Key")
    return private_key
