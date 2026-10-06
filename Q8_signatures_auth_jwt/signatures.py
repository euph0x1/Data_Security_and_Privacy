"""Part (a): RSA digital signatures with the `cryptography` library."""
import json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature


def generate_keypair(bits=2048):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def private_pem(k) -> str:
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption()).decode()


def public_pem(k) -> str:
    return k.public_key().public_bytes(serialization.Encoding.PEM,
                                       serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def _pad(scheme):
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH) \
        if scheme == "PSS" else padding.PKCS1v15()


def sign(private_key, data: bytes, scheme="PSS") -> bytes:
    return private_key.sign(data, _pad(scheme), hashes.SHA256())


def verify(public_key, signature: bytes, data: bytes, scheme="PSS") -> bool:
    try:
        public_key.verify(signature, data, _pad(scheme), hashes.SHA256())
        return True
    except InvalidSignature:
        return False


def load_public(pem: str):
    return serialization.load_pem_public_key(pem.encode())


def canonical(tx: dict) -> bytes:
    """Deterministic byte encoding so signer and verifier hash exactly the same bytes."""
    return json.dumps(tx, sort_keys=True, separators=(",", ":")).encode()
