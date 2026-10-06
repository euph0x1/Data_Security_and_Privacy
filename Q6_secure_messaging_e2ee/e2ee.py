"""End-to-end encryption primitives: X25519 key agreement + HKDF-SHA256 + AES-256-GCM."""
import os, base64, hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def unb64(s: str) -> bytes:
    return base64.b64decode(s)


def fingerprint(pub_a_hex: str, pub_b_hex: str) -> str:
    """'Safety number' both users compare out-of-band to detect a man-in-the-middle."""
    pair = b"".join(sorted([bytes.fromhex(pub_a_hex), bytes.fromhex(pub_b_hex)]))
    h = hashlib.sha256(pair).hexdigest()[:30]
    return " ".join(h[i:i + 5] for i in range(0, 30, 5))


class Device:
    """One user's device. The private key NEVER leaves this object."""

    def __init__(self, name: str):
        self.name = name
        self._priv = X25519PrivateKey.generate()
        self.public_hex = self._priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

    def _session_key(self, peer_pub_hex: str) -> bytes:
        peer = X25519PublicKey.from_public_bytes(bytes.fromhex(peer_pub_hex))
        shared = self._priv.exchange(peer)                       # ECDH shared secret
        salt = b"".join(sorted([bytes.fromhex(self.public_hex), bytes.fromhex(peer_pub_hex)]))
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"lab6-e2ee-v1").derive(shared)

    def encrypt(self, peer_id: str, peer_pub_hex: str, text: str) -> dict:
        nonce = os.urandom(12)
        aad = f"{self.name}->{peer_id}".encode()                 # binds ciphertext to sender/recipient
        ct = AESGCM(self._session_key(peer_pub_hex)).encrypt(nonce, text.encode(), aad)
        return {"from": self.name, "to": peer_id, "nonce": b64(nonce), "ct": b64(ct)}

    def decrypt(self, frame: dict, sender_pub_hex: str) -> str:
        aad = f"{frame['from']}->{frame['to']}".encode()
        pt = AESGCM(self._session_key(sender_pub_hex)).decrypt(unb64(frame["nonce"]), unb64(frame["ct"]), aad)
        return pt.decode()
