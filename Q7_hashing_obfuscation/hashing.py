"""Part (a): hash functions with hashlib."""
import hashlib

ALGOS = ["md5", "sha1", "sha256", "sha512", "sha3_256", "blake2b"]


def hash_bytes(data: bytes, algo: str) -> str:
    return hashlib.new(algo, data).hexdigest()


def hash_text(text: str, algo: str) -> str:
    return hash_bytes(text.encode("utf-8"), algo)


def hash_file_stream(fileobj, algo: str, chunk=1 << 16) -> str:
    """Hash a file-like object in chunks (works for very large files)."""
    h = hashlib.new(algo)
    while block := fileobj.read(chunk):
        h.update(block)
    return h.hexdigest()


def bit_diff(hex_a: str, hex_b: str) -> int:
    a, b = bytes.fromhex(hex_a), bytes.fromhex(hex_b)
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))
