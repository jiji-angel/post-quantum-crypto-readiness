"""
Crypto Agility Pattern Demo
---------------------------

Purpose:
Demonstrate how applications should be structured so that cryptographic
algorithms can be swapped or upgraded (e.g., for PQC migration) without
rewriting business logic.

This demo focuses on *design*, not cryptographic strength.

Key idea:
- Business logic calls an abstract crypto interface
- Algorithms are selected via configuration
- No hard-coded crypto primitives in application logic
"""

from abc import ABC, abstractmethod
import hashlib
import os

# -----------------------------
# Configuration (simulated)
# -----------------------------
CRYPTO_CONFIG = {
    "hash_algorithm": "sha256",  # change to: sha512, blake2b (example)
}

# -----------------------------
# Abstract interface
# -----------------------------
class Hasher(ABC):
    @abstractmethod
    def hash(self, data: bytes) -> bytes:
        pass

# -----------------------------
# Concrete implementations
# -----------------------------
class SHA256Hasher(Hasher):
    def hash(self, data: bytes) -> bytes:
        return hashlib.sha256(data).digest()

class SHA512Hasher(Hasher):
    def hash(self, data: bytes) -> bytes:
        return hashlib.sha512(data).digest()

class Blake2bHasher(Hasher):
    def hash(self, data: bytes) -> bytes:
        return hashlib.blake2b(data).digest()

# -----------------------------
# Factory
# -----------------------------

def get_hasher(config) -> Hasher:
    alg = config.get("hash_algorithm")

    if alg == "sha256":
        return SHA256Hasher()
    elif alg == "sha512":
        return SHA512Hasher()
    elif alg == "blake2b":
        return Blake2bHasher()
    else:
        raise ValueError(f"Unsupported hash algorithm: {alg}")

# -----------------------------
# Business logic (crypto-agnostic)
# -----------------------------

def store_password(password: str, hasher: Hasher) -> bytes:
    salt = os.urandom(16)
    digest = hasher.hash(salt + password.encode())
    return salt + digest

# -----------------------------
# Demo
# -----------------------------

def main():
    print("\n=== Crypto Agility Demo ===\n")

    hasher = get_hasher(CRYPTO_CONFIG)

    stored = store_password("correct-horse-battery-staple", hasher)

    print(f"Configured algorithm: {CRYPTO_CONFIG['hash_algorithm']}")
    print(f"Stored value length : {len(stored)} bytes")

if __name__ == "__main__":
    main()
