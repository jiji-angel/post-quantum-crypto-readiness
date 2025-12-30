"""
Hybrid Cryptography Demo
-----------------------

Purpose:
Demonstrate the concept of *hybrid cryptography* used during post-quantum
transitions: combining a classical cryptographic secret with a
post-quantum (simulated) secret to derive a final shared key.

This mirrors real-world designs such as:
- Hybrid TLS handshakes
- Classical + PQC key establishment

IMPORTANT:
- This demo does NOT implement a real PQC algorithm
- The PQC component is simulated to focus on *design*, not math
"""

import os
import hashlib

# -----------------------------
# Classical key agreement (simulated)
# -----------------------------

def classical_key_exchange() -> bytes:
    """Simulate a classical shared secret (e.g., ECDH output)."""
    return os.urandom(32)

# -----------------------------
# Post-quantum key agreement (simulated)
# -----------------------------

def pqc_key_exchange() -> bytes:
    """Simulate a PQC shared secret (e.g., KEM output)."""
    return os.urandom(32)

# -----------------------------
# Hybrid key derivation
# -----------------------------

def derive_hybrid_key(classical_secret: bytes, pqc_secret: bytes) -> bytes:
    """Derive a hybrid key from classical and PQC secrets."""
    combined = classical_secret + pqc_secret
    return hashlib.sha256(combined).digest()

# -----------------------------
# Demo
# -----------------------------

def main():
    print("\n=== Hybrid Cryptography Demo ===\n")

    classical_secret = classical_key_exchange()
    pqc_secret = pqc_key_exchange()

    hybrid_key = derive_hybrid_key(classical_secret, pqc_secret)

    print(f"Classical secret length : {len(classical_secret)} bytes")
    print(f"PQC secret length       : {len(pqc_secret)} bytes")
    print(f"Hybrid key length       : {len(hybrid_key)} bytes")

    print("\nSecurity properties:")
    print("- Secure if classical crypto remains secure")
    print("- Secure if PQC crypto remains secure")
    print("- Broken only if BOTH are broken")

if __name__ == "__main__":
    main()
