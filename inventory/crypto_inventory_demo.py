"""
Crypto Inventory Demo
---------------------

Purpose:
Demonstrate how an application or security team can *discover and classify*
cryptographic usage from a quantum-readiness perspective.

This demo focuses on:
- TLS certificate signature algorithms
- Public key types and sizes
- Classification into quantum-vulnerable vs PQC-ready (future)

This is NOT a scanner or production tool.
It is a conceptual demo aligned with real PQC migration workflows.
"""

import ssl
import socket
from pprint import pprint

# -----------------------------
# Configuration
# -----------------------------
TARGET_HOST = "example.com"
TARGET_PORT = 443

# Algorithms considered quantum-vulnerable
QUANTUM_VULNERABLE_SIGS = {
    "rsa",
    "ecdsa",
}

# -----------------------------
# Helper functions
# -----------------------------

def classify_signature_algorithm(sig_alg: str) -> str:
    """Classify signature algorithm from PQC perspective."""
    if sig_alg is None:
        return "Unknown"

    sig_alg = sig_alg.lower()

    for vulnerable in QUANTUM_VULNERABLE_SIGS:
        if vulnerable in sig_alg:
            return "Quantum-vulnerable"

    return "Unknown / PQC-candidate"


def fetch_tls_certificate(host: str, port: int):
    """Fetch peer certificate from a TLS endpoint."""
    context = ssl.create_default_context()

    with socket.create_connection((host, port)) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            cipher = ssock.cipher()

    return cert, cipher


# -----------------------------
# Main demo logic
# -----------------------------

def main():
    print("\n=== Crypto Inventory Demo ===\n")
    print(f"Target: {TARGET_HOST}:{TARGET_PORT}\n")

    cert, cipher = fetch_tls_certificate(TARGET_HOST, TARGET_PORT)

    print("[TLS Cipher Suite]")
    print(cipher)

    print("\n[Certificate Subject]")
    pprint(cert.get("subject"))

    print("\n[Certificate Signature Algorithm]")
    sig_alg = cert.get("signatureAlgorithm")
    print(sig_alg)

    classification = classify_signature_algorithm(sig_alg)
    print(f"Classification: {classification}")

    print("\n[Inventory Summary]")
    summary = {
        "host": TARGET_HOST,
        "cipher": cipher[0],
        "signature_algorithm": sig_alg,
        "quantum_risk": classification,
    }
    pprint(summary)


if __name__ == "__main__":
    main()
