"""
Crypto-Agile Certificate Verifier
--------------------------------

This module demonstrates a crypto-agile verification framework for
certificates protected by multiple signature algorithms.

Key idea:
- Verification logic MUST NOT be hardcoded to a single algorithm.
- Trust decisions are driven by policy.

This model supports:
- Classical only
- PQC only
- Hybrid (classical + PQC)
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.exceptions import InvalidSignature


# --------------------------------------------------------------------
# Signature Verifier Registry
# --------------------------------------------------------------------

class SignatureVerifierRegistry:
    """
    Registry mapping algorithm names to verification functions.
    """

    def __init__(self):
        self._verifiers = {}

    def register(self, alg_name, verify_func):
        self._verifiers[alg_name] = verify_func

    def verify(self, alg_name, *args, **kwargs):
        if alg_name not in self._verifiers:
            raise ValueError(f"Unsupported algorithm: {alg_name}")
        return self._verifiers[alg_name](*args, **kwargs)


# --------------------------------------------------------------------
# Classical ECDSA Verifier
# --------------------------------------------------------------------

def verify_ecdsa(public_key, message, signature):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message)
    hashed = digest.finalize()

    try:
        public_key.verify(
            signature,
            hashed,
            ec.ECDSA(Prehashed(hashes.SHA256()))
        )
        return True
    except InvalidSignature:
        return False


# --------------------------------------------------------------------
# Simulated PQC Verifier
# --------------------------------------------------------------------

def verify_pqc(public_key, message, signature):
    """
    Simulated PQC verification.
    Mirrors Dilithium-style API without real math.
    """
    digest = hashes.Hash(hashes.SHA256())
    digest.update(public_key)
    digest.update(message)
    return digest.finalize() == signature


# --------------------------------------------------------------------
# Policy Engine
# --------------------------------------------------------------------

class VerificationPolicy:
    """
    Defines how many and which algorithms must succeed.
    """

    def __init__(self, required_algorithms, mode="any"):
        """
        mode:
          - 'any': at least one algorithm must verify
          - 'all': all listed algorithms must verify
        """
        self.required_algorithms = required_algorithms
        self.mode = mode

    def evaluate(self, results):
        if self.mode == "any":
            return any(results.values())
        elif self.mode == "all":
            return all(results.values())
        else:
            raise ValueError("Invalid policy mode")


# --------------------------------------------------------------------
# Crypto-Agile Certificate Verification
# --------------------------------------------------------------------

def verify_certificate(cert, verifier_registry, policy):
    """
    cert structure:
    {
        "payload": bytes,
        "signatures": {
            "ecdsa": (public_key, signature),
            "pqc":   (public_key, signature)
        }
    }
    """

    print("[+] Starting crypto-agile verification")

    results = {}

    for alg in policy.required_algorithms:
        if alg not in cert["signatures"]:
            print(f"    ✗ Missing signature: {alg}")
            results[alg] = False
            continue

        public_key, signature = cert["signatures"][alg]

        ok = verifier_registry.verify(
            alg,
            public_key,
            cert["payload"],
            signature
        )

        results[alg] = ok
        status = "✓ valid" if ok else "✗ INVALID"
        print(f"    {alg}: {status}")

    trusted = policy.evaluate(results)

    if trusted:
        print("[✓] Certificate TRUSTED by policy")
    else:
        print("[✗] Certificate REJECTED by policy")

    return trusted


# --------------------------------------------------------------------
# Demo
# --------------------------------------------------------------------

def main():
    print("\n=== Crypto-Agile Verifier Demo ===\n")

    # Dummy payload
    payload = b"leaf public key bytes"

    # Dummy keys/signatures (simulated)
    ecdsa_public = ec.generate_private_key(ec.SECP256R1()).public_key()
    ecdsa_signature = b"fake-ecdsa-signature"

    pqc_public = b"pqc-public-key"
    pqc_signature = b"fake-pqc-signature"

    cert = {
        "payload": payload,
        "signatures": {
            "ecdsa": (ecdsa_public, ecdsa_signature),
            "pqc": (pqc_public, pqc_signature),
        }
    }

    # Setup verifier registry
    registry = SignatureVerifierRegistry()
    registry.register("ecdsa", verify_ecdsa)
    registry.register("pqc", verify_pqc)

    # Hybrid policy: accept if ANY succeeds
    policy = VerificationPolicy(
        required_algorithms=["ecdsa", "pqc"],
        mode="any"
    )

    verify_certificate(cert, registry, policy)

    print("\n=== Demo complete ===\n")


if __name__ == "__main__":
    main()
