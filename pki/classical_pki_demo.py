"""
Classical PKI Demonstration
---------------------------

This program demonstrates a minimal classical PKI flow:

1. Root CA key generation
2. Leaf certificate key generation
3. Root signs leaf certificate
4. Leaf certificate verification using Root public key

Algorithms used:
- ECDSA (P-256, SHA-256)

This establishes the baseline that PQC PKI will later modify or replace.
"""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.exceptions import InvalidSignature


# --------------------------------------------------------------------
# Step 1: Root CA key generation
# --------------------------------------------------------------------

def generate_root_ca():
    print("[+] Generating Root CA key pair (ECDSA P-256)")
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


# --------------------------------------------------------------------
# Step 2: Leaf certificate key generation
# --------------------------------------------------------------------

def generate_leaf_key():
    print("[+] Generating Leaf certificate key pair")
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


# --------------------------------------------------------------------
# Step 3: Root signs leaf "certificate"
# --------------------------------------------------------------------

def sign_leaf_certificate(root_private_key, leaf_public_key):
    """
    In real PKI, this would be a full X.509 certificate.
    Here, we simplify it to 'signing the leaf public key bytes'.
    """

    print("[+] Root CA signing leaf public key")

    leaf_pub_bytes = leaf_public_key.public_bytes(
        encoding = serialization.Encoding.DER,
        format = serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    digest = hashes.Hash(hashes.SHA256())
    digest.update(leaf_pub_bytes)
    hashed_leaf_key = digest.finalize()

    signature = root_private_key.sign(
        hashed_leaf_key,
        ec.ECDSA(Prehashed(hashes.SHA256()))
    )

    return leaf_pub_bytes, signature


# --------------------------------------------------------------------
# Step 4: Certificate verification
# --------------------------------------------------------------------

def verify_leaf_certificate(root_public_key, leaf_pub_bytes, signature):
    print("[+] Verifying leaf certificate using Root public key")

    digest = hashes.Hash(hashes.SHA256())
    digest.update(leaf_pub_bytes)
    hashed_leaf_key = digest.finalize()

    try:
        root_public_key.verify(
            signature,
            hashed_leaf_key,
            ec.ECDSA(Prehashed(hashes.SHA256()))
        )
        print("[✓] Certificate verification SUCCESSFUL")
        return True
    except InvalidSignature:
        print("[✗] Certificate verification FAILED")
        return False


# --------------------------------------------------------------------
# Main demo
# --------------------------------------------------------------------

def main():
    print("\n=== Classical PKI Demo (ECDSA) ===\n")

    # Root CA
    root_priv, root_pub = generate_root_ca()

    # Leaf
    leaf_priv, leaf_pub = generate_leaf_key()

    # Sign leaf certificate
    leaf_pub_bytes, signature = sign_leaf_certificate(root_priv, leaf_pub)

    # Verify certificate
    verify_leaf_certificate(root_pub, leaf_pub_bytes, signature)

    print("\n=== Demo complete ===\n")


if __name__ == "__main__":
    main()
