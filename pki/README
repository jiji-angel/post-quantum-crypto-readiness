# Post-Quantum PKI (Public Key Infrastructure)

## Why PKI is the Hardest Part of PQC Migration

Public Key Infrastructure (PKI) is the backbone of trust on the internet:
- TLS authentication
- Code signing
- Software updates
- Device identity
- Long-lived root certificates

While symmetric cryptography can be made quantum-resistant by increasing key sizes,
**PKI relies on asymmetric signatures that are vulnerable to quantum attacks**.

Replacing PKI is difficult because:
- Root certificates have lifetimes of 10–30 years
- Trust anchors are embedded in OSes, browsers, firmware, and devices
- Not all clients support post-quantum algorithms

As a result, **post-quantum PKI must be introduced gradually and safely**.

---

## Core Idea: Hybrid PKI

Post-quantum PKI today relies on **hybrid approaches**, where:

- Classical algorithms preserve compatibility
- Post-quantum algorithms provide future security
- Both are verified to establish trust

Security principle:
> The system remains secure as long as **at least one** algorithm remains unbroken.

---

## What This Directory Demonstrates

This directory contains hands-on demonstrations of PQC PKI concepts:

### 1. Classical PKI Baseline
Understand how certificates are signed and verified using RSA/ECDSA.

### 2. Hybrid Certificates
Certificates containing **both classical and post-quantum signatures**.

### 3. PQC Leaf Certificates
Using post-quantum signatures at the leaf level while retaining classical roots.

### 4. Crypto-Agile Verification
Algorithm-agnostic verification logic driven by policy, not hardcoded crypto.

---

## Why This Matters

Most PQC failures will not come from broken math,
but from:
- Inflexible PKI designs
- Hardcoded algorithms
- Inability to rotate trust anchors

Understanding PQC PKI is essential for:
- TLS migration
- Cloud KMS
- Financial systems
- Long-lived infrastructure

This repository focuses on **engineering reality**, not just cryptographic theory.
