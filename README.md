# Post-Quantum Cryptography Readiness

This repository focuses on **practical, engineering-oriented preparation for Post-Quantum Cryptography (PQC)**.
It is **not** an implementation of math behind the PQC algorithms such as lattices or hash-based constructs. Neither it has the implementations of current PQC standards such as ML-KEM, ML-DSA or SLH-DSA. Instead, it demonstrates how real-world systems can **identify, adapt, and migrate** cryptographic components in anticipation of quantum-capable adversaries.

The emphasis is on:

* Crypto inventory and discovery
* Algorithm agility
* Hybrid (classical + PQC) transitions
* PKI and TLS migration considerations

This complements classical applied cryptography by addressing **system-level readiness**, not just algorithms.

---

## Why this repository exists

Quantum-safe algorithms alone do not make a system quantum-safe.

Most real-world failures during cryptographic transitions come from:

* Hard-coded algorithms
* Hidden dependencies (TLS, HSMs, libraries)
* Lack of crypto agility
* Incomplete PKI migration strategies

This repository demonstrates **how to think and code for migration**, which is exactly what enterprises face today.

---

## Repository Structure

```
post-quantum-crypto-readiness/
│
├── inventory/
│   ├── README.md
│   └── crypto_inventory_demo.py
│
├── agility/
│   ├── README.md
│   └── crypto_agility_pattern.py
│
├── hybrid/
│   ├── README.md
│   └── hybrid_key_exchange_demo.py
│
├── pki/
│   ├── README.md
│   └── pqc_pki_migration_notes.py
│
└── README.md
```

Each folder represents a **distinct readiness dimension**.

---

## 1. Crypto Inventory

**Goal:** Identify where quantum-vulnerable cryptography is used.

Typical questions answered:

* Where are RSA/ECDSA keys used?
* Which TLS versions and cipher suites are enabled?
* Which components depend on asymmetric cryptography?

This is the **first mandatory step** in any PQC migration.

---

## 2. Crypto Agility

**Goal:** Ensure algorithms can be swapped without rewriting applications.

Key ideas:

* Configuration-driven algorithm selection
* No hard-coded primitives
* Clear separation between crypto logic and business logic

Without agility, PQC adoption becomes disruptive and risky.

---

## 3. Hybrid Cryptography

**Goal:** Transition safely using classical + PQC algorithms together.

Hybrid approaches:

* Preserve security against classical attackers
* Add protection against future quantum adversaries

This mirrors real-world standards activity (e.g., hybrid TLS handshakes).

---

## 4. PKI & Certificates

**Goal:** Understand how PQC impacts trust infrastructure.

Focus areas:

* Certificates and signature algorithms
* Trust anchors and long-lived roots
* Operational challenges (HSMs, compliance)

PKI migration is the **hardest part** of PQC adoption.

---

## What this repository is NOT

* ❌ A PQC algorithm implementation
* ❌ A lattice math tutorial
* ❌ A cryptanalytic attack repository

Those topics belong to research-focused repositories.

---

## Intended Audience

* Security architects
* Cryptography engineers
* Application security professionals
* Researchers transitioning PQC work into industry

---

## Background Note

The author’s background includes research in **lattice-based cryptanalysis of DSA/ECDSA under side-channel leakage**, which informs the emphasis on implementation safety, migration discipline, and system-level correctness.

---

## Status

This repository is intentionally iterative. Additional demos and migration patterns will be added over time as PQC standards and implementations mature.
