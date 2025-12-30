# Hybrid Cryptography – PQC Transition Pattern

This folder demonstrates **hybrid cryptography**, the primary mechanism used to transition real‑world systems from classical cryptography to post‑quantum cryptography (PQC).

Hybrid cryptography is not a theoretical construct — it is the **industry’s chosen migration strategy**.

---

## What is hybrid cryptography?

Hybrid cryptography combines:

* A **classical cryptographic primitive** (e.g., ECDH, RSA-based key transport)
* A **post‑quantum cryptographic primitive** (typically a KEM)

The outputs of both are combined (usually via a KDF) to derive a **single shared key**.

---

## Core security property

> **The system remains secure unless *both* the classical and PQC mechanisms are broken.**

This property is the reason hybrid designs are preferred during transition periods.

* If classical cryptography is broken by quantum attacks → PQC still protects
* If a PQC algorithm is later weakened → classical crypto still protects

---

## Why hybrid is necessary

Immediate replacement of classical cryptography is impractical because:

* PQC algorithms are relatively new
* Implementations are still maturing
* Performance and interoperability constraints exist

Hybrid approaches:

* Preserve existing security guarantees
* Add quantum resistance
* Avoid disruptive "flag‑day" migrations

---

## Demo overview

The program `hybrid_key_exchange_demo.py` illustrates:

* A simulated classical shared secret
* A simulated PQC shared secret
* Combination of both secrets via a KDF

The PQC component is intentionally **simulated** to focus on architectural design rather than algorithmic details.

---

## Relation to real‑world systems

Hybrid cryptography is being deployed or standardized in:

* TLS handshakes
* VPN protocols
* Secure messaging systems
* PKI transition strategies

The pattern shown here mirrors these real‑world designs.

---

## Why this demo avoids real PQC algorithms

This repository focuses on **PQC readiness**, not algorithm implementation.

Using simulated PQC components:

* Avoids premature dependency lock‑in
* Keeps the focus on system design
* Reflects how hybrid integration is handled at higher abstraction layers

---

## Scope and limitations

This demo:

* Demonstrates hybrid construction
* Emphasizes security reasoning
* Is suitable for architectural discussions

It does not:

* Implement real PQC primitives
* Benchmark performance
* Address side‑channel resistance

---

## Next steps

Natural extensions include:

* Hybrid crypto combined with agility patterns
* Hybrid certificate and PKI models
* PQC algorithm substitution once standards and libraries mature

These build directly on the hybrid foundation shown here.
