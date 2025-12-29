# Crypto Agility – Design Pattern

This folder demonstrates **crypto agility**: the ability of a system to change cryptographic algorithms **without modifying business logic**.

Crypto agility is a foundational requirement for Post‑Quantum Cryptography (PQC) migration.

---

## What is crypto agility?

Crypto agility means:

* Cryptographic algorithms are **not hard‑coded**
* Business logic depends on **interfaces**, not implementations
* Algorithm choices are **configuration‑driven**

In practice, this allows organizations to:

* Deprecate broken algorithms
* Respond to new cryptanalytic results
* Transition to PQC algorithms with minimal disruption

---

## Why crypto agility matters for PQC

Post‑quantum migration is not a single algorithm swap.

It requires:

* Gradual rollout
* Hybrid (classical + PQC) deployments
* Emergency rollback capability

Without crypto agility:

* Applications must be rewritten
* Testing becomes risky
* Adoption timelines become unrealistic

Crypto agility turns PQC migration into a **configuration change instead of a rewrite**.

---

## Demo overview

The program `crypto_agility_pattern.py` illustrates:

* An abstract cryptographic interface (`Hasher`)
* Multiple interchangeable algorithm implementations
* A factory that selects algorithms at runtime
* Business logic that remains crypto‑agnostic

The focus is on **architecture**, not cryptographic strength.

---

## Design principles demonstrated

1. **Separation of concerns**
   Business logic never imports cryptographic primitives directly.

2. **Late binding**
   Algorithms are selected at runtime via configuration.

3. **Replaceability**
   Algorithms can be added, removed, or replaced without touching core logic.

These principles are directly applicable to:

* TLS stacks
* PKI systems
* KMS and HSM integrations

---

## Relation to real‑world systems

This pattern mirrors how mature systems handle cryptography:

* TLS cipher suite negotiation
* Cloud KMS algorithm selection
* HSM abstraction layers

PQC adoption will reuse these exact mechanisms.

---

## Scope and limitations

This demo intentionally:

* Uses classical algorithms
* Avoids PQC‑specific implementations
* Focuses on structure, not performance

PQC and hybrid algorithms will be introduced in later demos.

---

## Next steps

Natural extensions include:

* Hybrid cryptographic operations
* Dual‑algorithm verification
* PQC‑ready abstraction layers

These build directly on the agility pattern shown here.
