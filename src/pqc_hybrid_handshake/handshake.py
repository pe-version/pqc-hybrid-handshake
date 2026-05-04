"""Hybrid X25519 + ML-KEM-768 key agreement.

The construction follows the same shape adopted by the IETF TLS 1.3 hybrid
key-exchange drafts and major real-world deployments (Cloudflare, Chrome,
AWS): run a classical ECDH (X25519) and a post-quantum KEM (ML-KEM-768) in
parallel, then derive a single session key via HKDF over the concatenation
of both shared secrets, with the handshake transcript as the salt.

The session key is secure as long as **at least one** of the two underlying
primitives stays secure — that's the whole point of hybrid.

This module exposes the in-process demo: one Python process simulating both
Alice (the initiator) and Bob (the responder).
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass

import oqs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


DEFAULT_KEM = "ML-KEM-768"
CNSA_2_KEM = "ML-KEM-1024"
KEM_NAME = DEFAULT_KEM  # back-compat alias


def _hkdf_info_for(kem_name: str) -> bytes:
    """Bind HKDF info to the chosen KEM parameter set.

    Different KEM sizes are different protocols; including the name here
    domain-separates derived keys so a session run with ML-KEM-1024 can
    never collide with one run at ML-KEM-768.
    """
    return f"pqc-hybrid-handshake/v1/x25519+{kem_name.lower()}".encode()


HKDF_INFO = _hkdf_info_for(DEFAULT_KEM)  # back-compat alias


@dataclass
class HandshakeResult:
    shared_key: bytes
    handshake_bytes: int
    classical_pk_bytes: int
    pq_pk_bytes: int
    pq_ciphertext_bytes: int
    duration_ms: float
    kem_name: str = DEFAULT_KEM


def derive_combined_key(
    classical_secret: bytes,
    pq_secret: bytes,
    transcript: bytes,
    length: int = 32,
    info: bytes = HKDF_INFO,
) -> bytes:
    """Derive the session key from both shared secrets.

    Uses HKDF-SHA256 over `classical_secret || pq_secret`, with the handshake
    transcript as salt. This is the construction used by the IETF TLS 1.3
    hybrid drafts. For an ML-KEM-only / ephemeral X25519 setting, the X-Wing
    combiner (`draft-connolly-cfrg-xwing-kem`) is the more rigorous choice
    and is on this project's roadmap.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=transcript,
        info=info,
    ).derive(classical_secret + pq_secret)


def _x25519_pub_bytes(pub: X25519PublicKey) -> bytes:
    return pub.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)


def run_handshake(kem_name: str = DEFAULT_KEM) -> HandshakeResult:
    """Simulate Alice (initiator) and Bob (responder) doing a hybrid key exchange.

    Pass ``kem_name="ML-KEM-1024"`` for the CNSA 2.0 / NSA top-secret-grade
    parameter set; the default is ML-KEM-768 (CNSA 2.0 SECRET-grade).

    Returns a HandshakeResult containing the (shared) derived key plus
    bookkeeping on wire-byte cost and end-to-end duration.
    """
    start = time.perf_counter()
    hkdf_info = _hkdf_info_for(kem_name)

    # 1. Bob has a long-ish-lived hybrid keypair: X25519 + the chosen ML-KEM.
    bob_x25519_priv = X25519PrivateKey.generate()
    bob_x25519_pub_bytes = _x25519_pub_bytes(bob_x25519_priv.public_key())

    # KEM state is managed via context managers and freed at the earliest
    # point it's no longer needed, per the minimum-lifetime principle. The
    # X25519 private keys and derived `bytes` secrets below are not
    # explicitly zeroized — `cryptography` doesn't expose that, and Python
    # bytes are immutable. A hardened deployment would use a native-level
    # binding (libsodium-style `sodium_memzero` on caller-owned buffers)
    # to close that gap; doing so cleanly requires leaving idiomatic Python.
    with oqs.KeyEncapsulation(kem_name) as bob_kem:
        bob_kem_pub_bytes = bob_kem.generate_keypair()

        # 2. Alice generates an ephemeral X25519 key and ML-KEM-encapsulates against
        #    Bob's KEM public key. Note: ML-KEM encapsulation is sender-side only;
        #    Alice does not need her own ML-KEM keypair for this direction.
        alice_x25519_priv = X25519PrivateKey.generate()
        alice_x25519_pub_bytes = _x25519_pub_bytes(alice_x25519_priv.public_key())

        with oqs.KeyEncapsulation(kem_name) as alice_kem:
            pq_ciphertext, alice_pq_secret = alice_kem.encap_secret(bob_kem_pub_bytes)
        # alice_kem freed — encapsulation is sender-side-only; nothing else needs it.

        # 3. Both sides compute their classical X25519 shared secret independently.
        bob_x25519_pub = X25519PublicKey.from_public_bytes(bob_x25519_pub_bytes)
        alice_classical_secret = alice_x25519_priv.exchange(bob_x25519_pub)

        alice_x25519_pub = X25519PublicKey.from_public_bytes(alice_x25519_pub_bytes)
        bob_classical_secret = bob_x25519_priv.exchange(alice_x25519_pub)

        # 4. Bob decapsulates the ML-KEM ciphertext with his secret key.
        bob_pq_secret = bob_kem.decap_secret(pq_ciphertext)
    # bob_kem freed — KEM state is no longer needed for HKDF below.

    # 5. Both derive the same session key from (classical_secret, pq_secret),
    #    salted by the full handshake transcript. The transcript binding is
    #    what protects against downgrade and reflection attacks in real
    #    protocols; included here for shape, though this isn't a full TLS
    #    handshake.
    transcript = (
        bob_x25519_pub_bytes
        + bob_kem_pub_bytes
        + alice_x25519_pub_bytes
        + pq_ciphertext
    )
    alice_key = derive_combined_key(
        alice_classical_secret, alice_pq_secret, transcript, info=hkdf_info
    )
    bob_key = derive_combined_key(
        bob_classical_secret, bob_pq_secret, transcript, info=hkdf_info
    )

    if alice_key != bob_key:
        raise RuntimeError("hybrid key derivation mismatch — bug")

    duration_ms = (time.perf_counter() - start) * 1000

    handshake_bytes = (
        len(bob_x25519_pub_bytes)
        + len(bob_kem_pub_bytes)
        + len(alice_x25519_pub_bytes)
        + len(pq_ciphertext)
    )

    return HandshakeResult(
        shared_key=alice_key,
        handshake_bytes=handshake_bytes,
        classical_pk_bytes=len(bob_x25519_pub_bytes),
        pq_pk_bytes=len(bob_kem_pub_bytes),
        pq_ciphertext_bytes=len(pq_ciphertext),
        duration_ms=duration_ms,
        kem_name=kem_name,
    )


def encrypt_message(
    key: bytes, plaintext: bytes, associated_data: bytes = b""
) -> tuple[bytes, bytes]:
    """AES-256-GCM encrypt; returns (nonce, ciphertext_with_tag)."""
    aead = AESGCM(key)
    nonce = os.urandom(12)
    return nonce, aead.encrypt(nonce, plaintext, associated_data)


def decrypt_message(
    key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes = b""
) -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, associated_data)


def baseline_x25519_handshake() -> tuple[int, float]:
    """Pure X25519 baseline for comparison: (handshake bytes, duration ms)."""
    start = time.perf_counter()

    bob_priv = X25519PrivateKey.generate()
    bob_pub_bytes = _x25519_pub_bytes(bob_priv.public_key())

    alice_priv = X25519PrivateKey.generate()
    alice_pub_bytes = _x25519_pub_bytes(alice_priv.public_key())

    alice_secret = alice_priv.exchange(X25519PublicKey.from_public_bytes(bob_pub_bytes))
    bob_secret = bob_priv.exchange(X25519PublicKey.from_public_bytes(alice_pub_bytes))

    if alice_secret != bob_secret:
        raise RuntimeError("baseline X25519 derivation mismatch — bug")

    duration_ms = (time.perf_counter() - start) * 1000
    return len(bob_pub_bytes) + len(alice_pub_bytes), duration_ms
