"""Terminal demo entry point."""

from __future__ import annotations

import argparse

from pqc_hybrid_handshake.handshake import (
    CNSA_2_KEM,
    DEFAULT_KEM,
    baseline_x25519_handshake,
    decrypt_message,
    encrypt_message,
    run_handshake,
)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="pqc-hybrid-handshake",
        description="Hybrid X25519 + ML-KEM key-agreement demo.",
    )
    parser.add_argument(
        "--cnsa-2.0",
        dest="cnsa_2_0",
        action="store_true",
        help=(
            "Use ML-KEM-1024 (CNSA 2.0 / NSA top-secret-grade parameter set) "
            f"instead of the default {DEFAULT_KEM}."
        ),
    )
    parser.add_argument(
        "--kem",
        dest="kem",
        default=None,
        help=(
            "Override the KEM by name (e.g. ML-KEM-512, ML-KEM-768, ML-KEM-1024). "
            "Takes precedence over --cnsa-2.0."
        ),
    )
    return parser.parse_args(argv)


def _resolve_kem(args: argparse.Namespace) -> str:
    if args.kem:
        return args.kem
    if args.cnsa_2_0:
        return CNSA_2_KEM
    return DEFAULT_KEM


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)
    kem_name = _resolve_kem(args)

    bar = "=" * 70
    print(bar)
    print(f" Hybrid X25519 + {kem_name} handshake demo")
    print(bar)
    print()

    result = run_handshake(kem_name=kem_name)
    print(f"  Handshake completed in {result.duration_ms:.2f} ms")
    print(f"  Derived shared key (32 bytes): {result.shared_key.hex()}")
    print()

    message = b"Hello from a post-quantum future. -- Alice"
    nonce, ct = encrypt_message(result.shared_key, message, associated_data=b"hybrid-demo-v1")
    decoded = decrypt_message(result.shared_key, nonce, ct, associated_data=b"hybrid-demo-v1")
    if decoded != message:
        raise RuntimeError("AES-GCM round-trip mismatch — bug")
    print(f"  Encrypted message round-tripped via AES-256-GCM ({len(ct)} byte ct)")
    print()

    baseline_bytes, baseline_ms = baseline_x25519_handshake()

    print("Wire-size comparison:")
    print(f"  X25519 only             {baseline_bytes:>6d} bytes total handshake material")
    print(f"  X25519 + {kem_name:<12s}   {result.handshake_bytes:>6d} bytes total handshake material")
    print(f"    classical X25519 pubkeys  2 x {result.classical_pk_bytes} = {2*result.classical_pk_bytes} bytes")
    print(f"    {kem_name} public key         {result.pq_pk_bytes} bytes")
    print(f"    {kem_name} ciphertext         {result.pq_ciphertext_bytes} bytes")
    if baseline_bytes:
        ratio = result.handshake_bytes / baseline_bytes
        print(f"  Wire-size cost of post-quantum: {ratio:.1f}x the bytes")
    print()

    print("Latency (single in-process handshake; not a benchmark):")
    print(f"  X25519 only             {baseline_ms:.2f} ms")
    print(f"  X25519 + {kem_name:<12s}   {result.duration_ms:.2f} ms")
