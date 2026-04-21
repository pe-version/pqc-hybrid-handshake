"""Terminal demo entry point."""

from __future__ import annotations

from pqc_hybrid_handshake.handshake import (
    baseline_x25519_handshake,
    decrypt_message,
    encrypt_message,
    run_handshake,
)


def main() -> None:
    bar = "=" * 70
    print(bar)
    print(" Hybrid X25519 + ML-KEM-768 handshake demo")
    print(bar)
    print()

    result = run_handshake()
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
    print(f"  X25519 + ML-KEM-768     {result.handshake_bytes:>6d} bytes total handshake material")
    print(f"    classical X25519 pubkeys  2 x {result.classical_pk_bytes} = {2*result.classical_pk_bytes} bytes")
    print(f"    ML-KEM-768 public key         {result.pq_pk_bytes} bytes")
    print(f"    ML-KEM-768 ciphertext         {result.pq_ciphertext_bytes} bytes")
    if baseline_bytes:
        ratio = result.handshake_bytes / baseline_bytes
        print(f"  Wire-size cost of post-quantum: {ratio:.1f}x the bytes")
    print()

    print("Latency (single in-process handshake; not a benchmark):")
    print(f"  X25519 only             {baseline_ms:.2f} ms")
    print(f"  X25519 + ML-KEM-768     {result.duration_ms:.2f} ms")
