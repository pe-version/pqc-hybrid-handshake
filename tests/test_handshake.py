from __future__ import annotations

import pytest

from pqc_hybrid_handshake.handshake import (
    baseline_x25519_handshake,
    decrypt_message,
    derive_combined_key,
    encrypt_message,
    run_handshake,
)


def test_handshake_produces_32_byte_session_key():
    result = run_handshake()
    assert len(result.shared_key) == 32


def test_handshake_byte_count_in_expected_range():
    """ML-KEM-768 has a 1184-byte pubkey and 1088-byte ciphertext, plus 2 x 32 X25519."""
    result = run_handshake()
    assert result.classical_pk_bytes == 32
    assert result.pq_pk_bytes == 1184
    assert result.pq_ciphertext_bytes == 1088
    assert result.handshake_bytes == 32 + 1184 + 32 + 1088


def test_aes_gcm_round_trip():
    result = run_handshake()
    message = b"the quick brown fox" * 10
    nonce, ct = encrypt_message(result.shared_key, message)
    assert decrypt_message(result.shared_key, nonce, ct) == message


def test_aes_gcm_with_associated_data():
    result = run_handshake()
    nonce, ct = encrypt_message(result.shared_key, b"secret", associated_data=b"hdr")
    assert decrypt_message(result.shared_key, nonce, ct, associated_data=b"hdr") == b"secret"
    with pytest.raises(Exception):
        decrypt_message(result.shared_key, nonce, ct, associated_data=b"wrong")


def test_tampered_ciphertext_fails():
    result = run_handshake()
    nonce, ct = encrypt_message(result.shared_key, b"hello")
    tampered = bytearray(ct)
    tampered[0] ^= 0xFF
    with pytest.raises(Exception):
        decrypt_message(result.shared_key, nonce, bytes(tampered))


def test_combiner_is_deterministic():
    cs = b"\x11" * 32
    ps = b"\x22" * 32
    transcript = b"transcript"
    assert derive_combined_key(cs, ps, transcript) == derive_combined_key(cs, ps, transcript)


def test_combiner_changes_when_pq_secret_changes():
    cs = b"\x11" * 32
    ps_a = b"\x22" * 32
    ps_b = b"\x33" * 32
    assert derive_combined_key(cs, ps_a, b"t") != derive_combined_key(cs, ps_b, b"t")


def test_combiner_changes_when_classical_secret_changes():
    cs_a = b"\x11" * 32
    cs_b = b"\x44" * 32
    ps = b"\x22" * 32
    assert derive_combined_key(cs_a, ps, b"t") != derive_combined_key(cs_b, ps, b"t")


def test_combiner_changes_when_transcript_changes():
    cs = b"\x11" * 32
    ps = b"\x22" * 32
    assert derive_combined_key(cs, ps, b"t1") != derive_combined_key(cs, ps, b"t2")


def test_two_independent_handshakes_produce_different_keys():
    r1 = run_handshake()
    r2 = run_handshake()
    assert r1.shared_key != r2.shared_key


def test_baseline_x25519_handshake_returns_64_bytes():
    bytes_count, _ = baseline_x25519_handshake()
    assert bytes_count == 64
