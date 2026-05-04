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


# Per FIPS 203 §8 (parameter sets): public key and ciphertext sizes by KEM.
KEM_SIZES = {
    "ML-KEM-512": {"pq_pk_bytes": 800, "pq_ciphertext_bytes": 768},
    "ML-KEM-768": {"pq_pk_bytes": 1184, "pq_ciphertext_bytes": 1088},
    "ML-KEM-1024": {"pq_pk_bytes": 1568, "pq_ciphertext_bytes": 1568},
}


@pytest.mark.parametrize("kem_name", ["ML-KEM-768", "ML-KEM-1024"])
def test_handshake_byte_count_in_expected_range(kem_name):
    """Each ML-KEM parameter set has a fixed pubkey/ciphertext size; X25519 is always 32 bytes."""
    expected = KEM_SIZES[kem_name]
    result = run_handshake(kem_name=kem_name)
    assert result.classical_pk_bytes == 32
    assert result.pq_pk_bytes == expected["pq_pk_bytes"]
    assert result.pq_ciphertext_bytes == expected["pq_ciphertext_bytes"]
    assert result.handshake_bytes == 32 + expected["pq_pk_bytes"] + 32 + expected["pq_ciphertext_bytes"]
    assert result.kem_name == kem_name


def test_cnsa_2_kem_produces_32_byte_session_key():
    """CNSA 2.0 path also derives a 32-byte session key (HKDF length is independent of KEM size)."""
    result = run_handshake(kem_name="ML-KEM-1024")
    assert len(result.shared_key) == 32


def test_run_handshake_records_kem_name():
    """The result reports which KEM was actually used."""
    assert run_handshake(kem_name="ML-KEM-768").kem_name == "ML-KEM-768"
    assert run_handshake(kem_name="ML-KEM-1024").kem_name == "ML-KEM-1024"


def test_hkdf_info_domain_separates_kems():
    """Same input secrets + different KEM-derived info bytes must produce different keys.

    This is the correctness check that HKDF info binding actually domain-separates
    sessions run at different KEM parameter sets, even if (hypothetically) the underlying
    secrets collided.
    """
    from pqc_hybrid_handshake.handshake import _hkdf_info_for, derive_combined_key

    cs = b"\x11" * 32
    ps = b"\x22" * 32
    transcript = b"identical-transcript"
    info_768 = _hkdf_info_for("ML-KEM-768")
    info_1024 = _hkdf_info_for("ML-KEM-1024")
    assert info_768 != info_1024
    k_768 = derive_combined_key(cs, ps, transcript, info=info_768)
    k_1024 = derive_combined_key(cs, ps, transcript, info=info_1024)
    assert k_768 != k_1024


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


def test_transcript_binding_resists_one_byte_tamper():
    """Sibling to test_combiner_is_deterministic: same secrets + same transcript
    → same key (determinism); same secrets + tampered transcript → different
    keys. Together they characterize transcript binding: a MitM flipping any
    byte of any public value causes Alice and Bob to derive distinct session
    keys, so the AEAD on first use fails to authenticate.
    """
    cs = b"\x11" * 32
    ps = b"\x22" * 32
    honest_transcript = b"bob_pub" + b"kem_pub" + b"alice_pub" + b"ciphertext"
    tampered = bytearray(honest_transcript)
    tampered[7] ^= 0x01  # flip one bit of "kem_pub"
    assert derive_combined_key(cs, ps, honest_transcript) != derive_combined_key(
        cs, ps, bytes(tampered)
    )


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
