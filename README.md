# pqc-hybrid-handshake

> A working end-to-end **hybrid X25519 + ML-KEM-768** key exchange in Python, using [`liboqs`](https://github.com/open-quantum-safe/liboqs) for the post-quantum half. The same construction major TLS deployments (Cloudflare, Chrome, AWS) are rolling out today.

## Why hybrid?

NIST finalized ML-KEM (FIPS 203) in 2024, but the cryptography community is not migrating to *pure* post-quantum primitives. The current consensus — baked into the IETF TLS 1.3 hybrid key-exchange drafts and into real production deployments — is **hybrid**: combine a classical key agreement (X25519) with a post-quantum KEM (ML-KEM-768) and use a KDF to derive a single session key from both shared secrets.

The reasoning:

- **Belt and suspenders.** ML-KEM has been standardized but it is much younger than X25519. If a flaw is discovered in ML-KEM, the X25519 half still protects you. If a sufficiently large fault-tolerant quantum computer (CRQC) arrives, the ML-KEM half still protects you. The session key is secure as long as **at least one** of the two primitives stays secure.
- **Harvest now, decrypt later.** Long-lived secrets — anything you'd hate to see leaked in 10 years — need post-quantum protection now, even if the CRQC is still hypothetical.

This demo shows the construction in working code: two parties (Alice and Bob) run both an X25519 Diffie-Hellman and an ML-KEM-768 encapsulation, derive a shared 32-byte session key via HKDF salted with the handshake transcript, and round-trip a message under that key with AES-256-GCM. It also prints the **wire-size cost** of the post-quantum side, which is real (~2.3 KB total handshake material vs. 64 bytes for X25519 alone).

## Install

The post-quantum side uses [`liboqs`](https://github.com/open-quantum-safe/liboqs), a C library, via the Python binding [`liboqs-python`](https://github.com/open-quantum-safe/liboqs-python). You need to install `liboqs` first, then `pip install` this project.

### macOS

```bash
brew install liboqs
pip install -e .
```

### Linux (Ubuntu/Debian)

```bash
sudo apt install -y cmake ninja-build libssl-dev
git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir build && cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local -DOQS_BUILD_ONLY_LIB=ON -DBUILD_SHARED_LIBS=ON ..
sudo ninja install
sudo ldconfig
cd ../..
pip install -e .
```

### Docker (skip the install dance)

```bash
docker build -t pqc-hybrid-handshake .
docker run --rm pqc-hybrid-handshake
```

## Run

```bash
python -m pqc_hybrid_handshake
# or, after install:
pqc-hybrid-handshake
```

## Sample output

```
======================================================================
 Hybrid X25519 + ML-KEM-768 handshake demo
======================================================================

  Handshake completed in 1.84 ms
  Derived shared key (32 bytes): 7c3f9e8a4d1b...

  Encrypted message round-tripped via AES-256-GCM (58 byte ct)

Wire-size comparison:
  X25519 only                 64 bytes total handshake material
  X25519 + ML-KEM-768       2336 bytes total handshake material
    classical X25519 pubkeys  2 x 32 = 64 bytes
    ML-KEM-768 public key         1184 bytes
    ML-KEM-768 ciphertext         1088 bytes
  Wire-size cost of post-quantum: 36.5x the bytes

Latency (single in-process handshake; not a benchmark):
  X25519 only             0.18 ms
  X25519 + ML-KEM-768     1.84 ms
```

## How the handshake actually works

1. **Bob has a hybrid keypair.** A static-ish X25519 keypair plus an ML-KEM-768 keypair. He publishes both public keys.
2. **Alice initiates.** She generates an ephemeral X25519 keypair (sends her public key), and runs `ML-KEM.Encapsulate` against Bob's ML-KEM public key, producing a ciphertext (sent to Bob) and a post-quantum shared secret (kept locally).
3. **Both compute the classical secret.** Alice does X25519 against Bob's X25519 public key; Bob does X25519 against Alice's. They get the same 32-byte classical shared secret.
4. **Bob decapsulates.** Bob runs `ML-KEM.Decapsulate(ciphertext)` with his ML-KEM secret key, recovering the same post-quantum shared secret Alice derived.
5. **Both run HKDF.** Both sides compute the session key as
   ```
   key = HKDF-SHA256(
       salt    = transcript,
       ikm     = classical_secret || pq_secret,
       info    = "pqc-hybrid-handshake/v1/x25519+ml-kem-768",
       length  = 32,
   )
   ```
   The transcript binding (Bob's pubkeys + Alice's pubkey + the ML-KEM ciphertext) is what protects real protocols against downgrade and reflection attacks.
6. **Round-trip a message** with AES-256-GCM under the derived key.

## What this demo is and isn't

**It is:**
- A faithful, runnable implementation of the *shape* of the hybrid construction Cloudflare, Chrome, and AWS KMS are deploying for TLS today.
- A clean working example of how X25519 (classical ECDH) and ML-KEM-768 (post-quantum KEM) compose via HKDF.
- A way to feel the wire-size cost of post-quantum cryptography (~36x the bytes of X25519 alone).

**It isn't:**
- A TLS implementation. There's no record protocol, no certificate validation, no full transcript binding for downgrade resistance, no resumption, no rekeying.
- The X-Wing combiner ([`draft-connolly-cfrg-xwing-kem`](https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-06.html)). X-Wing is the more rigorous specifically-designed combiner for ML-KEM + X25519. The IETF TLS hybrid drafts and most current deployments use the simpler HKDF-over-concatenation approach this demo uses; X-Wing is on the roadmap.
- Production code. Treat it as a learning artifact and a starting point.

## Roadmap

- [ ] TCP socket version (real network handshake with on-wire bytes shown).
- [ ] X-Wing combiner option (alongside the current HKDF construction).
- [ ] Jupyter notebook walkthrough.
- [ ] Pure-ML-KEM mode for comparison.

## Related work

This demo is a companion piece to [`pqc-readiness-scanner`](https://github.com/pe-version/pqc-readiness-scanner) (a CLI for inventorying quantum-vulnerable cryptography in code, certs, and TLS endpoints).

## License

MIT — see [LICENSE](LICENSE).

## Acknowledgments

Built with assistance from [Claude Code](https://claude.ai/code).
