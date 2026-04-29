# pqc-hybrid-handshake

[![CI](https://github.com/pe-version/pqc-hybrid-handshake/actions/workflows/ci.yml/badge.svg)](https://github.com/pe-version/pqc-hybrid-handshake/actions/workflows/ci.yml)

> A working end-to-end **hybrid X25519 + ML-KEM-768** key exchange in Python, using [`liboqs`](https://github.com/open-quantum-safe/liboqs) for the post-quantum half. The same construction major TLS deployments (Cloudflare, Chrome, AWS) are rolling out today.

## Why hybrid?

NIST finalized ML-KEM (FIPS 203) in 2024, but the cryptography community is not migrating to *pure* post-quantum primitives. The current consensus — baked into the IETF TLS 1.3 hybrid key-exchange drafts and into real production deployments — is **hybrid**: combine a classical key agreement (X25519) with a post-quantum KEM (ML-KEM-768) and use a KDF to derive a single session key from both shared secrets.

The reasoning:

- **Belt and suspenders.** ML-KEM has been standardized but it is much younger than X25519. If a flaw is discovered in ML-KEM, the X25519 half still protects you. If a sufficiently large fault-tolerant quantum computer (CRQC) arrives, the ML-KEM half still protects you. The session key is secure as long as **at least one** of the two primitives stays secure.
- **Harvest now, decrypt later.** Long-lived secrets — anything you'd hate to see leaked in 10 years — need post-quantum protection now, even if the CRQC is still hypothetical.

This demo shows the construction in working code: two parties (Alice and Bob) run both an X25519 Diffie-Hellman and an ML-KEM-768 encapsulation, derive a shared 32-byte session key via HKDF salted with the handshake transcript, and round-trip a message under that key with AES-256-GCM. It also prints the **wire-size cost** of the post-quantum side, which is real (~2.3 KB total handshake material vs. 64 bytes for X25519 alone).

## Install

The package itself is pure Python and runs anywhere; the per-OS notes below cover installing the [`liboqs`](https://github.com/open-quantum-safe/liboqs) C library and its Python binding [`liboqs-python`](https://github.com/open-quantum-safe/liboqs-python). CI validates on Ubuntu (Python 3.10–3.12) on every push — see the badge above.

### macOS

The `liboqs` Homebrew formula ships only a **static** archive (`liboqs.a`), which Python's `ctypes`-based `oqs` binding cannot load — it requires a shared library (`.dylib`). Build from source instead, mirroring the Linux instructions:

```bash
brew install cmake ninja
git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir build && cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX="$HOME/liboqs-install" \
  -DOQS_BUILD_ONLY_LIB=ON -DBUILD_SHARED_LIBS=ON \
  -DOQS_USE_OPENSSL=OFF ..
ninja && ninja install
# Make the lib discoverable by ctypes.util.find_library:
mkdir -p "$HOME/lib" && ln -sf "$HOME/liboqs-install/lib/liboqs.dylib" "$HOME/lib/liboqs.dylib"
cd ../.. && pip install -e .
```

`-DOQS_USE_OPENSSL=OFF` opts liboqs out of OpenSSL for SHA / AES / RAND helpers and uses its own bundled implementations. This avoids a runtime link dependency on a separately-installed OpenSSL (and the matching architecture/version dance), at the cost of slightly less optimized symmetric primitives — fine for this demo and for any setup that doesn't already have an OpenSSL build matching the target arch.

#### Apple Silicon note

If `which brew` returns `/usr/local/bin/brew`, you are running the **Intel-arch Homebrew under Rosetta**, which will produce an x86_64 `liboqs.dylib` that fails to load into a native arm64 Python with `incompatible architecture` errors.

The verified fix is to install the arm64 Homebrew at `/opt/homebrew` and use it for all native development. The migration is documented at <https://docs.brew.sh/Installation>; once installed, run `cmake` and `ninja` from `/opt/homebrew/bin` and follow the build above. The two brews coexist cleanly — your existing `/usr/local` brew can stay for any x86_64-only dependencies you have under Rosetta.

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

### Windows

Both `cryptography` and `liboqs` support Windows, and `liboqs-python` loads `.dll` libraries on Windows. This project has not been tested on Windows directly; see the [`liboqs` repository](https://github.com/open-quantum-safe/liboqs) for the current Windows build instructions, or use the Docker route below — Docker Desktop runs on Windows and bypasses the native build entirely.

### Docker (skip the install dance — runs on macOS, Linux, and Windows)

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

## Testing

The CI workflow at [`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs `pytest -v` on every push against a fresh build of `liboqs` `main`, on Python 3.10 / 3.11 / 3.12 (Ubuntu). That's the source of truth for whether the test suite passes.

Locally:

```bash
.venv/bin/python -m pytest
```

Tests have a 10-second per-test timeout (configured via `pytest-timeout` in `pyproject.toml`). The full suite normally completes in well under one second; the timeout exists so that runaway hangs in native-library load paths or RNG calls self-kill rather than blocking the run.

### Troubleshooting: pytest hangs at startup

If `pytest` hangs at module import (rather than during a test), `pytest-timeout` cannot help — the timeout only fires once a test starts running. The most common cause is a stuck Python process from an earlier session holding a `dyld` lock during `dlopen` of `liboqs`. Symptom: a freshly-started `pytest` sits with no output for minutes, and `ps -ax | grep pytest` shows multiple `python -m pytest` processes accumulating.

To clear it:

```bash
# Kill all Python processes related to this project. Project-scoped via -f match.
pkill -9 -f pqc_hybrid_handshake
```

If the hang persists, close your terminal tab (or all tabs running Claude Code / shells touching this project) — that sends `SIGHUP` to all child processes and forces macOS to release the shared `dyld` cache lock. As a last resort, log out and back in, or reboot. New shells will then run `pytest` cleanly.

## Compliance notes

- **FIPS 140-3 / CMVP.** This demo links against [`liboqs`](https://github.com/open-quantum-safe/liboqs) via [`liboqs-python`](https://github.com/open-quantum-safe/liboqs-python). `liboqs` is **not on the CMVP Active list** and is explicitly self-described as research-grade. Treat the post-quantum side of this handshake as a *prototype*, not a validated cryptographic module. Federal or otherwise regulated environments that require a FIPS 140-3 boundary should wait for CMVP-validated PQC modules or use a vendor implementation that has one.
- **CNSA 2.0 parameter selection.** This demo uses **ML-KEM-768** (NIST Category 3) and AES-256 for portability and small wire size. Systems classified as National Security Systems (NSS) under [NSA CNSA 2.0](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF) require **ML-KEM-1024** (Category 5) and matching ML-DSA-87 for signatures. Swap the `KEM_NAME` constant in [`src/pqc_hybrid_handshake/handshake.py`](src/pqc_hybrid_handshake/handshake.py) for NSS-aligned use.

## Roadmap

- [ ] TCP socket version (real network handshake with on-wire bytes shown).
- [ ] X-Wing combiner option (alongside the current HKDF construction).
- [ ] Jupyter notebook walkthrough.
- [ ] Pure-ML-KEM mode for comparison.

## Related work

- [`pqc-readiness-scanner`](https://github.com/pe-version/pqc-readiness-scanner) — Python CLI for inventorying quantum-vulnerable cryptography in code, X.509 certs, SSH keys, and live TLS endpoints (with SARIF / CycloneDX 1.6 CBOM / OMB M-23-02 inventory CSV outputs).
- [`pqc-semgrep-rules`](https://github.com/pe-version/pqc-semgrep-rules) — Semgrep ruleset flagging the same quantum-vulnerable algorithms across Python, JavaScript/TypeScript, Go, and Java. Drops into existing client CI.

## License

MIT — see [LICENSE](LICENSE).

## Acknowledgments

Built with assistance from [Claude Code](https://claude.ai/code).
