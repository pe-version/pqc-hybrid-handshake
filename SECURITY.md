# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in `pqc-hybrid-handshake`, please report it through [GitHub's private vulnerability reporting](https://github.com/pe-version/pqc-hybrid-handshake/security/advisories/new) rather than opening a public issue.

Reports will be acknowledged within seven days where possible.

## Scope

This is a portfolio and learning project — a *demonstration* of the hybrid X25519 + ML-KEM-768 construction, not production cryptographic software. Treat it as illustrative.

The post-quantum side links against [`liboqs`](https://github.com/open-quantum-safe/liboqs), which is **research-grade** and **not on the CMVP Active list**. Do not deploy this implementation in environments that require a FIPS 140-3 boundary or any other cryptographic-module certification.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | ✓ |
| < 0.1 | ✗ |
