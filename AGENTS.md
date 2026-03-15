# AI Agent Guide: swift-openssl

**Last Updated**: 2026-03-14 | **Phase**: 1 Complete, Phases 2–6 Planned

## What This Project Is

A Swift package providing modern, type-safe bindings for OpenSSL cryptographic operations — matching swift-crypto's API style — across Apple platforms and Linux. Uses Swift's C interoperability with OpenSSL 3.x.

## Current State

### What Exists
- **Phase 1 (Core Extraction)**: Complete
  - OpenSSL 3.x source extraction via git subtree
  - SPM build configuration with `libcrypto` and `libssl` C targets
  - Swift wrapper module (`OpenSSL`) with top-level types: `SHA256`, `RSA`, `SSL`, `Base64URL`
  - `OpenSSLError` enum with `Sendable`, `Equatable`, `LocalizedError` conformance
  - Algorithm selection (legacy ciphers, hashes, regional standards disabled)
  - 11 tests passing (SHA-256, Base64URL, RSA key parsing)

### What's Planned
- **Phase 2**: Foundation Crypto (HMAC, HKDF, SymmetricKey, HashFunction, X.509 basic, error types, pointer wrappers)
- **Phase 3**: Verification (RSA-PSS, Certificate Transparency, AEAD)
- **Phase 4**: Advanced Validation (X.509 Chain, Trust Store, Verification Policy)
- **Phase 5**: Binary Size Optimization (no-engine, no-hw, provider trimming)
- **Phase 6**: Advanced Extensions (Merkle proofs, RSA-PSS signing, OCSP, TLS session info)

See `.specify/memory/roadmap.md` and `.specify/memory/roadmap/` for detailed phase specs.

## Architecture

**Pattern**: Single module with top-level types (matching swift-crypto)

```
Sources/
├── OpenSSL/           # Swift wrapper API (top-level types: SHA256, RSA, SSL, Base64URL)
├── libcrypto/         # OpenSSL crypto library (C sources + headers)
└── libssl/            # OpenSSL SSL/TLS library (C sources + headers)
```

- `import OpenSSL` gives access to all Swift types directly (no namespace enum)
- `libcrypto` and `libssl` are also exposed as separate products for low-level access

## Tech Stack

- **Language**: Swift 6.0+
- **Package Manager**: Swift Package Manager
- **Testing**: XCTest
- **Platforms**: macOS 13+, iOS 16+, tvOS 16+, watchOS 9+, visionOS 1+, Linux
- **OpenSSL**: 3.x (vendored via git subtree)

## Key Constraints

- **Pre-1.0**: APIs are not stable, pin with `exact:` version
- **No test vectors yet**: Cryptographic test vectors (Wycheproof, NIST CAVP) planned for Phase 2+
- **No ASM**: Built with `no-asm` for cross-platform portability
- **Top-level types**: Types like `SHA`, `RSA`, `HMAC` are module-scope (not nested in a namespace enum)

## Global Guidance

- Keep changes small and reviewable
- Do not introduce new third-party dependencies without asking
- Do not output or log secrets (private keys, sensitive test vectors)
- Validate changes with `swift test`

## How to Help

1. Check `.specify/memory/roadmap.md` for current phase status
2. Review phase files in `.specify/memory/roadmap/` for detailed specs
3. Run `swift test` to verify all tests pass
4. Follow existing code style (doc comments on all public API, `Sendable` conformance)
