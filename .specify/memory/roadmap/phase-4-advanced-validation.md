# Phase 4: Advanced Validation

> **Status:** ⏳ Planned  
> **Last Updated:** 2026-03-14

## Goal

Deliver full X.509 certificate chain verification with trust store management and policy-based validation, completing the certificate verification story started in Phases 2–3.

## Features

### Trust Store Management

- **Purpose**: Manage collections of trusted root and intermediate certificates for chain verification, with system, file, and directory loading
- **Success Metrics**:
  - `TrustStore` with `init(certificates:)`, `.system()`, `.loadPEM(from:)`, `.loadDirectory(from:)`
  - Immutable value semantics: `adding(_:)`, `adding(contentsOf:)`, `merging(_:)` return new stores
  - System trust store loads from Keychain (macOS/iOS) and `/etc/ssl/certs` (Linux)
  - `Sendable` conformance
- **Dependencies**: Phase 2 (X.509 Certificate)
- **Notes**: See `Draft APIs/x509-chain.md` → Trust Store; consider bundling Mozilla root store for cross-platform consistency

### Verification Policy

- **Purpose**: Policy-driven certificate verification supporting TLS, code signing, email, and custom use cases
- **Success Metrics**:
  - `VerificationPolicy` enum: `.tls(hostname:)`, `.tlsClient`, `.codeSigning`, `.email(address:)`, `.any`, `.custom(CustomPolicy)`
  - `CustomPolicy` struct with: `requiredExtendedKeyUsages`, `requiredKeyUsages`, `hostname`, `email`, `maxDepth`, `checkRevocation`, `verificationTime`
  - `ExtendedKeyUsage` and `KeyUsage` types
  - Hostname verification for TLS via `X509_VERIFY_PARAM_set1_host`
- **Dependencies**: Trust Store Management
- **Notes**: See `Draft APIs/x509-chain.md` → Verification Policy

### Chain Verification API

- **Purpose**: Build and verify certificate chains from leaf to root with detailed failure reporting
- **Success Metrics**:
  - Fast path: `X509.isValid(_:intermediates:using:policy:)` → `Bool`
  - Detailed path: `X509.verify(...)` → `VerificationResult` with chain, failures, policy
  - `X509.buildChain(for:intermediates:using:)` → `[Certificate]?`
  - `ChainFailure` enum covering: `untrustedRoot`, `expired`, `notYetValid`, `invalidSignature`, `hostnameMismatch`, `revoked`, `selfSignedCertificate`, `incompletePath`, `chainTooLong`, and more
  - OpenSSL `X509_V_ERR_*` codes mapped to Swift failure cases
- **Dependencies**: Trust Store Management, Verification Policy, Phase 3 (RSA-PSS for signature verification within chains)
- **Notes**: See `Draft APIs/x509-chain.md` → Verification API; uses `X509_STORE_CTX` per-call for thread safety

## Dependencies & Sequencing

```
Phase 2 (X.509 basic) ──→ Trust Store ──→ Verification Policy ──→ Chain Verification
Phase 3 (RSA-PSS) ──────────────────────────────────────────────→ Chain Verification
```

- Trust Store can begin as soon as Phase 2 X.509 Certificate type is available
- Chain Verification requires both the policy framework and RSA-PSS from Phase 3

## Phase Metrics

- 3 features shipped (Trust Store, Policy, Chain Verification)
- All types conform to `Sendable`
- `isValid*()` fast path returns `Bool` without throwing
- Full chain verification tested against real-world certificate chains
- `swift build` and `swift test` pass on macOS + Linux

## Test Vector Strategy

- Wycheproof `x509_test.json` for chain verification edge cases
- Real-world certificate chains (e.g., Let's Encrypt, Google) for integration testing
- Expired/revoked/self-signed test certificates for failure path coverage
- Platform-specific system trust store validation (macOS Keychain vs. Linux `/etc/ssl/certs`)
