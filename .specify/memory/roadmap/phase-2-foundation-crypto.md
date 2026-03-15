# Phase 2: Foundation Crypto

> **Status:** ⏳ Planned  
> **Last Updated:** 2026-03-14

## Goal

Build the shared type system and foundational cryptographic primitives that all subsequent API phases depend on. Establish error handling, memory management patterns, and the first two algorithm families (HMAC, HKDF).

## Features

### Shared Error Type (`OpenSSLError`)

- **Purpose**: Unified error enum for all OpenSSL operations, matching swift-crypto's pattern of throwing only for programmer errors
- **Success Metrics**:
  - `OpenSSLError` enum with cases: `invalidKey`, `invalidSignature`, `invalidCertificate`, `invalidInput`, `unsupportedOperation`, `underlyingError`, `authenticationFailure`
  - Conforms to `Error`, `Equatable`, `Sendable`, `LocalizedError`
  - Used consistently by all subsequent API families
- **Dependencies**: Phase 1 (Core Extraction)
- **Notes**: See `Draft APIs/overview.md` for full definition

### OpenSSL Pointer Wrappers

- **Purpose**: Safe memory management for OpenSSL C pointer types (`EVP_PKEY*`, `X509*`, etc.) via reference-counted Swift wrappers with `deinit`
- **Success Metrics**:
  - `@unchecked Sendable` wrapper classes with `deinit` calling appropriate `*_free`
  - Zero memory leaks under repeated create/destroy cycles
  - BIO helper utilities for PEM/DER encoding
- **Dependencies**: Phase 1 (Core Extraction)
- **Notes**: See `Draft APIs/overview.md` → Memory Management

### HashFunction Protocol & Digest Types

- **Purpose**: Generic hash function protocol enabling `HMAC<H>` and `HKDF<H>` to be parameterized by algorithm
- **Success Metrics**:
  - `HashFunction` protocol with `Digest` associated type, `digestByteCount`, `blockByteCount`, `update`, `finalize`
  - `SHA256`, `SHA384`, `SHA512` conforming types
  - `SHA384Digest` and `SHA512Digest` types (SHA256 already exists)
  - All types conform to `Sendable`
- **Dependencies**: Shared Error Type
- **Notes**: See `Draft APIs/hmac.md` → Hash Function Protocol; `Draft APIs/x509.md` → SHA-384

### SymmetricKey & SymmetricKeySize

- **Purpose**: Type-safe symmetric key representation for HMAC, HKDF, and AEAD operations
- **Success Metrics**:
  - `SymmetricKey` with `init(data:)`, `init(size:)`, `withUnsafeBytes`
  - `SymmetricKeySize` enum: `.bits128`, `.bits192`, `.bits256`, `.bits(Int)`
  - Conforms to `Sendable`
  - Random key generation uses OpenSSL's CSPRNG
- **Dependencies**: Phase 1 (Core Extraction)
- **Notes**: See `Draft APIs/hmac.md` → Symmetric Key

### HMAC

- **Purpose**: Hash-based Message Authentication Codes for message authentication and integrity verification, matching swift-crypto's `HMAC<H>` API
- **Success Metrics**:
  - `HMAC<H>` with incremental (`init/update/finalize`) and one-shot (`authenticationCode(for:using:)`) APIs
  - `HashedAuthenticationCode<H>` result type with `rawRepresentation` and constant-time `==`
  - `isValidAuthenticationCode` verification method
  - Works with SHA-256, SHA-384, SHA-512
  - Constant-time comparison via `CRYPTO_memcmp`
- **Dependencies**: HashFunction Protocol, SymmetricKey
- **Notes**: See `Draft APIs/hmac.md` for full spec; uses `EVP_MAC` API

### HKDF

- **Purpose**: HMAC-based Key Derivation Function (RFC 5869) for deriving cryptographic keys from input key material
- **Success Metrics**:
  - One-shot `deriveKey(inputKeyMaterial:salt:info:outputByteCount:)` API
  - Fine-grained `extract` + `expand` API for multi-key derivation
  - Output length validation (max 255 × H.digestByteCount)
  - Works with SHA-256, SHA-384, SHA-512
- **Dependencies**: HMAC (uses `HashedAuthenticationCode<H>` for PRK type)
- **Notes**: See `Draft APIs/hkdf.md` for full spec; uses `EVP_KDF` API

### X.509 Certificate (Basic)

- **Purpose**: Minimal X.509 certificate wrapper sufficient for key extraction and SCT parsing in later phases
- **Success Metrics**:
  - Parse from PEM and DER
  - Properties: `notBefore`, `notAfter`, `subjectCommonName`, `issuerCommonName`, `serialNumber`, `isCurrentlyValid`, `validityPeriodDays`
  - Public key extraction: `publicKeyType`, `rsaPSSPublicKey`, `subjectPublicKeyInfo`
  - DER/PEM round-trip encoding
  - `Sendable` conformance via pointer wrapper
- **Dependencies**: OpenSSL Pointer Wrappers, Shared Error Type
- **Notes**: See `Draft APIs/x509.md` for full spec; intentionally minimal — chain validation is Phase 4

## Dependencies & Sequencing

```
Shared Error Type ──┬──→ HashFunction Protocol ──→ HMAC ──→ HKDF
                    │
Pointer Wrappers ───┴──→ X.509 Certificate (Basic)
                    │
SymmetricKey ───────┴──→ HMAC
```

## Phase Metrics

- 7 features shipped
- All types conform to `Sendable`
- Unit tests for each feature
- `swift build` and `swift test` pass on macOS + Linux

## Test Vector Strategy

- HMAC: Wycheproof `hmac_sha*.json` + RFC 4231
- HKDF: RFC 5869 Appendix A (7 test cases) + Wycheproof `hkdf_sha*.json`
- X.509: Manual PEM/DER round-trip tests; Wycheproof deferred to Phase 4
