# Phase 3: Verification

> **Status:** ⏳ Planned  
> **Last Updated:** 2026-03-14

## Goal

Deliver the core verification APIs — RSA-PSS signature verification, Certificate Transparency (SCT verification), and AEAD ciphers — enabling TLS-oriented cryptographic workflows.

## Features

### RSA-PSS Signature Verification

- **Purpose**: Verify RSA-PSS signatures over data and digests, supporting TLS certificate signature validation with SHA-256 and SHA-384
- **Success Metrics**:
  - `RSA.PSS.PublicKey` with PEM, DER, and certificate-based initialization
  - `isValidSignature(_:for:parameters:)` returning `Bool` (no throws for invalid signatures)
  - Configurable parameters: hash function, MGF1 hash, salt length
  - Convenience statics: `.sha256`, `.sha384`
  - Key size introspection (`keySizeInBits`)
- **Dependencies**: Phase 2 (X.509 Certificate, Pointer Wrappers, Error Type)
- **Notes**: See `Draft APIs/rsa-pss.md`; uses `EVP_DigestVerifyInit` / `EVP_DigestVerify`

### Certificate Transparency (CT)

- **Purpose**: Parse and verify Signed Certificate Timestamps (SCTs) per RFC 6962/9162, with policy-based verification against trusted CT log lists
- **Success Metrics**:
  - `CT.SCT` parsing from TLS bytes, base64, and certificate extensions
  - `CT.Log` and `CT.LogList` with bundled public logs (Google, Cloudflare, DigiCert, Let's Encrypt)
  - `CT.LogList(googleJSON:)` for loading custom log lists
  - `CT.Policy` enum: `.atLeast(Int)`, `.requireDistinctLogs(Int)`, `.allMustPass`, `.chromeLike`, `.default`
  - Fast path: `isValidSCTs(_:for:issuer:context:)` → `Bool`
  - Detailed path: `verifySCTs(...)` → `SCTReport` with per-SCT results and failure reasons
  - `VerificationContext` with configurable log list, policy, time, clock skew
- **Dependencies**: Phase 2 (X.509 Certificate — needed for SCT extraction and precert verification)
- **Notes**: See `Draft APIs/ct.md`; uses OpenSSL's `CT_POLICY_EVAL_CTX` and `SCT_LIST_validate`

### AEAD Ciphers (AES-GCM + ChaCha20-Poly1305)

- **Purpose**: Authenticated encryption for TLS record layer verification and general-purpose encrypt/decrypt, matching swift-crypto's `AES.GCM` and `ChaChaPoly` APIs
- **Success Metrics**:
  - `AES.GCM.seal` / `AES.GCM.open` with AAD support
  - `ChaChaPoly.seal` / `ChaChaPoly.open` with AAD support
  - `SealedBox` type with `nonce`, `ciphertext`, `tag`, `combined` representation
  - `Nonce` types (12 bytes) with random and data-based initialization
  - `isAuthentic` verification-only API (no decryption needed)
  - AES key sizes: 128, 192, 256 bits; ChaCha20 requires 256 bits
  - 16-byte authentication tags (standard)
- **Dependencies**: Phase 2 (SymmetricKey, Error Type)
- **Notes**: See `Draft APIs/aead.md`; uses `EVP_EncryptInit_ex` / `EVP_DecryptInit_ex`; CRITICAL — never reuse nonce with same key

## Dependencies & Sequencing

```
Phase 2 (X.509 basic) ──→ RSA-PSS ──┐
                         ──→ CT ─────┤──→ Phase 4
Phase 2 (SymmetricKey) ──→ AEAD ────┘
```

- RSA-PSS and CT can be developed in parallel once Phase 2 X.509 is available
- AEAD depends only on SymmetricKey from Phase 2 — can start as soon as Phase 2 keys ship
- All three are independent of each other

## Phase Metrics

- 3 API families shipped
- All types conform to `Sendable`
- Unit tests with Wycheproof vectors for each algorithm
- `isValid*()` fast paths return `Bool` without throwing
- `swift build` and `swift test` pass on macOS + Linux

## Test Vector Strategy

- **RSA-PSS**: Wycheproof `rsa_pss_*.json` + NIST CAVP RSA
- **AEAD (AES-GCM)**: Wycheproof `aes_gcm_test.json` + NIST CAVP GCM
- **AEAD (ChaCha20-Poly1305)**: RFC 8439 Appendix A + Wycheproof `chacha20_poly1305_test.json`
- **CT**: CT Test Logs from certificate.transparency.dev + RFC 6962 test cases
