# RSA-PSS & Certificate Transparency — Overview

> **Version:** 0.1.0-draft  
> **Date:** 2026-01-19  
> **Status:** Draft  

## Purpose

This specification defines Swift APIs for RSA-PSS signature verification and Certificate Transparency (CT) verification, built on OpenSSL's EVP and CT libraries. 

## Specification Index

| Document | Description | Priority |
|----------|-------------|----------|
| [overview.md](overview.md) | This file — design principles, scope, error handling, file structure | — |
| [rsa-pss.md](rsa-pss.md) | RSA-PSS types, verification API, usage examples | High |
| [ct.md](ct.md) | Certificate Transparency types, SCT verification API, policy | High |
| [x509.md](x509.md) | X.509 certificate wrapper, SHA-384 addition | High |
| [hmac.md](hmac.md) | HMAC authentication codes, swift-crypto style | 1 |
| [hkdf.md](hkdf.md) | HKDF key derivation (RFC 5869) | 2 |
| [aead.md](aead.md) | AES-GCM and ChaCha20-Poly1305 AEAD ciphers | 3 |
| [x509-chain.md](x509-chain.md) | X.509 chain verification, trust stores, policies | 4 |
| [test-vectors](#test-vectors) | Public test vector sources for validation | — |

---

## Scope

| In Scope (OpenSSL) | Out of Scope |
|-------------------|--------------|
| RSA-PSS signature verification | TLSNotary protocol |
| SCT parsing & signature verification | OpenTimestamps integration |
| Certificate chain building & verification | Event formatting |
| CT log list management | HTTP layer / networking |
| HMAC authentication | DNSSEC verification |
| HKDF key derivation | Full TLS handshake |
| AEAD ciphers (AES-GCM, ChaCha20-Poly1305) | Key exchange |
| X.509 trust store management | Certificate issuance |

---

## Design Principles

1. **swift-crypto style** — High-level, type-safe APIs hiding OpenSSL internals
2. **Bool for validity** — `isValid*()` returns `Bool`; throws only for programmer errors
3. **Policy-driven** — CT verification uses policy objects, not hard-coded thresholds
4. **Cross-platform** — Works on Apple platforms and Linux via OpenSSL backend
5. **Sendable everywhere** — All public types conform to `Sendable` for concurrency safety

---

## Module Organization

```swift
import OpenSSL

// RSA-PSS (see rsa-pss.md)
OpenSSL.RSA.PSS.PublicKey
OpenSSL.RSA.PSS.Signature
OpenSSL.RSA.PSS.Parameters

// Certificate Transparency (see ct.md)
OpenSSL.CT.SCT
OpenSSL.CT.LogList
OpenSSL.CT.Policy
OpenSSL.CT.SCTReport

// HMAC (see hmac.md)
OpenSSL.HMAC<H>
OpenSSL.HashedAuthenticationCode<H>
OpenSSL.SymmetricKey

// HKDF (see hkdf.md)
OpenSSL.HKDF<H>

// AEAD (see aead.md)
OpenSSL.AES.GCM
OpenSSL.ChaChaPoly

// X.509 (see x509.md, x509-chain.md)
OpenSSL.X509.Certificate
OpenSSL.X509.TrustStore
OpenSSL.X509.VerificationPolicy
OpenSSL.SHA.SHA384Digest
```

---

## Error Handling

### Philosophy

- **Fast path**: `isValid*()` methods return `Bool` — no exceptions for invalid signatures
- **Detailed path**: `verify*()` methods return result structs with per-item failure reasons
- **Throws**: Only for programmer/configuration errors (malformed input, unsupported params)

### Error Type

```swift
/// Errors that can occur during OpenSSL operations.
public enum OpenSSLError: Error, Equatable, Sendable {
    /// The key data is invalid or malformed.
    case invalidKey(String)
    
    /// The signature is invalid or malformed.
    case invalidSignature(String)
    
    /// The certificate is invalid or malformed.
    case invalidCertificate(String)
    
    /// The input data is invalid or malformed.
    case invalidInput(String)
    
    /// An operation is not supported (e.g., unsupported algorithm).
    case unsupportedOperation(String)
    
    /// An underlying OpenSSL error occurred.
    case underlyingError(String)
    
    /// AEAD authentication tag verification failed.
    case authenticationFailure
}

extension OpenSSLError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .invalidKey(let reason): return "Invalid key: \(reason)"
        case .invalidSignature(let reason): return "Invalid signature: \(reason)"
        case .invalidCertificate(let reason): return "Invalid certificate: \(reason)"
        case .invalidInput(let reason): return "Invalid input: \(reason)"
        case .unsupportedOperation(let reason): return "Unsupported operation: \(reason)"
        case .underlyingError(let reason): return "OpenSSL error: \(reason)"
        case .authenticationFailure: return "Authentication failed"
        }
    }
}
```

---

## Implementation Notes

### Memory Management

- All OpenSSL pointer types (`EVP_PKEY*`, `X509*`, `SCT*`, `CTLOG_STORE*`) are wrapped in Swift classes with `deinit` calling the appropriate `*_free` function.
- Swift structs hold reference-counted wrappers to ensure memory safety.

### Thread Safety

- All public types are `Sendable`.
- OpenSSL context objects are created per-operation or use thread-local storage where required.

---

## Test Vectors

Public test vectors are available for validating API implementations against known-correct outputs and attack vectors.

### Recommended: Wycheproof

**[Project Wycheproof](https://github.com/C2SP/wycheproof)** is the recommended primary source for test vectors:

- JSON format with schemas (easy to parse in Swift)
- Covers all APIs: HMAC, HKDF, AES-GCM, ChaCha20-Poly1305, RSA-PSS
- Includes attack vectors (invalid signatures, wrong tags, edge cases)
- Used by pyca/cryptography, BoringSSL, and other major libraries

```bash
# Clone as submodule or vendor JSON files
git clone https://github.com/C2SP/wycheproof.git
# Test vectors in: wycheproof/testvectors_v1/
```

### Test Vector Sources by Algorithm

| Algorithm | Primary Source | Additional Sources |
|-----------|---------------|-------------------|
| **HMAC** | Wycheproof `hmac_sha*.json` | [NIST CAVP](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/message-authentication), [RFC 4231](https://www.rfc-editor.org/rfc/rfc4231) |
| **HKDF** | [RFC 5869 Appendix A](https://www.rfc-editor.org/rfc/rfc5869.html) (7 test cases) | Wycheproof `hkdf_sha*.json` |
| **AES-GCM** | Wycheproof `aes_gcm_test.json` | [NIST CAVP GCM](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip) |
| **ChaCha20-Poly1305** | [RFC 8439 Appendix A](https://www.rfc-editor.org/rfc/rfc8439.html) | Wycheproof `chacha20_poly1305_test.json` |
| **RSA-PSS** | Wycheproof `rsa_pss_*.json` | [NIST CAVP RSA](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program) |
| **X.509** | Wycheproof `x509_test.json` | — |
| **CT (SCT)** | [CT Test Logs](https://certificate.transparency.dev/testlogs/) | [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) |

### RFC 5869 HKDF Test Case 1 (SHA-256)

```
Hash = SHA-256
IKM  = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 octets)
salt = 0x000102030405060708090a0b0c (13 octets)
info = 0xf0f1f2f3f4f5f6f7f8f9 (10 octets)
L    = 42

PRK  = 0x077709362c2e32df0ddc3f0dc47bba63
       90b6c73bb50f9c3122ec844ad7c2b3e5 (32 octets)
OKM  = 0x3cb25f25faacd57a90434f64d0362f2a
       2d2d0a90cf1a5a4c5db02d56ecc4c5bf
       34007208d5b887185865 (42 octets)
```

### Suggested Test File Structure

```
Tests/OpenSSLTests/
├── Resources/
│   └── wycheproof/           # Vendored JSON test vectors
│       ├── hmac_sha256_test.json
│       ├── hmac_sha384_test.json
│       ├── hmac_sha512_test.json
│       ├── hkdf_sha256_test.json
│       ├── aes_gcm_test.json
│       ├── chacha20_poly1305_test.json
│       └── rsa_pss_*.json
├── HMACTests.swift
├── HKDFTests.swift
├── AESGCMTests.swift
├── ChaChaPolyTests.swift
├── RSAPSSTests.swift
└── WycheproofTestHelper.swift  # JSON parsing utilities
```

---

## File Structure

```
Sources/OpenSSL/
├── OpenSSL.swift              # Root namespace, extended with CT enum
├── Error.swift                # OpenSSLError (refactored from OpenSSL.swift)
├── RSA/
│   ├── RSA.swift              # RSA namespace
│   ├── RSA+PSS.swift          # PSS types and verification
│   └── RSA+Key.swift          # Key types (shared)
├── CT/
│   ├── CT.swift               # CT namespace
│   ├── CT+SCT.swift           # SCT type and parsing
│   ├── CT+Log.swift           # Log and LogList types
│   ├── CT+Policy.swift        # Policy and SCTReport
│   └── CT+Verification.swift  # Verification functions
├── X509/
│   ├── X509.swift             # X509 namespace
│   ├── X509+Certificate.swift # Certificate type
│   ├── X509+TrustStore.swift  # TrustStore type
│   ├── X509+VerificationPolicy.swift  # Policy enum
│   └── X509+Verification.swift # Chain verification
├── HMAC/
│   ├── HMAC.swift             # HMAC<H> type and static methods
│   └── HashedAuthenticationCode.swift  # Result type
├── KDF/
│   └── HKDF.swift             # HKDF<H> key derivation
├── AEAD/
│   ├── AES-GCM.swift          # AES.GCM namespace and API
│   ├── ChaChaPoly.swift       # ChaChaPoly namespace and API
│   └── SealedBox.swift        # SealedBox types
├── Keys/
│   ├── SymmetricKey.swift     # SymmetricKey type
│   └── SymmetricKeySize.swift # Size enum
├── Digests/
│   ├── HashFunction.swift     # HashFunction protocol
│   ├── SHA256.swift           # SHA256 (existing, extend)
│   ├── SHA384.swift           # SHA384 (new)
│   └── SHA512.swift           # SHA512 (new)
└── Internal/
    ├── OpenSSLPointer.swift   # Reference-counted wrappers
    └── BIO+Helpers.swift      # BIO utility functions
```

---

## Future Extensions

1. **Merkle Inclusion Proofs** — `CT.MerkleInclusionProof`, `CT.verifyInclusion(sct:proof:sth:)`
2. **Certificate Chain Validation** — `X509.CertificateChain`, `chain.verify(trustAnchors:)`
3. **RSA-PSS Signing** — `RSA.PSS.PrivateKey`, `signature(for:)`
4. **OCSP** — `OCSP.Response`, SCT extraction from stapled responses
5. **TLS Session Info** — `SSL.SessionInfo` for protocol version, cipher suite extraction

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 0.1.0-draft | 2026-01-19 | Initial API design |
| 0.1.0-draft | 2026-01-19 | Refactored into multi-file structure |
| 0.1.0-draft | 2026-01-19 | Added HMAC, HKDF, AEAD, X.509 chain specs |
| 0.1.0-draft | 2026-01-19 | Added test vectors section (Wycheproof, NIST CAVP, RFCs) |
