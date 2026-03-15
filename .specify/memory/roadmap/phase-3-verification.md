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

```swift
extension RSA {
    public enum PSS {}
}

extension RSA.PSS {
    public enum HashFunction: Sendable {
        case sha256  // 32-byte salt default
        case sha384  // 48-byte salt default
        public var digestLength: Int { get }
    }

    public struct Parameters: Sendable, Equatable {
        public let hashFunction: HashFunction
        public let mgf1HashFunction: HashFunction
        public let saltLength: Int?  // nil = hash-length (TLS 1.3 convention)
        public static let sha256 = Parameters(hashFunction: .sha256)
        public static let sha384 = Parameters(hashFunction: .sha384)
        public init(hashFunction: HashFunction, mgf1HashFunction: HashFunction? = nil, saltLength: Int? = nil)
    }

    public struct PublicKey: Sendable {
        public var keySizeInBits: Int { get }
        public init(pemRepresentation: String) throws
        public init<D: DataProtocol>(derRepresentation: D) throws
        public init(certificate: X509.Certificate) throws
        public var derRepresentation: Data { get }
        public var pemRepresentation: String { get }
    }

    public struct Signature: ContiguousBytes, Sendable {
        public let rawRepresentation: Data
        public init<D: DataProtocol>(rawRepresentation: D)
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R
    }
}

extension RSA.PSS.PublicKey {
    public func isValidSignature<D: DataProtocol>(
        _ signature: RSA.PSS.Signature, for data: D, parameters: RSA.PSS.Parameters = .sha256
    ) -> Bool

    public func isValidSignature<D: Digest>(
        _ signature: RSA.PSS.Signature, for digest: D, parameters: RSA.PSS.Parameters
    ) -> Bool
}
```

**OpenSSL function mapping:**

| Swift API | OpenSSL Functions |
|-----------|-------------------|
| `PublicKey(pemRepresentation:)` | `BIO_new_mem_buf`, `PEM_read_bio_PUBKEY` |
| `PublicKey(derRepresentation:)` | `d2i_PUBKEY` |
| `PublicKey(certificate:)` | `X509_get_pubkey` |
| `keySizeInBits` | `EVP_PKEY_get_bits` |
| `isValidSignature(_:for:parameters:)` | `EVP_DigestVerifyInit`, `EVP_PKEY_CTX_set_rsa_padding(RSA_PKCS1_PSS_PADDING)`, `EVP_PKEY_CTX_set_rsa_pss_saltlen`, `EVP_PKEY_CTX_set_rsa_mgf1_md`, `EVP_DigestVerify` |

**Implementation notes:**
- When `saltLength` is `nil`, use `RSA_PSS_SALTLEN_DIGEST` (salt = hash length, TLS 1.3 convention)
- `EVP_PKEY_get_base_id()` must return `EVP_PKEY_RSA` or `EVP_PKEY_RSA_PSS`; throw `OpenSSLError.invalidKey` otherwise

**Usage examples:**

```swift
import OpenSSL

let publicKey = try RSA.PSS.PublicKey(pemRepresentation: pemString)
let signature = RSA.PSS.Signature(rawRepresentation: signatureData)
let isValid = publicKey.isValidSignature(signature, for: messageData)

// SHA-384
let isValid384 = publicKey.isValidSignature(signature, for: messageData, parameters: .sha384)

// From certificate
let cert = try X509.Certificate(pemRepresentation: certPEM)
let certKey = try RSA.PSS.PublicKey(certificate: cert)
```

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

```swift
public enum CT {}

extension CT {
    public enum SCTSource: Sendable {
        case certificateExtension, tlsExtension, ocspResponse, unknown
    }

    public struct SCT: Sendable {
        public let logID: Data           // SHA-256 of log's public key (32 bytes)
        public let timestamp: UInt64     // Milliseconds since Unix epoch
        public var date: Date { get }
        public let signature: Data
        public let source: SCTSource
        public let extensions: Data
        public init<D: DataProtocol>(tlsBytes: D) throws
        public init(logIDBase64: String, timestamp: UInt64, signatureBase64: String,
                    extensionsBase64: String = "", source: SCTSource = .unknown) throws
        public static func list<D: DataProtocol>(fromTLSBytes tlsBytes: D) throws -> [SCT]
        public static func embedded(in certificate: X509.Certificate) -> [SCT]
    }

    public struct Log: Sendable, Identifiable {
        public let id: Data
        public let name: String
        public let publicKey: Data       // DER-encoded SPKI
        public let `operator`: String?
        public let url: URL?
        public init(name: String, publicKeyBase64: String, operator: String? = nil, url: URL? = nil) throws
    }

    public struct LogList: Sendable {
        public let logs: [Log]
        public init()
        public init(logs: [Log])
        public init<D: DataProtocol>(googleJSON jsonData: D) throws
        public init(contentsOf url: URL) throws
        public static let bundled: LogList
        public func log(withID logID: Data) -> Log?
        public func adding(_ log: Log) -> LogList
        public func adding(contentsOf logs: [Log]) -> LogList
    }

    public enum Policy: Sendable {
        case atLeast(Int)
        case requireDistinctLogs(Int)
        case allMustPass
        case chromeLike  // < 180 days: 2 distinct; 180+ days: 3 distinct
        public static let `default`: Policy = .requireDistinctLogs(1)
    }

    public enum SCTFailure: Sendable, Equatable {
        case invalidSignature, unknownLogID, timestampInFuture
        case timestampOutsideCertValidity, unsupportedVersion, merkleProofMismatch
        case internalError(String)
    }

    public struct PerSCTResult: Sendable {
        public let sct: SCT
        public let log: Log?
        public let isValid: Bool
        public let failure: SCTFailure?
    }

    public struct SCTReport: Sendable {
        public let passed: Bool
        public let policy: Policy
        public let results: [PerSCTResult]
        public var validCount: Int { get }
        public var distinctValidLogCount: Int { get }
        public var failures: [PerSCTResult] { get }
    }

    public struct VerificationContext: Sendable {
        public let logList: LogList
        public let policy: Policy
        public let verificationTime: Date
        public let allowedClockSkew: TimeInterval  // Default: 300s (5 min)
        public init(logList: LogList = .bundled, policy: Policy = .default,
                    verificationTime: Date = Date(), allowedClockSkew: TimeInterval = 300)
        public static let `default` = VerificationContext()
    }
}

extension CT {
    // Fast path
    public static func isValidSCTs(
        _ scts: [SCT], for certificate: X509.Certificate,
        issuer: X509.Certificate? = nil, context: VerificationContext = .default
    ) -> Bool

    // Detailed path
    public static func verifySCTs(
        _ scts: [SCT], for certificate: X509.Certificate,
        issuer: X509.Certificate? = nil, context: VerificationContext = .default
    ) -> SCTReport
}
```

**OpenSSL function mapping:**

| Swift API | OpenSSL Functions |
|-----------|-------------------|
| `SCT(tlsBytes:)` | `o2i_SCT` |
| `SCT.list(fromTLSBytes:)` | `o2i_SCT_LIST` |
| `SCT.embedded(in:)` | `X509_get_ext_d2i(NID_ct_precert_scts)`, `d2i_SCT_LIST` |
| `Log(publicKeyBase64:)` | `CTLOG_new_from_base64` |
| `LogList(googleJSON:)` | `CTLOG_STORE_new`, JSON parsing + `CTLOG_new_from_base64` |
| `isValidSCTs` / `verifySCTs` | `CT_POLICY_EVAL_CTX_new`, `CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE`, `CT_POLICY_EVAL_CTX_set1_cert`, `CT_POLICY_EVAL_CTX_set1_issuer`, `CT_POLICY_EVAL_CTX_set_time`, `SCT_LIST_validate` |

**Implementation notes:**
- Bundled log list includes major public CT logs (Google, Cloudflare, DigiCert, Sectigo, Let's Encrypt)
- Embedded SCTs sign the "precertificate" (with poison extension); TLS/OCSP SCTs sign the final certificate — OpenSSL's `CT_POLICY_EVAL_CTX` handles this when issuer cert is provided
- SCT timestamp must be ≤ verification time + allowed clock skew

**Usage examples:**

```swift
import OpenSSL

let cert = try X509.Certificate(pemRepresentation: leafCertPEM)
let issuer = try X509.Certificate(pemRepresentation: issuerCertPEM)
let embeddedSCTs = CT.SCT.embedded(in: cert)

// Quick check
let isValid = CT.isValidSCTs(embeddedSCTs, for: cert, issuer: issuer)

// Detailed report
let report = CT.verifySCTs(embeddedSCTs, for: cert, issuer: issuer)
print("Valid SCTs: \(report.validCount) from \(report.distinctValidLogCount) distinct logs")

// Custom policy
let context = CT.VerificationContext(policy: .requireDistinctLogs(2))
let report = CT.verifySCTs(embeddedSCTs, for: cert, issuer: issuer, context: context)
```

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

```swift
public enum AES {
    public enum GCM {}
}
public enum ChaChaPoly {}

// Nonce (shared pattern for both ciphers — 12 bytes)
extension AES.GCM {
    public struct Nonce: ContiguousBytes, Sendable {
        public static let byteCount = 12
        public init()                                      // Random
        public init<D: DataProtocol>(data: D) throws       // From bytes
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R
    }
}
extension ChaChaPoly {
    public struct Nonce: ContiguousBytes, Sendable {
        public static let byteCount = 12
        public init()
        public init<D: DataProtocol>(data: D) throws
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R
    }
}

// SealedBox (shared pattern for both ciphers)
extension AES.GCM {
    public struct SealedBox: Sendable {
        public let nonce: Nonce
        public let ciphertext: Data
        public let tag: Data
        public var combined: Data { get }  // nonce || ciphertext || tag
        public init<C: DataProtocol, T: DataProtocol>(nonce: Nonce, ciphertext: C, tag: T) throws
        public init<D: DataProtocol>(combined: D) throws
    }
}
extension ChaChaPoly {
    public struct SealedBox: Sendable {
        public let nonce: Nonce
        public let ciphertext: Data
        public let tag: Data
        public var combined: Data { get }
        public init<C: DataProtocol, T: DataProtocol>(nonce: Nonce, ciphertext: C, tag: T) throws
        public init<D: DataProtocol>(combined: D) throws
    }
}

// Encryption / Decryption API
extension AES.GCM {
    public static func seal<P: DataProtocol, AAD: DataProtocol>(
        _ message: P, using key: SymmetricKey, nonce: Nonce? = nil, authenticating aad: AAD
    ) throws -> SealedBox
    public static func seal<P: DataProtocol>(
        _ message: P, using key: SymmetricKey, nonce: Nonce? = nil
    ) throws -> SealedBox
    public static func open<AAD: DataProtocol>(
        _ sealedBox: SealedBox, using key: SymmetricKey, authenticating aad: AAD
    ) throws -> Data
    public static func open(_ sealedBox: SealedBox, using key: SymmetricKey) throws -> Data

    // Verification-only (no decryption)
    public static func isAuthentic<AAD: DataProtocol>(
        _ sealedBox: SealedBox, using key: SymmetricKey, authenticating aad: AAD
    ) -> Bool
}
// ChaChaPoly has identical API shape
```

**OpenSSL function mapping:**

| Swift API | OpenSSL Functions |
|-----------|-------------------|
| `AES.GCM.seal` | `EVP_EncryptInit_ex(EVP_aes_256_gcm())`, `EVP_EncryptUpdate` (AAD), `EVP_EncryptUpdate` (plaintext), `EVP_EncryptFinal_ex`, `EVP_CIPHER_CTX_ctrl(EVP_CTRL_GCM_GET_TAG)` |
| `AES.GCM.open` | `EVP_DecryptInit_ex`, `EVP_DecryptUpdate` (AAD + ciphertext), `EVP_CIPHER_CTX_ctrl(EVP_CTRL_GCM_SET_TAG)`, `EVP_DecryptFinal_ex` |
| `ChaChaPoly.seal` | `EVP_EncryptInit_ex(EVP_chacha20_poly1305())`, ... |
| `ChaChaPoly.open` | `EVP_DecryptInit_ex(EVP_chacha20_poly1305())`, ... |

**Implementation notes:**
- **CRITICAL**: Never reuse a nonce with the same key — nonce reuse completely breaks GCM security
- If nonce is nil, generate cryptographically random 12 bytes
- AES key size auto-selects cipher: 128 → `EVP_aes_128_gcm()`, 192 → `EVP_aes_192_gcm()`, 256 → `EVP_aes_256_gcm()`
- Tag size: 16 bytes (128 bits) for both AES-GCM and ChaCha20-Poly1305
- All methods are static; `EVP_CIPHER_CTX` created per-call — fully `Sendable`

**Usage examples:**

```swift
import OpenSSL

let key = SymmetricKey(size: .bits256)

// Encrypt
let sealedBox = try AES.GCM.seal(plaintext, using: key)

// Decrypt
let decrypted = try AES.GCM.open(sealedBox, using: key)

// With AAD (e.g., TLS record header)
let header = Data([0x17, 0x03, 0x03, 0x00, 0x20])
let sealedBox = try AES.GCM.seal(payload, using: key, nonce: nonce, authenticating: header)

// Verify without decrypting (TLS record verification)
let isValid = AES.GCM.isAuthentic(sealedBox, using: trafficKey, authenticating: recordHeader)

// ChaCha20-Poly1305 (same API)
let sealedBox = try ChaChaPoly.seal(plaintext, using: key, authenticating: aad)
```

## Dependencies & Sequencing

```
Phase 2 (X.509 basic) ──→ RSA-PSS ──┐
                         ──→ CT ─────┤──→ Phase 4
Phase 2 (SymmetricKey) ──→ AEAD ────┘
```

- RSA-PSS and CT can be developed in parallel once Phase 2 X.509 is available
- AEAD depends only on SymmetricKey from Phase 2 — can start as soon as Phase 2 keys ship
- All three are independent of each other

## File Structure

```
Sources/OpenSSL/
├── RSA/
│   ├── RSA.swift              # RSA namespace (existing)
│   ├── RSA+PSS.swift          # PSS types and verification
│   └── RSA+Key.swift          # Key types (shared)
├── CT/
│   ├── CT.swift               # CT namespace
│   ├── CT+SCT.swift           # SCT type and parsing
│   ├── CT+Log.swift           # Log and LogList types
│   ├── CT+Policy.swift        # Policy and SCTReport
│   └── CT+Verification.swift  # Verification functions
├── AEAD/
│   ├── AES-GCM.swift          # AES.GCM namespace and API
│   ├── ChaChaPoly.swift       # ChaChaPoly namespace and API
│   └── SealedBox.swift        # Shared sealed box concept
```

## Phase Metrics

- 3 API families shipped
- All types conform to `Sendable`
- Unit tests with Wycheproof vectors for each algorithm
- `isValid*()` fast paths return `Bool` without throwing
- `swift build` and `swift test` pass on macOS + Linux

## Test Vector Strategy

| Algorithm | Primary Source | Additional Sources |
|-----------|---------------|-------------------|
| **RSA-PSS** | Wycheproof `rsa_pss_*.json` | NIST CAVP RSA |
| **AES-GCM** | Wycheproof `aes_gcm_test.json` | NIST CAVP GCM |
| **ChaCha20-Poly1305** | RFC 8439 Appendix A | Wycheproof `chacha20_poly1305_test.json` |
| **CT** | CT Test Logs (certificate.transparency.dev) | RFC 6962 test cases |

```
Tests/OpenSSLTests/
├── Resources/wycheproof/
│   ├── rsa_pss_*.json
│   ├── aes_gcm_test.json
│   └── chacha20_poly1305_test.json
├── RSAPSSTests.swift
├── AESGCMTests.swift
├── ChaChaPolyTests.swift
└── CTTests.swift
```
