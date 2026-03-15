# Phase 2: Foundation Crypto

> **Status:** ⏳ Planned  
> **Last Updated:** 2026-03-14

## Goal

Build the shared type system and foundational cryptographic primitives that all subsequent API phases depend on. Establish error handling, memory management patterns, and the first two algorithm families (HMAC, HKDF).

## Design Principles

1. **swift-crypto style** — High-level, type-safe APIs hiding OpenSSL internals
2. **Bool for validity** — `isValid*()` returns `Bool`; throws only for programmer errors
3. **Cross-platform** — Works on Apple platforms and Linux via OpenSSL backend
4. **Sendable everywhere** — All public types conform to `Sendable` for concurrency safety

## Features

### Shared Error Type (`OpenSSLError`)

- **Purpose**: Unified error enum for all OpenSSL operations, matching swift-crypto's pattern of throwing only for programmer errors
- **Success Metrics**:
  - `OpenSSLError` enum with cases: `invalidKey`, `invalidSignature`, `invalidCertificate`, `invalidInput`, `unsupportedOperation`, `underlyingError`, `authenticationFailure`
  - Conforms to `Error`, `Equatable`, `Sendable`, `LocalizedError`
  - Used consistently by all subsequent API families
- **Dependencies**: Phase 1 (Core Extraction)

```swift
public enum OpenSSLError: Error, Equatable, Sendable {
    case invalidKey(String)
    case invalidSignature(String)
    case invalidCertificate(String)
    case invalidInput(String)
    case unsupportedOperation(String)
    case underlyingError(String)
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

### OpenSSL Pointer Wrappers

- **Purpose**: Safe memory management for OpenSSL C pointer types (`EVP_PKEY*`, `X509*`, etc.) via reference-counted Swift wrappers with `deinit`
- **Success Metrics**:
  - `@unchecked Sendable` wrapper classes with `deinit` calling appropriate `*_free`
  - Zero memory leaks under repeated create/destroy cycles
  - BIO helper utilities for PEM/DER encoding
- **Dependencies**: Phase 1 (Core Extraction)

```swift
// Example: X509 pointer wrapper
internal final class X509Pointer: @unchecked Sendable {
    let pointer: OpaquePointer  // X509*
    init(pointer: OpaquePointer) { self.pointer = pointer }
    deinit { X509_free(pointer) }
}
```

### HashFunction Protocol & Digest Types

- **Purpose**: Generic hash function protocol enabling `HMAC<H>` and `HKDF<H>` to be parameterized by algorithm
- **Success Metrics**:
  - `HashFunction` protocol with `Digest` associated type, `digestByteCount`, `blockByteCount`, `update`, `finalize`
  - `SHA256`, `SHA384`, `SHA512` conforming types
  - `SHA384Digest` and `SHA512Digest` types (`SHA256Digest` already exists)
  - All types conform to `Sendable`
- **Dependencies**: Shared Error Type

```swift
public protocol HashFunction: Sendable {
    associatedtype Digest: Sendable
    static var digestByteCount: Int { get }
    static var blockByteCount: Int { get }
    init()
    mutating func update<D: DataProtocol>(data: D)
    func finalize() -> Digest
}

// SHA256 already exists (Phase 1) — extend to conform to HashFunction
// digestByteCount = 32, blockByteCount = 64

public struct SHA384: HashFunction {
    public typealias Digest = SHA384Digest
    public static let digestByteCount = 48
    public static let blockByteCount = 128
    // ...
}

public struct SHA512: HashFunction {
    public typealias Digest = SHA512Digest
    public static let digestByteCount = 64
    public static let blockByteCount = 128
    // ...
}
```

### SymmetricKey & SymmetricKeySize

- **Purpose**: Type-safe symmetric key representation for HMAC, HKDF, and AEAD operations
- **Success Metrics**:
  - `SymmetricKey` with `init(data:)`, `init(size:)`, `withUnsafeBytes`
  - `SymmetricKeySize` enum: `.bits128`, `.bits192`, `.bits256`, `.bits(Int)`
  - Conforms to `Sendable`
  - Random key generation uses OpenSSL's CSPRNG
- **Dependencies**: Phase 1 (Core Extraction)

```swift
public struct SymmetricKey: Sendable {
    public var bitCount: Int { get }
    public init<D: DataProtocol>(data: D)
    public init(size: SymmetricKeySize)
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R
}

public enum SymmetricKeySize: Sendable {
    case bits128
    case bits192
    case bits256
    case bits(Int)
    public var bitCount: Int { get }
}
```

### HMAC

- **Purpose**: Hash-based Message Authentication Codes for message authentication and integrity verification, matching swift-crypto's `HMAC<H>` API
- **Success Metrics**:
  - `HMAC<H>` with incremental (`init/update/finalize`) and one-shot (`authenticationCode(for:using:)`) APIs
  - `HashedAuthenticationCode<H>` result type with `rawRepresentation` and constant-time `==`
  - `isValidAuthenticationCode` verification method
  - Works with SHA-256, SHA-384, SHA-512
  - Constant-time comparison via `CRYPTO_memcmp`
- **Dependencies**: HashFunction Protocol, SymmetricKey

```swift
public struct HashedAuthenticationCode<H: HashFunction>: Sendable, ContiguousBytes {
    public var rawRepresentation: Data { get }
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R
}

extension HashedAuthenticationCode: Equatable {
    /// Constant-time comparison via CRYPTO_memcmp.
    public static func == (lhs: Self, rhs: Self) -> Bool
}

public struct HMAC<H: HashFunction>: Sendable {
    public init(key: SymmetricKey)
    public mutating func update<D: DataProtocol>(data: D)
    public func finalize() -> HashedAuthenticationCode<H>

    // One-shot API
    public static func authenticationCode<D: DataProtocol>(
        for data: D, using key: SymmetricKey
    ) -> HashedAuthenticationCode<H>

    public static func isValidAuthenticationCode<D: DataProtocol>(
        _ authenticationCode: HashedAuthenticationCode<H>,
        authenticating data: D, using key: SymmetricKey
    ) -> Bool

    public static func isValidAuthenticationCode<C: ContiguousBytes, D: DataProtocol>(
        _ authenticationCode: C,
        authenticating data: D, using key: SymmetricKey
    ) -> Bool
}
```

**OpenSSL function mapping:**

| Swift API | OpenSSL Functions |
|-----------|-------------------|
| `HMAC.init(key:)` | `EVP_MAC_CTX_new`, `EVP_MAC_fetch("HMAC")`, `EVP_MAC_init` |
| `HMAC.update(data:)` | `EVP_MAC_update` |
| `HMAC.finalize()` | `EVP_MAC_final` |
| `authenticationCode(for:using:)` | `EVP_MAC_init` + `EVP_MAC_update` + `EVP_MAC_final` (one-shot) |
| `isValidAuthenticationCode` | Compute + `CRYPTO_memcmp` |

**Implementation notes:**
- `isValidAuthenticationCode` **must** use constant-time comparison to prevent timing attacks
- Keys shorter than block size are used directly; longer keys are hashed first (per RFC 2104) — OpenSSL handles this via `EVP_MAC`
- Each `HMAC<H>` instance has its own `EVP_MAC_CTX` (no shared state)

**Usage examples:**

```swift
import OpenSSL

let key = SymmetricKey(size: .bits256)

// One-shot HMAC-SHA256
let mac = HMAC<SHA256>.authenticationCode(for: messageData, using: key)

// Verify
let isValid = HMAC<SHA256>.isValidAuthenticationCode(
    receivedMAC, authenticating: messageData, using: key
)

// Incremental
var hmac = HMAC<SHA256>(key: key)
hmac.update(data: chunk1)
hmac.update(data: chunk2)
let mac = hmac.finalize()
```

### HKDF

- **Purpose**: HMAC-based Key Derivation Function (RFC 5869) for deriving cryptographic keys from input key material
- **Success Metrics**:
  - One-shot `deriveKey(inputKeyMaterial:salt:info:outputByteCount:)` API
  - Fine-grained `extract` + `expand` API for multi-key derivation
  - Output length validation (max 255 × H.digestByteCount)
  - Works with SHA-256, SHA-384, SHA-512
- **Dependencies**: HMAC (uses `HashedAuthenticationCode<H>` for PRK type)

```swift
public struct HKDF<H: HashFunction>: Sendable {
    // One-shot key derivation
    public static func deriveKey<Salt: DataProtocol, Info: DataProtocol>(
        inputKeyMaterial: SymmetricKey, salt: Salt, info: Info, outputByteCount: Int
    ) -> SymmetricKey

    // Overloads: no salt, no info, or neither
    public static func deriveKey<Info: DataProtocol>(
        inputKeyMaterial: SymmetricKey, info: Info, outputByteCount: Int
    ) -> SymmetricKey
    public static func deriveKey<Salt: DataProtocol>(
        inputKeyMaterial: SymmetricKey, salt: Salt, outputByteCount: Int
    ) -> SymmetricKey
    public static func deriveKey(
        inputKeyMaterial: SymmetricKey, outputByteCount: Int
    ) -> SymmetricKey

    // Extract-then-expand (fine-grained control)
    public static func extract<Salt: DataProtocol>(
        inputKeyMaterial: SymmetricKey, salt: Salt?
    ) -> HashedAuthenticationCode<H>

    public static func expand<PRK: ContiguousBytes, Info: DataProtocol>(
        pseudoRandomKey prk: PRK, info: Info?, outputByteCount: Int
    ) -> SymmetricKey
}
```

**OpenSSL function mapping:**

| Swift API | OpenSSL Functions |
|-----------|-------------------|
| `deriveKey(...)` | `EVP_KDF_fetch("HKDF")`, `EVP_KDF_CTX_new`, `EVP_KDF_derive` with `EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND` |
| `extract(...)` | `EVP_KDF_derive` with `EVP_KDF_HKDF_MODE_EXTRACT_ONLY` |
| `expand(...)` | `EVP_KDF_derive` with `EVP_KDF_HKDF_MODE_EXPAND_ONLY` |

**Implementation notes:**
- Max output length: `255 * H.digestByteCount` bytes (SHA-256: 8,160 bytes max)
- If salt is `nil` or empty, use `H.digestByteCount` zero bytes (per RFC 5869)
- `extract()` returns `HashedAuthenticationCode<H>` — conforms to `ContiguousBytes`, can pass directly to `expand()`
- All methods are static and stateless; `EVP_KDF_CTX` created per-call

**Usage examples:**

```swift
import OpenSSL

// One-shot key derivation
let derivedKey = HKDF<SHA256>.deriveKey(
    inputKeyMaterial: password, salt: salt, info: info, outputByteCount: 32
)

// Multi-key derivation from same source
let prk = HKDF<SHA256>.extract(inputKeyMaterial: sharedSecret, salt: salt)
let encKey = HKDF<SHA256>.expand(pseudoRandomKey: prk, info: Data("encryption".utf8), outputByteCount: 32)
let authKey = HKDF<SHA256>.expand(pseudoRandomKey: prk, info: Data("authentication".utf8), outputByteCount: 32)
```

### X.509 Certificate (Basic)

- **Purpose**: Minimal X.509 certificate wrapper sufficient for key extraction and SCT parsing in later phases
- **Success Metrics**:
  - Parse from PEM and DER
  - Properties: `notBefore`, `notAfter`, `subjectCommonName`, `issuerCommonName`, `serialNumber`, `isCurrentlyValid`, `validityPeriodDays`
  - Public key extraction: `publicKeyType`, `rsaPSSPublicKey`, `subjectPublicKeyInfo`
  - DER/PEM round-trip encoding
  - `Sendable` conformance via pointer wrapper
- **Dependencies**: OpenSSL Pointer Wrappers, Shared Error Type
- **Note**: Intentionally minimal — chain validation is Phase 4

```swift
public enum X509 {}

extension X509 {
    public struct Certificate: Sendable {
        public init(pemRepresentation: String) throws
        public init<D: DataProtocol>(derRepresentation: D) throws

        public var notBefore: Date { get }
        public var notAfter: Date { get }
        public var subjectCommonName: String? { get }
        public var issuerCommonName: String? { get }
        public var serialNumber: String { get }
        public var derRepresentation: Data { get }
        public var pemRepresentation: String { get }
        public var isCurrentlyValid: Bool { get }
        public var validityPeriodDays: Int { get }
    }
}

extension X509.Certificate {
    public enum PublicKeyType: Sendable {
        case rsa, rsaPSS, ecdsa, ed25519, unknown
    }
    public var publicKeyType: PublicKeyType { get }
    public var rsaPSSPublicKey: RSA.PSS.PublicKey? { get }
    public var subjectPublicKeyInfo: Data { get }
}
```

**OpenSSL function mapping:**

| Swift API | OpenSSL Functions |
|-----------|-------------------|
| `Certificate(pemRepresentation:)` | `BIO_new_mem_buf`, `PEM_read_bio_X509` |
| `Certificate(derRepresentation:)` | `d2i_X509` |
| `notBefore` / `notAfter` | `X509_get_notBefore`, `X509_get_notAfter`, `ASN1_TIME_to_tm` |
| `subjectCommonName` | `X509_get_subject_name`, `X509_NAME_get_text_by_NID(NID_commonName)` |
| `serialNumber` | `X509_get_serialNumber`, `ASN1_INTEGER_to_BN`, `BN_bn2hex` |
| `derRepresentation` | `i2d_X509` |
| `publicKeyType` | `X509_get_pubkey`, `EVP_PKEY_get_base_id` |
| `rsaPSSPublicKey` | `X509_get_pubkey` (returns EVP_PKEY*) |

**Implementation notes:**
- Certificate struct holds reference-counted `X509Pointer` wrapper
- Date conversion: `ASN1_TIME` → `struct tm` via `ASN1_TIME_to_tm` → `timegm` → Swift `Date`
- Future extensions: SANs, key usage, chain building (Phase 4)

## Dependencies & Sequencing

```
Shared Error Type ──┬──→ HashFunction Protocol ──→ HMAC ──→ HKDF
                    │
Pointer Wrappers ───┴──→ X.509 Certificate (Basic)
                    │
 SymmetricKey ───────┴──→ HMAC
```

## File Structure

```
Sources/OpenSSL/
├── Error.swift                # OpenSSLError (refactored from OpenSSL.swift)
├── Digests/
│   ├── HashFunction.swift     # HashFunction protocol
│   ├── SHA256.swift           # SHA256 (existing, extend to conform)
│   ├── SHA384.swift           # SHA384 (new)
│   └── SHA512.swift           # SHA512 (new)
├── Keys/
│   ├── SymmetricKey.swift     # SymmetricKey type
│   └── SymmetricKeySize.swift # SymmetricKeySize enum
├── HMAC/
│   ├── HMAC.swift             # HMAC<H> type and static methods
│   └── HashedAuthenticationCode.swift  # Result type
├── KDF/
│   └── HKDF.swift             # HKDF<H> key derivation
├── X509/
│   ├── X509.swift             # X509 namespace
│   └── X509+Certificate.swift # Certificate type
└── Internal/
    ├── OpenSSLPointer.swift   # Reference-counted wrappers
    └── BIO+Helpers.swift      # BIO utility functions
```

## Phase Metrics

- 7 features shipped
- All types conform to `Sendable`
- Unit tests for each feature
- `swift build` and `swift test` pass on macOS + Linux

## Test Vector Strategy

| Algorithm | Primary Source | Additional Sources |
|-----------|---------------|-------------------|
| **HMAC** | Wycheproof `hmac_sha*.json` | RFC 4231 |
| **HKDF** | RFC 5869 Appendix A (7 test cases) | Wycheproof `hkdf_sha*.json` |
| **X.509** | Manual PEM/DER round-trip tests | Wycheproof deferred to Phase 4 |

```
Tests/OpenSSLTests/
├── Resources/wycheproof/
│   ├── hmac_sha256_test.json
│   ├── hmac_sha384_test.json
│   ├── hmac_sha512_test.json
│   └── hkdf_sha256_test.json
├── HMACTests.swift
├── HKDFTests.swift
└── WycheproofTestHelper.swift
```
