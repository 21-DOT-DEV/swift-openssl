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
- **Note**: Consider bundling Mozilla root store for cross-platform consistency

```swift
extension X509 {
    public struct TrustStore: Sendable {
        public init()
        public init(certificates: [Certificate])
        public static func system() throws -> TrustStore
        public static func loadPEM(from url: URL) throws -> TrustStore
        public static func loadDirectory(from url: URL) throws -> TrustStore
        public func adding(_ certificate: Certificate) -> TrustStore
        public func adding(contentsOf certificates: [Certificate]) -> TrustStore
        public func merging(_ other: TrustStore) -> TrustStore
        public var certificates: [Certificate] { get }
    }
}
```

### Verification Policy

- **Purpose**: Policy-driven certificate verification supporting TLS, code signing, email, and custom use cases
- **Success Metrics**:
  - `VerificationPolicy` enum: `.tls(hostname:)`, `.tlsClient`, `.codeSigning`, `.email(address:)`, `.any`, `.custom(CustomPolicy)`
  - `CustomPolicy` struct with: `requiredExtendedKeyUsages`, `requiredKeyUsages`, `hostname`, `email`, `maxDepth`, `checkRevocation`, `verificationTime`
  - `ExtendedKeyUsage` and `KeyUsage` types
  - Hostname verification for TLS via `X509_VERIFY_PARAM_set1_host`
- **Dependencies**: Trust Store Management

```swift
extension X509 {
    public enum VerificationPolicy: Sendable {
        case tls(hostname: String?)
        case tlsClient
        case codeSigning
        case email(address: String?)
        case any
        case custom(CustomPolicy)
    }

    public struct CustomPolicy: Sendable {
        public var requiredExtendedKeyUsages: [ExtendedKeyUsage]
        public var requiredKeyUsages: [KeyUsage]
        public var hostname: String?
        public var email: String?
        public var maxDepth: Int           // 0 = unlimited
        public var checkRevocation: Bool
        public var verificationTime: Date? // nil = current time
        public init()
    }

    public enum ExtendedKeyUsage: Sendable {
        case serverAuth, clientAuth, codeSigning, emailProtection
        case timeStamping, ocspSigning, anyExtendedKeyUsage
        case custom(String)  // OID string
    }

    public struct KeyUsage: OptionSet, Sendable {
        public static let digitalSignature = KeyUsage(rawValue: 1 << 0)
        public static let nonRepudiation   = KeyUsage(rawValue: 1 << 1)
        public static let keyEncipherment  = KeyUsage(rawValue: 1 << 2)
        public static let dataEncipherment = KeyUsage(rawValue: 1 << 3)
        public static let keyAgreement     = KeyUsage(rawValue: 1 << 4)
        public static let keyCertSign      = KeyUsage(rawValue: 1 << 5)
        public static let crlSign          = KeyUsage(rawValue: 1 << 6)
        public static let encipherOnly     = KeyUsage(rawValue: 1 << 7)
        public static let decipherOnly     = KeyUsage(rawValue: 1 << 8)
        public let rawValue: Int
        public init(rawValue: Int)
    }
}
```

### Chain Verification API

- **Purpose**: Build and verify certificate chains from leaf to root with detailed failure reporting
- **Success Metrics**:
  - Fast path: `X509.isValid(_:intermediates:using:policy:)` → `Bool`
  - Detailed path: `X509.verify(...)` → `VerificationResult` with chain, failures, policy
  - `X509.buildChain(for:intermediates:using:)` → `[Certificate]?`
  - `ChainFailure` enum covering: `untrustedRoot`, `expired`, `notYetValid`, `invalidSignature`, `hostnameMismatch`, `revoked`, `selfSignedCertificate`, `incompletePath`, `chainTooLong`, and more
  - OpenSSL `X509_V_ERR_*` codes mapped to Swift failure cases
- **Dependencies**: Trust Store Management, Verification Policy, Phase 3 (RSA-PSS for signature verification within chains)

```swift
extension X509 {
    public enum ChainFailure: Sendable, Equatable {
        case untrustedRoot
        case expired(Certificate)
        case notYetValid(Certificate)
        case invalidSignature(Certificate)
        case missingExtendedKeyUsage(Certificate, ExtendedKeyUsage)
        case missingKeyUsage(Certificate, KeyUsage)
        case hostnameMismatch(expected: String, certificate: Certificate)
        case emailMismatch(expected: String, certificate: Certificate)
        case chainTooLong(depth: Int, maximum: Int)
        case revoked(Certificate)
        case selfSignedCertificate(Certificate)
        case incompletePath
        case nameConstraintViolation(Certificate)
        case basicConstraintViolation(Certificate)
        case internalError(String)
    }

    public struct VerificationResult: Sendable {
        public let isValid: Bool
        public let chain: [Certificate]        // Leaf to root (populated on success)
        public let failures: [ChainFailure]
        public let policy: VerificationPolicy
        public var chainDepth: Int { get }
        public var summary: String { get }
    }
}

extension X509 {
    // Fast path
    public static func isValid(
        _ certificate: Certificate, intermediates: [Certificate] = [],
        using trustStore: TrustStore, policy: VerificationPolicy = .any
    ) -> Bool

    // Detailed path
    public static func verify(
        _ certificate: Certificate, intermediates: [Certificate] = [],
        using trustStore: TrustStore, policy: VerificationPolicy = .any
    ) -> VerificationResult

    // Chain building
    public static func buildChain(
        for certificate: Certificate, intermediates: [Certificate] = [],
        using trustStore: TrustStore
    ) -> [Certificate]?
}
```

**OpenSSL function mapping:**

| Swift API | OpenSSL Functions |
|-----------|-------------------|
| `TrustStore.system()` | `X509_STORE_new`, `X509_STORE_set_default_paths` |
| `TrustStore.loadPEM(from:)` | `X509_STORE_new`, `X509_STORE_load_file` |
| `TrustStore.loadDirectory(from:)` | `X509_STORE_new`, `X509_STORE_load_path` |
| `TrustStore.adding(_:)` | `X509_STORE_add_cert` |
| `isValid(...)` | `X509_STORE_CTX_new`, `X509_STORE_CTX_init`, `X509_verify_cert` |
| `verify(...)` | Same + `X509_STORE_CTX_get_error`, `X509_STORE_CTX_get_chain` |
| `.tls(hostname:)` | `X509_VERIFY_PARAM_set1_host`, `X509_VERIFY_PARAM_set_purpose(X509_PURPOSE_SSL_SERVER)` |
| `CustomPolicy.verificationTime` | `X509_VERIFY_PARAM_set_time` |
| `CustomPolicy.maxDepth` | `X509_VERIFY_PARAM_set_depth` |
| `CustomPolicy.checkRevocation` | `X509_VERIFY_PARAM_set_flags(X509_V_FLAG_CRL_CHECK)` |

**OpenSSL error code mapping:**

| OpenSSL Error | ChainFailure |
|---------------|--------------|
| `X509_V_ERR_CERT_NOT_YET_VALID` | `.notYetValid(cert)` |
| `X509_V_ERR_CERT_HAS_EXPIRED` | `.expired(cert)` |
| `X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT` | `.untrustedRoot` |
| `X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT` | `.selfSignedCertificate(cert)` |
| `X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN` | `.selfSignedCertificate(cert)` |
| `X509_V_ERR_CERT_CHAIN_TOO_LONG` | `.chainTooLong(...)` |
| `X509_V_ERR_CERT_REVOKED` | `.revoked(cert)` |
| `X509_V_ERR_HOSTNAME_MISMATCH` | `.hostnameMismatch(...)` |

**Implementation notes:**
- `TrustStore` is immutable and `Sendable`
- Verification creates a new `X509_STORE_CTX` per call (thread-safe)
- Underlying `X509_STORE*` is reference-counted with thread-safe access
- System trust store locations: macOS → Keychain; Linux → `/etc/ssl/certs`, `/etc/pki/tls/certs`, or `$SSL_CERT_DIR`

**Usage examples:**

```swift
import OpenSSL

// Basic TLS verification
let leafCert = try X509.Certificate(pemRepresentation: leafPEM)
let intermediate = try X509.Certificate(pemRepresentation: intermediatePEM)
let trustStore = try X509.TrustStore.system()

let isValid = X509.isValid(
    leafCert, intermediates: [intermediate],
    using: trustStore, policy: .tls(hostname: "example.com")
)

// Detailed verification
let result = X509.verify(
    leafCert, intermediates: [intermediate],
    using: trustStore, policy: .tls(hostname: "example.com")
)
if result.isValid {
    print("Chain depth: \(result.chainDepth)")
} else {
    for failure in result.failures {
        switch failure {
        case .expired(let cert): print("Expired: \(cert.subjectCommonName ?? "?")")
        case .hostnameMismatch(let expected, _): print("Hostname mismatch: \(expected)")
        case .untrustedRoot: print("Untrusted root")
        default: print("\(failure)")
        }
    }
}

// Custom trust store
let customCA = try X509.Certificate(pemRepresentation: customCAPEM)
let customStore = X509.TrustStore(certificates: [customCA])
let combined = try X509.TrustStore.system().merging(customStore)

// Custom policy
var policy = X509.CustomPolicy()
policy.requiredExtendedKeyUsages = [.codeSigning]
policy.requiredKeyUsages = [.digitalSignature]
policy.maxDepth = 3
let result = X509.verify(cert, using: trustStore, policy: .custom(policy))
```

## Dependencies & Sequencing

```
Phase 2 (X.509 basic) ──→ Trust Store ──→ Verification Policy ──→ Chain Verification
Phase 3 (RSA-PSS) ──────────────────────────────────────────────→ Chain Verification
```

- Trust Store can begin as soon as Phase 2 X.509 Certificate type is available
- Chain Verification requires both the policy framework and RSA-PSS from Phase 3

## File Structure

```
Sources/OpenSSL/
├── X509/
│   ├── X509.swift                     # X509 namespace (existing from Phase 2)
│   ├── X509+Certificate.swift         # Certificate type (existing from Phase 2)
│   ├── X509+TrustStore.swift          # TrustStore type
│   ├── X509+VerificationPolicy.swift  # Policy enum and CustomPolicy
│   ├── X509+VerificationResult.swift  # Result and ChainFailure
│   └── X509+Verification.swift        # isValid/verify/buildChain functions
```

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
