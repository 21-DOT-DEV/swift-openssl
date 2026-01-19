# X.509 Chain Verification Specification

> **Parent:** [overview.md](overview.md)  
> **Status:** Draft  
> **Priority:** 4 (Certificate Validation)

## Overview

X.509 certificate chain building and verification using OpenSSL's `X509_STORE` and `X509_verify_cert`. Provides trust store management and policy-based verification for TLS and other use cases.

---

## Namespace

Extends the existing `OpenSSL.X509` namespace from [x509.md](x509.md).

```swift
extension OpenSSL.X509 {
    /// Trust store for certificate verification.
    public struct TrustStore {}
    
    /// Verification policy configuration.
    public enum VerificationPolicy {}
    
    /// Result of certificate chain verification.
    public struct VerificationResult {}
    
    /// Reasons a certificate chain may fail verification.
    public enum ChainFailure {}
}
```

---

## Types

### Trust Store

```swift
extension OpenSSL.X509 {
    /// A store of trusted certificates for chain verification.
    public struct TrustStore: Sendable {
        /// Creates an empty trust store.
        public init()
        
        /// Creates a trust store from an array of trusted certificates.
        /// - Parameter certificates: The trusted root/intermediate certificates.
        public init(certificates: [Certificate])
        
        /// Loads the system's default trust store.
        /// - Returns: A trust store containing system root certificates.
        /// - Note: On macOS/iOS, loads from Keychain. On Linux, loads from /etc/ssl/certs.
        public static func system() throws -> TrustStore
        
        /// Loads certificates from a PEM file containing multiple certificates.
        /// - Parameter url: Path to the PEM file.
        /// - Returns: A trust store containing the certificates.
        public static func loadPEM(from url: URL) throws -> TrustStore
        
        /// Loads certificates from a directory of PEM files.
        /// - Parameter url: Path to the directory.
        /// - Returns: A trust store containing all certificates found.
        public static func loadDirectory(from url: URL) throws -> TrustStore
        
        /// Adds a certificate to the trust store.
        /// - Parameter certificate: The certificate to add.
        /// - Returns: A new trust store containing the additional certificate.
        public func adding(_ certificate: Certificate) -> TrustStore
        
        /// Adds multiple certificates to the trust store.
        /// - Parameter certificates: The certificates to add.
        /// - Returns: A new trust store containing the additional certificates.
        public func adding(contentsOf certificates: [Certificate]) -> TrustStore
        
        /// Merges another trust store into this one.
        /// - Parameter other: The trust store to merge.
        /// - Returns: A combined trust store.
        public func merging(_ other: TrustStore) -> TrustStore
        
        /// The certificates in this trust store.
        public var certificates: [Certificate] { get }
    }
}
```

### Verification Policy

```swift
extension OpenSSL.X509 {
    /// Policy for certificate chain verification.
    public enum VerificationPolicy: Sendable {
        /// TLS server authentication policy.
        /// - Requires Extended Key Usage: serverAuth (or anyExtendedKeyUsage)
        /// - Validates hostname if provided
        /// - Checks certificate validity dates
        case tls(hostname: String?)
        
        /// TLS client authentication policy.
        /// - Requires Extended Key Usage: clientAuth
        case tlsClient
        
        /// Code signing policy.
        /// - Requires Extended Key Usage: codeSigning
        case codeSigning
        
        /// Email protection (S/MIME) policy.
        /// - Requires Extended Key Usage: emailProtection
        case email(address: String?)
        
        /// Basic chain validation only.
        /// - Validates signatures and dates
        /// - No EKU or hostname requirements
        case any
        
        /// Custom policy with specific requirements.
        case custom(CustomPolicy)
    }
    
    /// Custom verification policy options.
    public struct CustomPolicy: Sendable {
        /// Required extended key usages (empty = any).
        public var requiredExtendedKeyUsages: [ExtendedKeyUsage]
        
        /// Required key usages (empty = any).
        public var requiredKeyUsages: [KeyUsage]
        
        /// Hostname to verify (nil = skip hostname check).
        public var hostname: String?
        
        /// Email address to verify (nil = skip email check).
        public var email: String?
        
        /// Maximum chain depth (0 = unlimited).
        public var maxDepth: Int
        
        /// Whether to check certificate revocation (CRL/OCSP).
        public var checkRevocation: Bool
        
        /// The time to use for validity checking (nil = current time).
        public var verificationTime: Date?
        
        /// Creates a custom policy with default settings.
        public init()
    }
    
    /// Extended Key Usage OIDs.
    public enum ExtendedKeyUsage: Sendable {
        case serverAuth
        case clientAuth
        case codeSigning
        case emailProtection
        case timeStamping
        case ocspSigning
        case anyExtendedKeyUsage
        case custom(String)  // OID string
    }
    
    /// Key Usage flags.
    public struct KeyUsage: OptionSet, Sendable {
        public static let digitalSignature = KeyUsage(rawValue: 1 << 0)
        public static let nonRepudiation = KeyUsage(rawValue: 1 << 1)
        public static let keyEncipherment = KeyUsage(rawValue: 1 << 2)
        public static let dataEncipherment = KeyUsage(rawValue: 1 << 3)
        public static let keyAgreement = KeyUsage(rawValue: 1 << 4)
        public static let keyCertSign = KeyUsage(rawValue: 1 << 5)
        public static let crlSign = KeyUsage(rawValue: 1 << 6)
        public static let encipherOnly = KeyUsage(rawValue: 1 << 7)
        public static let decipherOnly = KeyUsage(rawValue: 1 << 8)
        
        public let rawValue: Int
        public init(rawValue: Int)
    }
}
```

### Chain Failure

```swift
extension OpenSSL.X509 {
    /// Reasons a certificate chain verification may fail.
    public enum ChainFailure: Sendable, Equatable {
        /// No valid chain could be built to a trusted root.
        case untrustedRoot
        
        /// A certificate in the chain has expired.
        case expired(Certificate)
        
        /// A certificate in the chain is not yet valid.
        case notYetValid(Certificate)
        
        /// A certificate's signature is invalid.
        case invalidSignature(Certificate)
        
        /// A required extended key usage is missing.
        case missingExtendedKeyUsage(Certificate, ExtendedKeyUsage)
        
        /// A required key usage is missing.
        case missingKeyUsage(Certificate, KeyUsage)
        
        /// Hostname verification failed.
        case hostnameMismatch(expected: String, certificate: Certificate)
        
        /// Email verification failed.
        case emailMismatch(expected: String, certificate: Certificate)
        
        /// Chain depth exceeds maximum allowed.
        case chainTooLong(depth: Int, maximum: Int)
        
        /// Certificate has been revoked.
        case revoked(Certificate)
        
        /// A self-signed certificate was encountered but not trusted.
        case selfSignedCertificate(Certificate)
        
        /// A certificate is missing from the chain.
        case incompletePath
        
        /// Name constraints were violated.
        case nameConstraintViolation(Certificate)
        
        /// Basic constraints were violated (e.g., non-CA signing).
        case basicConstraintViolation(Certificate)
        
        /// An internal error occurred during verification.
        case internalError(String)
    }
}
```

### Verification Result

```swift
extension OpenSSL.X509 {
    /// Result of certificate chain verification.
    public struct VerificationResult: Sendable {
        /// Whether the verification succeeded.
        public let isValid: Bool
        
        /// The verified certificate chain from leaf to root.
        /// Only populated if verification succeeded.
        public let chain: [Certificate]
        
        /// Any failures encountered during verification.
        public let failures: [ChainFailure]
        
        /// The policy that was used for verification.
        public let policy: VerificationPolicy
        
        /// The depth of the verified chain.
        public var chainDepth: Int { chain.count }
        
        /// A human-readable summary of the result.
        public var summary: String { get }
    }
}
```

---

## Verification API

```swift
extension OpenSSL.X509 {
    /// Verifies a certificate against a trust store (fast path).
    ///
    /// - Parameters:
    ///   - certificate: The certificate to verify (leaf/end-entity).
    ///   - intermediates: Optional intermediate certificates for chain building.
    ///   - trustStore: The trust store containing trusted roots.
    ///   - policy: The verification policy to apply.
    /// - Returns: `true` if the certificate is valid according to the policy.
    public static func isValid(
        _ certificate: Certificate,
        intermediates: [Certificate] = [],
        using trustStore: TrustStore,
        policy: VerificationPolicy = .any
    ) -> Bool
    
    /// Verifies a certificate with detailed result.
    ///
    /// - Parameters:
    ///   - certificate: The certificate to verify (leaf/end-entity).
    ///   - intermediates: Optional intermediate certificates for chain building.
    ///   - trustStore: The trust store containing trusted roots.
    ///   - policy: The verification policy to apply.
    /// - Returns: A detailed verification result.
    public static func verify(
        _ certificate: Certificate,
        intermediates: [Certificate] = [],
        using trustStore: TrustStore,
        policy: VerificationPolicy = .any
    ) -> VerificationResult
}
```

### Chain Building

```swift
extension OpenSSL.X509 {
    /// Builds a certificate chain from leaf to root.
    ///
    /// - Parameters:
    ///   - certificate: The leaf certificate.
    ///   - intermediates: Available intermediate certificates.
    ///   - trustStore: The trust store containing trusted roots.
    /// - Returns: The built chain from leaf to root, or nil if no chain could be built.
    public static func buildChain(
        for certificate: Certificate,
        intermediates: [Certificate] = [],
        using trustStore: TrustStore
    ) -> [Certificate]?
}
```

---

## Usage Examples

### Basic TLS Certificate Verification

```swift
import OpenSSL

// Load leaf certificate
let leafCert = try OpenSSL.X509.Certificate(pemRepresentation: leafPEM)

// Load intermediates (if any)
let intermediateCert = try OpenSSL.X509.Certificate(pemRepresentation: intermediatePEM)

// Use system trust store
let trustStore = try OpenSSL.X509.TrustStore.system()

// Verify for TLS with hostname
let isValid = OpenSSL.X509.isValid(
    leafCert,
    intermediates: [intermediateCert],
    using: trustStore,
    policy: .tls(hostname: "example.com")
)

print("Certificate valid: \(isValid)")
```

### Detailed Verification

```swift
let result = OpenSSL.X509.verify(
    leafCert,
    intermediates: [intermediateCert],
    using: trustStore,
    policy: .tls(hostname: "example.com")
)

if result.isValid {
    print("Certificate chain valid")
    print("Chain depth: \(result.chainDepth)")
    for (i, cert) in result.chain.enumerated() {
        print("  [\(i)] \(cert.subjectCommonName ?? "unknown")")
    }
} else {
    print("Certificate chain invalid:")
    for failure in result.failures {
        switch failure {
        case .expired(let cert):
            print("  - Expired: \(cert.subjectCommonName ?? "?")")
        case .hostnameMismatch(let expected, _):
            print("  - Hostname mismatch: expected \(expected)")
        case .untrustedRoot:
            print("  - Untrusted root certificate")
        default:
            print("  - \(failure)")
        }
    }
}
```

### Custom Trust Store

```swift
// Create custom trust store with specific CAs
let customCA = try OpenSSL.X509.Certificate(pemRepresentation: customCAPEM)
let trustStore = OpenSSL.X509.TrustStore(certificates: [customCA])

// Or load from file
let trustStore = try OpenSSL.X509.TrustStore.loadPEM(
    from: URL(fileURLWithPath: "/path/to/trusted-cas.pem")
)

// Merge with system
let combined = try OpenSSL.X509.TrustStore.system()
    .merging(trustStore)
```

### Custom Policy

```swift
// Custom policy: code signing with specific key usage
var customPolicy = OpenSSL.X509.CustomPolicy()
customPolicy.requiredExtendedKeyUsages = [.codeSigning]
customPolicy.requiredKeyUsages = [.digitalSignature]
customPolicy.maxDepth = 3
customPolicy.checkRevocation = true

let result = OpenSSL.X509.verify(
    cert,
    using: trustStore,
    policy: .custom(customPolicy)
)
```

### TLS Snapshot Integration

```swift
struct TLSSnapshot {
    let certificateChain: [OpenSSL.X509.Certificate]
    let capturedAt: Date
    
    func verifyChain() -> OpenSSL.X509.VerificationResult {
        guard let leaf = certificateChain.first else {
            return OpenSSL.X509.VerificationResult(
                isValid: false,
                chain: [],
                failures: [.incompletePath],
                policy: .tls(hostname: nil)
            )
        }
        
        let intermediates = Array(certificateChain.dropFirst().dropLast())
        
        // Use custom policy with snapshot capture time
        var policy = OpenSSL.X509.CustomPolicy()
        policy.verificationTime = capturedAt
        
        return OpenSSL.X509.verify(
            leaf,
            intermediates: intermediates,
            using: try! .system(),
            policy: .custom(policy)
        )
    }
}
```

---

## OpenSSL Function Mapping

| Swift API | OpenSSL Functions |
|-----------|-------------------|
| `TrustStore.system()` | `X509_STORE_new`, `X509_STORE_set_default_paths` |
| `TrustStore.loadPEM(from:)` | `X509_STORE_new`, `X509_STORE_load_file` |
| `TrustStore.loadDirectory(from:)` | `X509_STORE_new`, `X509_STORE_load_path` |
| `TrustStore.adding(_:)` | `X509_STORE_add_cert` |
| `isValid(...)` | `X509_STORE_CTX_new`, `X509_STORE_CTX_init`, `X509_verify_cert` |
| `verify(...)` | Same as above + `X509_STORE_CTX_get_error`, `X509_STORE_CTX_get_chain` |
| `.tls(hostname:)` | `X509_VERIFY_PARAM_set1_host`, `X509_VERIFY_PARAM_set_purpose(X509_PURPOSE_SSL_SERVER)` |
| `CustomPolicy.verificationTime` | `X509_VERIFY_PARAM_set_time` |
| `CustomPolicy.maxDepth` | `X509_VERIFY_PARAM_set_depth` |
| `CustomPolicy.checkRevocation` | `X509_VERIFY_PARAM_set_flags(X509_V_FLAG_CRL_CHECK)` |

### Verification Parameter Setup

```c
// Set up verification parameters
X509_VERIFY_PARAM* param = X509_STORE_CTX_get0_param(ctx);

// TLS hostname verification
X509_VERIFY_PARAM_set1_host(param, hostname, 0);

// Set verification time
X509_VERIFY_PARAM_set_time(param, verification_time);

// Set max depth
X509_VERIFY_PARAM_set_depth(param, max_depth);

// Set purpose
X509_VERIFY_PARAM_set_purpose(param, X509_PURPOSE_SSL_SERVER);
```

---

## Implementation Notes

### Error Code Mapping

Map OpenSSL `X509_V_ERR_*` codes to `ChainFailure`:

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

### System Trust Store Locations

| Platform | Location |
|----------|----------|
| macOS | Keychain (via Security.framework) or `/etc/ssl/certs` |
| Linux | `/etc/ssl/certs`, `/etc/pki/tls/certs`, or `$SSL_CERT_DIR` |
| iOS | System Keychain (limited access) |

For cross-platform consistency, prefer bundling a known root store (e.g., Mozilla's) when system access is restricted.

### Thread Safety

- `TrustStore` is immutable and `Sendable`
- Verification creates a new `X509_STORE_CTX` per call
- Underlying `X509_STORE*` is reference-counted with thread-safe access

---

## File Structure

```
Sources/OpenSSL/
├── X509/
│   ├── X509.swift                  # X509 namespace (existing)
│   ├── X509+Certificate.swift      # Certificate type (existing)
│   ├── X509+TrustStore.swift       # TrustStore type
│   ├── X509+VerificationPolicy.swift  # Policy enum and CustomPolicy
│   ├── X509+VerificationResult.swift  # Result and ChainFailure
│   └── X509+Verification.swift     # isValid/verify/buildChain functions
```
