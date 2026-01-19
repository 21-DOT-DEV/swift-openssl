# Certificate Transparency Specification

> **Parent:** [overview.md](overview.md)  
> **Status:** Draft  

## Overview

Certificate Transparency (RFC 6962/9162) verification for validating Signed Certificate Timestamps (SCTs). Supports parsing SCTs from certificates, TLS extensions, and OCSP responses, with policy-based verification against trusted CT log lists.

---

## Namespace

```swift
extension OpenSSL {
    /// Certificate Transparency (RFC 6962/9162) operations.
    public enum CT {}
}
```

---

## Types

### SCT Source

```swift
extension OpenSSL.CT {
    /// The source from which an SCT was obtained.
    public enum SCTSource: Sendable {
        /// Embedded in the certificate's X.509v3 extension.
        case certificateExtension
        /// Delivered via TLS extension during handshake.
        case tlsExtension
        /// Included in a stapled OCSP response.
        case ocspResponse
        /// Source unknown or not specified.
        case unknown
    }
}
```

### SCT (Signed Certificate Timestamp)

```swift
extension OpenSSL.CT {
    /// A Signed Certificate Timestamp from a CT log.
    public struct SCT: Sendable {
        /// The SHA-256 hash of the log's public key (32 bytes).
        public let logID: Data
        
        /// The timestamp when the SCT was issued (milliseconds since Unix epoch).
        public let timestamp: UInt64
        
        /// The timestamp as a Date.
        public var date: Date {
            Date(timeIntervalSince1970: TimeInterval(timestamp) / 1000.0)
        }
        
        /// The SCT signature.
        public let signature: Data
        
        /// The source of this SCT.
        public let source: SCTSource
        
        /// SCT extensions (typically empty in v1).
        public let extensions: Data
        
        /// Creates an SCT from raw TLS-encoded bytes.
        /// - Parameter tlsBytes: The TLS-serialized SCT.
        /// - Throws: `OpenSSLError.invalidInput` if parsing fails.
        public init<D: DataProtocol>(tlsBytes: D) throws
        
        /// Creates an SCT from base64-encoded components (for JSON log lists).
        public init(
            logIDBase64: String,
            timestamp: UInt64,
            signatureBase64: String,
            extensionsBase64: String = "",
            source: SCTSource = .unknown
        ) throws
        
        /// Parses a list of SCTs from TLS-encoded format (as in TLS extension).
        /// - Parameter tlsBytes: The TLS-serialized SCT list.
        /// - Returns: Array of parsed SCTs.
        /// - Throws: `OpenSSLError.invalidInput` if parsing fails.
        public static func list<D: DataProtocol>(fromTLSBytes tlsBytes: D) throws -> [SCT]
        
        /// Extracts embedded SCTs from a certificate's X.509v3 extension.
        /// - Parameter certificate: The certificate to extract SCTs from.
        /// - Returns: Array of embedded SCTs, or empty if none present.
        public static func embedded(in certificate: OpenSSL.X509.Certificate) -> [SCT]
    }
}
```

### CT Log

```swift
extension OpenSSL.CT {
    /// A Certificate Transparency log.
    public struct Log: Sendable, Identifiable {
        /// The log's unique identifier (SHA-256 of public key).
        public let id: Data
        
        /// Human-readable log name.
        public let name: String
        
        /// The log's ECDSA or RSA public key (DER-encoded SPKI).
        public let publicKey: Data
        
        /// Log operator name (optional).
        public let `operator`: String?
        
        /// Log URL (optional, for fetching proofs).
        public let url: URL?
        
        /// Creates a log entry.
        public init(
            name: String,
            publicKeyBase64: String,
            operator: String? = nil,
            url: URL? = nil
        ) throws
        
        /// Creates a log entry from DER-encoded public key.
        public init<D: DataProtocol>(
            name: String,
            publicKeyDER: D,
            operator: String? = nil,
            url: URL? = nil
        )
    }
}
```

### Log List

```swift
extension OpenSSL.CT {
    /// A collection of trusted CT logs for SCT verification.
    public struct LogList: Sendable {
        /// The logs in this list.
        public let logs: [Log]
        
        /// Creates an empty log list.
        public init()
        
        /// Creates a log list from an array of logs.
        public init(logs: [Log])
        
        /// Loads logs from Google's JSON log list format.
        /// - Parameter jsonData: The JSON data in Google's log_list.json format.
        /// - Throws: `OpenSSLError.invalidInput` if parsing fails.
        public init<D: DataProtocol>(googleJSON jsonData: D) throws
        
        /// Loads logs from a JSON file.
        /// - Parameter url: URL to the JSON file.
        /// - Throws: `OpenSSLError.invalidInput` if parsing fails.
        public init(contentsOf url: URL) throws
        
        /// The bundled log list (compiled into the library).
        /// Contains major public logs from Google, Cloudflare, DigiCert, etc.
        public static let bundled: LogList
        
        /// Finds a log by its ID.
        /// - Parameter logID: The 32-byte log ID (SHA-256 of public key).
        /// - Returns: The matching log, or `nil` if not found.
        public func log(withID logID: Data) -> Log?
        
        /// Adds a log to the list.
        /// - Parameter log: The log to add.
        /// - Returns: A new LogList containing the additional log.
        public func adding(_ log: Log) -> LogList
        
        /// Adds multiple logs to the list.
        /// - Parameter logs: The logs to add.
        /// - Returns: A new LogList containing the additional logs.
        public func adding(contentsOf logs: [Log]) -> LogList
    }
}
```

---

## Policy

```swift
extension OpenSSL.CT {
    /// Policy for SCT verification.
    public enum Policy: Sendable {
        /// At least N SCTs must verify successfully.
        case atLeast(Int)
        
        /// At least N SCTs from distinct logs must verify.
        case requireDistinctLogs(Int)
        
        /// All SCTs must verify successfully.
        case allMustPass
        
        /// Chrome-like policy: depends on certificate lifetime.
        /// - < 180 days: 2 SCTs from distinct logs
        /// - 180+ days: 3 SCTs from distinct logs
        case chromeLike
        
        /// Default policy: at least 1 SCT from a known log.
        public static let `default`: Policy = .requireDistinctLogs(1)
    }
}
```

---

## Verification Result Types

### SCT Failure

```swift
extension OpenSSL.CT {
    /// Reason an SCT failed verification.
    public enum SCTFailure: Sendable, Equatable {
        /// The SCT signature is cryptographically invalid.
        case invalidSignature
        
        /// The log ID doesn't match any known log.
        case unknownLogID
        
        /// The SCT timestamp is in the future relative to verification time.
        case timestampInFuture
        
        /// The SCT timestamp is outside the certificate's validity period.
        case timestampOutsideCertValidity
        
        /// SCT version is unsupported (only v1 is supported).
        case unsupportedVersion
        
        /// Merkle inclusion proof verification failed (if provided).
        case merkleProofMismatch
        
        /// An internal error occurred during verification.
        case internalError(String)
    }
}
```

### Per-SCT Result

```swift
extension OpenSSL.CT {
    /// Result of verifying a single SCT.
    public struct PerSCTResult: Sendable {
        /// The SCT that was verified.
        public let sct: SCT
        
        /// The log that issued this SCT, if known.
        public let log: Log?
        
        /// Whether verification succeeded.
        public let isValid: Bool
        
        /// The failure reason, if verification failed.
        public let failure: SCTFailure?
    }
}
```

### SCT Report

```swift
extension OpenSSL.CT {
    /// Detailed report of SCT verification.
    public struct SCTReport: Sendable {
        /// Whether the overall verification passed according to the policy.
        public let passed: Bool
        
        /// The policy that was applied.
        public let policy: Policy
        
        /// Results for each individual SCT.
        public let results: [PerSCTResult]
        
        /// Number of SCTs that verified successfully.
        public var validCount: Int {
            results.filter(\.isValid).count
        }
        
        /// Number of distinct logs with valid SCTs.
        public var distinctValidLogCount: Int {
            Set(results.filter(\.isValid).compactMap(\.log?.id)).count
        }
        
        /// SCTs that failed verification.
        public var failures: [PerSCTResult] {
            results.filter { !$0.isValid }
        }
    }
}
```

---

## Verification Context

```swift
extension OpenSSL.CT {
    /// Configuration for SCT verification.
    public struct VerificationContext: Sendable {
        /// The trusted log list.
        public let logList: LogList
        
        /// The verification policy.
        public let policy: Policy
        
        /// The time to use for timestamp validation (default: now).
        public let verificationTime: Date
        
        /// Maximum allowed clock skew in seconds (default: 300 = 5 minutes).
        public let allowedClockSkew: TimeInterval
        
        /// Creates a verification context.
        public init(
            logList: LogList = .bundled,
            policy: Policy = .default,
            verificationTime: Date = Date(),
            allowedClockSkew: TimeInterval = 300
        ) {
            self.logList = logList
            self.policy = policy
            self.verificationTime = verificationTime
            self.allowedClockSkew = allowedClockSkew
        }
        
        /// Default context using bundled logs and default policy.
        public static let `default` = VerificationContext()
    }
}
```

---

## Verification API

```swift
extension OpenSSL.CT {
    /// Verifies SCTs for a certificate (fast path).
    ///
    /// - Parameters:
    ///   - scts: The SCTs to verify.
    ///   - certificate: The certificate the SCTs are for.
    ///   - issuer: The issuer certificate (needed for precert SCTs).
    ///   - context: Verification configuration.
    /// - Returns: `true` if verification passes according to the policy.
    public static func isValidSCTs(
        _ scts: [SCT],
        for certificate: OpenSSL.X509.Certificate,
        issuer: OpenSSL.X509.Certificate? = nil,
        context: VerificationContext = .default
    ) -> Bool
    
    /// Verifies SCTs for a certificate with detailed report.
    ///
    /// - Parameters:
    ///   - scts: The SCTs to verify.
    ///   - certificate: The certificate the SCTs are for.
    ///   - issuer: The issuer certificate (needed for precert SCTs).
    ///   - context: Verification configuration.
    /// - Returns: A detailed verification report.
    public static func verifySCTs(
        _ scts: [SCT],
        for certificate: OpenSSL.X509.Certificate,
        issuer: OpenSSL.X509.Certificate? = nil,
        context: VerificationContext = .default
    ) -> SCTReport
}
```

---

## Usage Examples

### Basic CT Verification

```swift
import OpenSSL

// Parse certificate and extract embedded SCTs
let cert = try OpenSSL.X509.Certificate(pemRepresentation: leafCertPEM)
let issuer = try OpenSSL.X509.Certificate(pemRepresentation: issuerCertPEM)
let embeddedSCTs = OpenSSL.CT.SCT.embedded(in: cert)

// Quick verification with default policy
let isValid = OpenSSL.CT.isValidSCTs(embeddedSCTs, for: cert, issuer: issuer)
print("CT Valid: \(isValid)")
```

### Detailed Verification Report

```swift
// Get detailed report
let report = OpenSSL.CT.verifySCTs(embeddedSCTs, for: cert, issuer: issuer)

print("CT Verification: \(report.passed ? "PASSED" : "FAILED")")
print("Valid SCTs: \(report.validCount) from \(report.distinctValidLogCount) distinct logs")

for failure in report.failures {
    let logPrefix = failure.sct.logID.prefix(8).map { String(format: "%02x", $0) }.joined()
    print("  Failed: \(failure.failure!) for log \(logPrefix)...")
}
```

### Custom Policy

```swift
// Require at least 2 SCTs from distinct logs
let context = OpenSSL.CT.VerificationContext(
    logList: .bundled,
    policy: .requireDistinctLogs(2),
    verificationTime: snapshotTime
)

let report = OpenSSL.CT.verifySCTs(embeddedSCTs, for: cert, issuer: issuer, context: context)
```

### Custom Log List

```swift
// Load custom log list from JSON
let customLogs = try OpenSSL.CT.LogList(contentsOf: URL(fileURLWithPath: "logs.json"))

// Merge with bundled logs
let mergedLogs = OpenSSL.CT.LogList.bundled.adding(contentsOf: customLogs.logs)

let context = OpenSSL.CT.VerificationContext(logList: mergedLogs)
let isValid = OpenSSL.CT.isValidSCTs(scts, for: cert, context: context)
```

### Parse SCTs from TLS Extension

```swift
// Parse SCTs received via TLS extension
let tlsSCTs = try OpenSSL.CT.SCT.list(fromTLSBytes: tlsExtensionData)

// Verify combined SCTs (embedded + TLS)
let allSCTs = embeddedSCTs + tlsSCTs
let report = OpenSSL.CT.verifySCTs(allSCTs, for: cert, issuer: issuer)
```

### TLS Snapshot Integration

```swift
struct TLSSnapshot {
    let origin: URL
    let capturedAt: Date
    let certificateChain: [OpenSSL.X509.Certificate]
    let scts: [OpenSSL.CT.SCT]
    
    func verifyCT() -> OpenSSL.CT.SCTReport {
        guard let leaf = certificateChain.first,
              let issuer = certificateChain.dropFirst().first else {
            // Return empty failed report
            return OpenSSL.CT.SCTReport(passed: false, policy: .default, results: [])
        }
        
        let context = OpenSSL.CT.VerificationContext(
            verificationTime: capturedAt
        )
        
        return OpenSSL.CT.verifySCTs(scts, for: leaf, issuer: issuer, context: context)
    }
}
```

---

## OpenSSL Function Mapping

| Swift API | OpenSSL Functions |
|-----------|-------------------|
| `SCT(tlsBytes:)` | `o2i_SCT` |
| `SCT.list(fromTLSBytes:)` | `o2i_SCT_LIST` |
| `SCT.embedded(in:)` | `X509_get_ext_d2i(NID_ct_precert_scts)`, `d2i_SCT_LIST` |
| `Log(publicKeyBase64:)` | `CTLOG_new_from_base64` |
| `LogList(googleJSON:)` | `CTLOG_STORE_new`, JSON parsing + `CTLOG_new_from_base64` |
| `LogList.bundled` | Compiled `CTLOG_STORE` from embedded data |
| `isValidSCTs` / `verifySCTs` | `CT_POLICY_EVAL_CTX_new`, `CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE`, `CT_POLICY_EVAL_CTX_set1_cert`, `CT_POLICY_EVAL_CTX_set1_issuer`, `CT_POLICY_EVAL_CTX_set_time`, `SCT_LIST_validate` |

---

## Implementation Notes

### Bundled Log List

The bundled log list should include major public CT logs:
- Google (Argon, Xenon, Icarus, Pilot, Skydiver, etc.)
- Cloudflare (Nimbus)
- DigiCert (Yeti, Nessie)
- Sectigo (Sabre, Mammoth)
- Let's Encrypt (Oak)

Store as:
1. Compiled Swift code (fallback, always available)
2. JSON resource file (updatable without recompilation)

### Precert vs Final Cert SCTs

- Embedded SCTs sign the "precertificate" (with poison extension)
- TLS/OCSP SCTs sign the final certificate
- OpenSSL's `CT_POLICY_EVAL_CTX` handles this distinction when issuer cert is provided

### Timestamp Validation

- SCT timestamp must be ≤ verification time + allowed clock skew
- SCT timestamp should be within certificate validity period (warning, not failure)
