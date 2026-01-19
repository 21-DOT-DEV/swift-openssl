# RSA-PSS Verification Specification

> **Parent:** [overview.md](overview.md)  
> **Status:** Draft  

## Overview

RSA-PSS (Probabilistic Signature Scheme) verification for TLS certificate signature validation. Supports SHA-256 and SHA-384 hash algorithms with configurable salt length.

---

## Namespace

```swift
extension OpenSSL.RSA {
    /// RSA-PSS (Probabilistic Signature Scheme) operations.
    public enum PSS {}
}
```

---

## Types

### Hash Function

```swift
extension OpenSSL.RSA.PSS {
    /// Hash algorithms supported for RSA-PSS.
    public enum HashFunction: Sendable {
        /// SHA-256 (256-bit digest, 32-byte salt default)
        case sha256
        
        /// SHA-384 (384-bit digest, 48-byte salt default)
        case sha384
        
        /// The digest length in bytes.
        public var digestLength: Int {
            switch self {
            case .sha256: return 32
            case .sha384: return 48
            }
        }
    }
}
```

### Parameters

```swift
extension OpenSSL.RSA.PSS {
    /// RSA-PSS signature parameters.
    public struct Parameters: Sendable, Equatable {
        /// The hash function for the message digest.
        public let hashFunction: HashFunction
        
        /// The hash function for MGF1 (defaults to same as hashFunction).
        public let mgf1HashFunction: HashFunction
        
        /// Salt length in bytes. Use `nil` for hash-length default (TLS 1.3 convention).
        public let saltLength: Int?
        
        /// Default parameters: SHA-256, saltLength = hashLength.
        public static let sha256 = Parameters(hashFunction: .sha256)
        
        /// SHA-384 parameters: SHA-384, saltLength = hashLength.
        public static let sha384 = Parameters(hashFunction: .sha384)
        
        /// Creates RSA-PSS parameters.
        /// - Parameters:
        ///   - hashFunction: The hash algorithm for the message digest.
        ///   - mgf1HashFunction: The hash algorithm for MGF1. Defaults to `hashFunction`.
        ///   - saltLength: Salt length in bytes. `nil` means hash-length (TLS 1.3 default).
        public init(
            hashFunction: HashFunction,
            mgf1HashFunction: HashFunction? = nil,
            saltLength: Int? = nil
        ) {
            self.hashFunction = hashFunction
            self.mgf1HashFunction = mgf1HashFunction ?? hashFunction
            self.saltLength = saltLength
        }
    }
}
```

### Public Key

```swift
extension OpenSSL.RSA.PSS {
    /// An RSA public key for PSS signature verification.
    public struct PublicKey: Sendable {
        // Internal: OpenSSL EVP_PKEY handle (wrapped for memory safety)
        
        /// The key size in bits.
        public var keySizeInBits: Int { get }
        
        /// Creates a public key from PEM-encoded data.
        /// - Parameter pemRepresentation: The PEM-encoded public key string.
        /// - Throws: `OpenSSLError.invalidKey` if the PEM data is invalid or not an RSA key.
        public init(pemRepresentation: String) throws
        
        /// Creates a public key from DER-encoded SubjectPublicKeyInfo.
        /// - Parameter derRepresentation: The DER-encoded SPKI data.
        /// - Throws: `OpenSSLError.invalidKey` if the data is invalid.
        public init<D: DataProtocol>(derRepresentation: D) throws
        
        /// Extracts the RSA public key from an X.509 certificate.
        /// - Parameter certificate: The certificate containing the public key.
        /// - Throws: `OpenSSLError.invalidKey` if the certificate doesn't contain an RSA key.
        public init(certificate: OpenSSL.X509.Certificate) throws
        
        /// The DER-encoded SubjectPublicKeyInfo representation.
        public var derRepresentation: Data { get }
        
        /// The PEM-encoded public key representation.
        public var pemRepresentation: String { get }
    }
}
```

### Signature

```swift
extension OpenSSL.RSA.PSS {
    /// An RSA-PSS signature.
    public struct Signature: ContiguousBytes, Sendable {
        /// The raw signature bytes.
        public let rawRepresentation: Data
        
        /// Creates a signature from raw bytes.
        /// - Parameter rawRepresentation: The raw signature data.
        public init<D: DataProtocol>(rawRepresentation: D) {
            self.rawRepresentation = Data(rawRepresentation)
        }
        
        /// Invokes the given closure with a buffer pointer covering the raw bytes.
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R
    }
}
```

---

## Verification API

```swift
extension OpenSSL.RSA.PSS.PublicKey {
    /// Verifies an RSA-PSS signature over data.
    ///
    /// - Parameters:
    ///   - signature: The signature to verify.
    ///   - data: The original data that was signed.
    ///   - parameters: RSA-PSS parameters. Defaults to SHA-256 with salt = hash length.
    /// - Returns: `true` if the signature is valid; `false` otherwise.
    public func isValidSignature<D: DataProtocol>(
        _ signature: Signature,
        for data: D,
        parameters: Parameters = .sha256
    ) -> Bool
    
    /// Verifies an RSA-PSS signature over a pre-computed digest.
    ///
    /// - Parameters:
    ///   - signature: The signature to verify.
    ///   - digest: The message digest that was signed.
    ///   - parameters: RSA-PSS parameters. Must match the hash used for the digest.
    /// - Returns: `true` if the signature is valid; `false` otherwise.
    public func isValidSignature<D: Digest>(
        _ signature: Signature,
        for digest: D,
        parameters: Parameters
    ) -> Bool
}
```

---

## Protocols (Optional Conformance)

```swift
/// A type that can validate signatures over digests.
public protocol DigestValidator {
    associatedtype Signature
    func isValidSignature<D: Digest>(_ signature: Signature, for digest: D) -> Bool
}

/// A type that can validate signatures over raw data.
public protocol DataValidator {
    associatedtype Signature
    func isValidSignature<D: DataProtocol>(_ signature: Signature, for data: D) -> Bool
}

// Conformance (internal, to avoid protocol requirement conflicts)
extension OpenSSL.RSA.PSS.PublicKey {
    // Implements both protocols with default parameters
}
```

---

## Usage Examples

### Basic Verification

```swift
import OpenSSL

// Load a public key from PEM
let publicKey = try OpenSSL.RSA.PSS.PublicKey(pemRepresentation: pemString)

// Verify a signature (SHA-256 by default)
let signature = OpenSSL.RSA.PSS.Signature(rawRepresentation: signatureData)
let isValid = publicKey.isValidSignature(signature, for: messageData)

print("Signature valid: \(isValid)")
```

### SHA-384 Verification

```swift
// Verify with SHA-384
let isValid384 = publicKey.isValidSignature(
    signature, 
    for: messageData, 
    parameters: .sha384
)
```

### Extract Key from Certificate

```swift
// Extract RSA public key from X.509 certificate
let cert = try OpenSSL.X509.Certificate(pemRepresentation: certPEM)
let certKey = try OpenSSL.RSA.PSS.PublicKey(certificate: cert)

// Verify signature using extracted key
let isValid = certKey.isValidSignature(signature, for: messageData)
```

### Custom Parameters

```swift
// Custom RSA-PSS parameters: SHA-256 with explicit salt length
let params = OpenSSL.RSA.PSS.Parameters(
    hashFunction: .sha256,
    saltLength: 20  // 20-byte salt instead of default 32
)

let isValid = publicKey.isValidSignature(signature, for: messageData, parameters: params)
```

---

## OpenSSL Function Mapping

| Swift API | OpenSSL Functions |
|-----------|-------------------|
| `PublicKey(pemRepresentation:)` | `BIO_new_mem_buf`, `PEM_read_bio_PUBKEY` |
| `PublicKey(derRepresentation:)` | `d2i_PUBKEY` |
| `PublicKey(certificate:)` | `X509_get_pubkey` |
| `keySizeInBits` | `EVP_PKEY_get_bits` |
| `derRepresentation` | `i2d_PUBKEY` |
| `pemRepresentation` | `PEM_write_bio_PUBKEY` |
| `isValidSignature(_:for:parameters:)` | `EVP_DigestVerifyInit`, `EVP_PKEY_CTX_set_rsa_padding(RSA_PKCS1_PSS_PADDING)`, `EVP_PKEY_CTX_set_rsa_pss_saltlen`, `EVP_PKEY_CTX_set_rsa_mgf1_md`, `EVP_DigestVerify` |

---

## Implementation Notes

### Salt Length Handling

- When `saltLength` is `nil`, use `RSA_PSS_SALTLEN_DIGEST` (salt = hash length)
- This matches TLS 1.3 convention where salt length equals digest length
- For certificates with explicit RSA-PSS parameters in AlgorithmIdentifier, those parameters should override defaults

### Key Type Validation

- `EVP_PKEY_get_base_id()` must return `EVP_PKEY_RSA` or `EVP_PKEY_RSA_PSS`
- Throw `OpenSSLError.invalidKey("Not an RSA key")` for other key types
