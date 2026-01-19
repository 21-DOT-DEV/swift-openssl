# HMAC Specification

> **Parent:** [overview.md](overview.md)  
> **Status:** Draft  
> **Priority:** 1 (Foundation)

## Overview

HMAC (Hash-based Message Authentication Code) for message authentication and integrity verification. API matches swift-crypto's `HMAC<H: HashFunction>` pattern.

---

## Namespace

```swift
extension OpenSSL {
    /// HMAC (Hash-based Message Authentication Code) operations.
    public enum HMAC {}
}
```

---

## Types

### Hash Function Protocol

```swift
/// A cryptographic hash function.
public protocol HashFunction: Sendable {
    /// The type of the digest output.
    associatedtype Digest: Sendable
    
    /// The number of bytes in the digest.
    static var digestByteCount: Int { get }
    
    /// The block size of the hash function in bytes.
    static var blockByteCount: Int { get }
    
    /// Creates a new hash function instance.
    init()
    
    /// Updates the hash with additional data.
    mutating func update<D: DataProtocol>(data: D)
    
    /// Finalizes the hash and returns the digest.
    func finalize() -> Digest
}
```

### Supported Hash Functions

```swift
extension OpenSSL {
    /// SHA-256 hash function.
    public struct SHA256: HashFunction {
        public typealias Digest = SHA256Digest
        public static let digestByteCount = 32
        public static let blockByteCount = 64
        
        public init()
        public mutating func update<D: DataProtocol>(data: D)
        public func finalize() -> Digest
    }
    
    /// SHA-384 hash function.
    public struct SHA384: HashFunction {
        public typealias Digest = SHA384Digest
        public static let digestByteCount = 48
        public static let blockByteCount = 128
        
        public init()
        public mutating func update<D: DataProtocol>(data: D)
        public func finalize() -> Digest
    }
    
    /// SHA-512 hash function.
    public struct SHA512: HashFunction {
        public typealias Digest = SHA512Digest
        public static let digestByteCount = 64
        public static let blockByteCount = 128
        
        public init()
        public mutating func update<D: DataProtocol>(data: D)
        public func finalize() -> Digest
    }
}
```

### Symmetric Key

```swift
extension OpenSSL {
    /// A symmetric cryptographic key.
    public struct SymmetricKey: Sendable {
        /// The size of the key in bits.
        public var bitCount: Int { get }
        
        /// Creates a key from raw bytes.
        /// - Parameter data: The key material.
        public init<D: DataProtocol>(data: D)
        
        /// Generates a random key of the specified size.
        /// - Parameter size: The desired key size.
        public init(size: SymmetricKeySize)
        
        /// Invokes the given closure with a buffer pointer covering the raw key bytes.
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R
    }
    
    /// Symmetric key sizes.
    public enum SymmetricKeySize: Sendable {
        case bits128
        case bits192
        case bits256
        
        /// Custom size in bits.
        case bits(Int)
        
        /// The size in bits.
        public var bitCount: Int { get }
    }
}
```

### Hashed Authentication Code

```swift
extension OpenSSL {
    /// The output of an HMAC operation.
    public struct HashedAuthenticationCode<H: HashFunction>: Sendable, ContiguousBytes {
        /// The raw bytes of the authentication code.
        public var rawRepresentation: Data { get }
        
        /// Invokes the given closure with a buffer pointer covering the raw bytes.
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R
    }
}

extension HashedAuthenticationCode: Equatable {
    /// Compares two authentication codes in constant time.
    public static func == (lhs: Self, rhs: Self) -> Bool
}
```

---

## HMAC Type

```swift
extension OpenSSL {
    /// HMAC with a specified hash function.
    public struct HMAC<H: HashFunction>: Sendable {
        /// The key used for authentication.
        private let key: SymmetricKey
        
        /// Creates an HMAC instance with the specified key.
        /// - Parameter key: The symmetric key for authentication.
        public init(key: SymmetricKey)
        
        /// Updates the HMAC with additional data.
        /// - Parameter data: The data to authenticate.
        public mutating func update<D: DataProtocol>(data: D)
        
        /// Finalizes the HMAC and returns the authentication code.
        /// - Returns: The authentication code.
        public func finalize() -> HashedAuthenticationCode<H>
    }
}
```

---

## Static API

```swift
extension OpenSSL.HMAC {
    /// Computes an authentication code for the given data.
    ///
    /// - Parameters:
    ///   - data: The data to authenticate.
    ///   - key: The symmetric key for authentication.
    /// - Returns: The authentication code.
    public static func authenticationCode<D: DataProtocol>(
        for data: D,
        using key: SymmetricKey
    ) -> HashedAuthenticationCode<H>
    
    /// Verifies an authentication code for the given data.
    ///
    /// - Parameters:
    ///   - authenticationCode: The expected authentication code.
    ///   - data: The data to verify.
    ///   - key: The symmetric key for authentication.
    /// - Returns: `true` if the authentication code is valid.
    public static func isValidAuthenticationCode<D: DataProtocol>(
        _ authenticationCode: HashedAuthenticationCode<H>,
        authenticating data: D,
        using key: SymmetricKey
    ) -> Bool
    
    /// Verifies an authentication code for the given data.
    ///
    /// - Parameters:
    ///   - authenticationCode: The expected authentication code as raw bytes.
    ///   - data: The data to verify.
    ///   - key: The symmetric key for authentication.
    /// - Returns: `true` if the authentication code is valid.
    public static func isValidAuthenticationCode<C: ContiguousBytes, D: DataProtocol>(
        _ authenticationCode: C,
        authenticating data: D,
        using key: SymmetricKey
    ) -> Bool
}
```

---

## Usage Examples

### Basic Authentication

```swift
import OpenSSL

// Create a key
let key = OpenSSL.SymmetricKey(size: .bits256)

// Compute HMAC-SHA256
let mac = OpenSSL.HMAC<OpenSSL.SHA256>.authenticationCode(
    for: messageData,
    using: key
)

print("MAC: \(mac.rawRepresentation.hexString)")
```

### Verify Authentication Code

```swift
// Verify HMAC
let isValid = OpenSSL.HMAC<OpenSSL.SHA256>.isValidAuthenticationCode(
    receivedMAC,
    authenticating: messageData,
    using: key
)

if isValid {
    print("Message is authentic")
} else {
    print("Message has been tampered with")
}
```

### Incremental Hashing

```swift
// For large data, use incremental API
var hmac = OpenSSL.HMAC<OpenSSL.SHA256>(key: key)
hmac.update(data: chunk1)
hmac.update(data: chunk2)
hmac.update(data: chunk3)
let mac = hmac.finalize()
```

### Different Hash Functions

```swift
// HMAC-SHA384
let mac384 = OpenSSL.HMAC<OpenSSL.SHA384>.authenticationCode(
    for: data,
    using: key
)

// HMAC-SHA512
let mac512 = OpenSSL.HMAC<OpenSSL.SHA512>.authenticationCode(
    for: data,
    using: key
)
```

---

## OpenSSL Function Mapping

| Swift API | OpenSSL Functions |
|-----------|-------------------|
| `HMAC.init(key:)` | `EVP_MAC_CTX_new`, `EVP_MAC_fetch("HMAC")`, `EVP_MAC_init` |
| `HMAC.update(data:)` | `EVP_MAC_update` |
| `HMAC.finalize()` | `EVP_MAC_final` |
| `HMAC.authenticationCode(for:using:)` | `EVP_MAC_init`, `EVP_MAC_update`, `EVP_MAC_final` (one-shot) |
| `isValidAuthenticationCode` | Compute + constant-time compare via `CRYPTO_memcmp` |

---

## Implementation Notes

### Constant-Time Comparison

The `isValidAuthenticationCode` method **must** use constant-time comparison to prevent timing attacks:

```c
// Use OpenSSL's CRYPTO_memcmp
int result = CRYPTO_memcmp(computed, expected, length);
return result == 0;
```

### Key Handling

- Keys shorter than the block size are used directly
- Keys longer than the block size are hashed first (per RFC 2104)
- OpenSSL handles this automatically via `EVP_MAC`

### Thread Safety

- `HMAC<H>` is a value type (struct) and is `Sendable`
- Each instance has its own `EVP_MAC_CTX` (no shared state)

---

## File Structure

```
Sources/OpenSSL/
├── HMAC/
│   ├── HMAC.swift              # HMAC<H> type and static methods
│   └── HashedAuthenticationCode.swift  # Result type
├── Keys/
│   ├── SymmetricKey.swift      # Key type
│   └── SymmetricKeySize.swift  # Size enum
└── Digests/
    ├── HashFunction.swift      # Protocol
    ├── SHA256.swift            # (existing, extend)
    ├── SHA384.swift            # (new)
    └── SHA512.swift            # (new)
```
