# AEAD Ciphers Specification

> **Parent:** [overview.md](overview.md)  
> **Status:** Draft  
> **Priority:** 3 (TLS Record Layer)

## Overview

Authenticated Encryption with Associated Data (AEAD) ciphers for TLS record authentication and encryption. Supports AES-GCM and ChaCha20-Poly1305. API matches swift-crypto's `AES.GCM` and `ChaChaPoly` patterns.

---

## Namespaces

```swift
extension OpenSSL {
    /// AES cipher operations.
    public enum AES {
        /// AES-GCM authenticated encryption.
        public enum GCM {}
    }
    
    /// ChaCha20-Poly1305 authenticated encryption.
    public enum ChaChaPoly {}
}
```

---

## Types

### Nonce

```swift
extension OpenSSL.AES.GCM {
    /// A nonce for AES-GCM encryption.
    public struct Nonce: ContiguousBytes, Sendable {
        /// The nonce size in bytes (12 bytes for GCM).
        public static let byteCount = 12
        
        /// Creates a random nonce.
        public init()
        
        /// Creates a nonce from raw bytes.
        /// - Parameter data: The nonce bytes (must be 12 bytes).
        /// - Throws: `OpenSSLError.invalidInput` if not 12 bytes.
        public init<D: DataProtocol>(data: D) throws
        
        /// Invokes the given closure with a buffer pointer covering the nonce bytes.
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R
    }
}

extension OpenSSL.ChaChaPoly {
    /// A nonce for ChaCha20-Poly1305 encryption.
    public struct Nonce: ContiguousBytes, Sendable {
        /// The nonce size in bytes (12 bytes).
        public static let byteCount = 12
        
        /// Creates a random nonce.
        public init()
        
        /// Creates a nonce from raw bytes.
        /// - Parameter data: The nonce bytes (must be 12 bytes).
        /// - Throws: `OpenSSLError.invalidInput` if not 12 bytes.
        public init<D: DataProtocol>(data: D) throws
        
        /// Invokes the given closure with a buffer pointer covering the nonce bytes.
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R
    }
}
```

### Sealed Box

```swift
extension OpenSSL.AES.GCM {
    /// A sealed box containing encrypted data and authentication tag.
    public struct SealedBox: Sendable {
        /// The nonce used for encryption.
        public let nonce: Nonce
        
        /// The encrypted ciphertext.
        public let ciphertext: Data
        
        /// The authentication tag.
        public let tag: Data
        
        /// The combined representation: nonce || ciphertext || tag.
        public var combined: Data { get }
        
        /// Creates a sealed box from components.
        /// - Parameters:
        ///   - nonce: The nonce used for encryption.
        ///   - ciphertext: The encrypted data.
        ///   - tag: The authentication tag.
        /// - Throws: `OpenSSLError.invalidInput` if tag is not 16 bytes.
        public init<C: DataProtocol, T: DataProtocol>(
            nonce: Nonce,
            ciphertext: C,
            tag: T
        ) throws
        
        /// Creates a sealed box from combined representation.
        /// - Parameter combined: The combined data (nonce || ciphertext || tag).
        /// - Throws: `OpenSSLError.invalidInput` if data is too short.
        public init<D: DataProtocol>(combined: D) throws
    }
}

extension OpenSSL.ChaChaPoly {
    /// A sealed box containing encrypted data and authentication tag.
    public struct SealedBox: Sendable {
        /// The nonce used for encryption.
        public let nonce: Nonce
        
        /// The encrypted ciphertext.
        public let ciphertext: Data
        
        /// The authentication tag.
        public let tag: Data
        
        /// The combined representation: nonce || ciphertext || tag.
        public var combined: Data { get }
        
        /// Creates a sealed box from components.
        public init<C: DataProtocol, T: DataProtocol>(
            nonce: Nonce,
            ciphertext: C,
            tag: T
        ) throws
        
        /// Creates a sealed box from combined representation.
        public init<D: DataProtocol>(combined: D) throws
    }
}
```

---

## AES-GCM API

```swift
extension OpenSSL.AES.GCM {
    /// Encrypts and authenticates data using AES-GCM.
    ///
    /// - Parameters:
    ///   - message: The plaintext to encrypt.
    ///   - key: The symmetric encryption key (128, 192, or 256 bits).
    ///   - nonce: The nonce for encryption. If nil, a random nonce is generated.
    ///   - authenticatedData: Additional data to authenticate but not encrypt.
    /// - Returns: A sealed box containing the ciphertext and authentication tag.
    /// - Throws: `OpenSSLError.invalidKey` if key size is invalid.
    public static func seal<Plaintext: DataProtocol, AAD: DataProtocol>(
        _ message: Plaintext,
        using key: SymmetricKey,
        nonce: Nonce? = nil,
        authenticating authenticatedData: AAD
    ) throws -> SealedBox
    
    /// Encrypts and authenticates data without additional authenticated data.
    public static func seal<Plaintext: DataProtocol>(
        _ message: Plaintext,
        using key: SymmetricKey,
        nonce: Nonce? = nil
    ) throws -> SealedBox
    
    /// Decrypts and verifies a sealed box.
    ///
    /// - Parameters:
    ///   - sealedBox: The sealed box to decrypt.
    ///   - key: The symmetric encryption key.
    ///   - authenticatedData: The additional authenticated data used during encryption.
    /// - Returns: The decrypted plaintext.
    /// - Throws: `OpenSSLError.authenticationFailure` if the tag is invalid.
    public static func open<AAD: DataProtocol>(
        _ sealedBox: SealedBox,
        using key: SymmetricKey,
        authenticating authenticatedData: AAD
    ) throws -> Data
    
    /// Decrypts and verifies a sealed box without additional authenticated data.
    public static func open(
        _ sealedBox: SealedBox,
        using key: SymmetricKey
    ) throws -> Data
}
```

---

## ChaCha20-Poly1305 API

```swift
extension OpenSSL.ChaChaPoly {
    /// Encrypts and authenticates data using ChaCha20-Poly1305.
    ///
    /// - Parameters:
    ///   - message: The plaintext to encrypt.
    ///   - key: The symmetric encryption key (256 bits).
    ///   - nonce: The nonce for encryption. If nil, a random nonce is generated.
    ///   - authenticatedData: Additional data to authenticate but not encrypt.
    /// - Returns: A sealed box containing the ciphertext and authentication tag.
    /// - Throws: `OpenSSLError.invalidKey` if key is not 256 bits.
    public static func seal<Plaintext: DataProtocol, AAD: DataProtocol>(
        _ message: Plaintext,
        using key: SymmetricKey,
        nonce: Nonce? = nil,
        authenticating authenticatedData: AAD
    ) throws -> SealedBox
    
    /// Encrypts and authenticates data without additional authenticated data.
    public static func seal<Plaintext: DataProtocol>(
        _ message: Plaintext,
        using key: SymmetricKey,
        nonce: Nonce? = nil
    ) throws -> SealedBox
    
    /// Decrypts and verifies a sealed box.
    ///
    /// - Parameters:
    ///   - sealedBox: The sealed box to decrypt.
    ///   - key: The symmetric encryption key.
    ///   - authenticatedData: The additional authenticated data used during encryption.
    /// - Returns: The decrypted plaintext.
    /// - Throws: `OpenSSLError.authenticationFailure` if the tag is invalid.
    public static func open<AAD: DataProtocol>(
        _ sealedBox: SealedBox,
        using key: SymmetricKey,
        authenticating authenticatedData: AAD
    ) throws -> Data
    
    /// Decrypts and verifies a sealed box without additional authenticated data.
    public static func open(
        _ sealedBox: SealedBox,
        using key: SymmetricKey
    ) throws -> Data
}
```

---

## Verification-Only API (TLS Records)

For TLS snapshot verification, you may only need to verify authenticity without decrypting:

```swift
extension OpenSSL.AES.GCM {
    /// Verifies the authentication tag without decrypting.
    ///
    /// This is useful for TLS record verification where you only need
    /// to confirm authenticity, not access the plaintext.
    ///
    /// - Parameters:
    ///   - sealedBox: The sealed box to verify.
    ///   - key: The symmetric encryption key.
    ///   - authenticatedData: The additional authenticated data.
    /// - Returns: `true` if the tag is valid.
    public static func isAuthentic<AAD: DataProtocol>(
        _ sealedBox: SealedBox,
        using key: SymmetricKey,
        authenticating authenticatedData: AAD
    ) -> Bool
}

extension OpenSSL.ChaChaPoly {
    /// Verifies the authentication tag without decrypting.
    public static func isAuthentic<AAD: DataProtocol>(
        _ sealedBox: SealedBox,
        using key: SymmetricKey,
        authenticating authenticatedData: AAD
    ) -> Bool
}
```

---

## Usage Examples

### Basic Encryption/Decryption

```swift
import OpenSSL

// Generate a key
let key = OpenSSL.SymmetricKey(size: .bits256)

// Encrypt
let sealedBox = try OpenSSL.AES.GCM.seal(
    plaintext,
    using: key
)

// Decrypt
let decrypted = try OpenSSL.AES.GCM.open(
    sealedBox,
    using: key
)
```

### With Additional Authenticated Data

```swift
// AAD is authenticated but not encrypted (e.g., TLS record header)
let header = Data([0x17, 0x03, 0x03, 0x00, 0x20])

let sealedBox = try OpenSSL.AES.GCM.seal(
    payload,
    using: key,
    nonce: nonce,
    authenticating: header
)

let decrypted = try OpenSSL.AES.GCM.open(
    sealedBox,
    using: key,
    authenticating: header
)
```

### TLS Record Verification

```swift
// Verify a TLS 1.3 record without decrypting
let recordHeader = tlsRecord.header  // 5 bytes
let nonce = try OpenSSL.AES.GCM.Nonce(data: computedNonce)
let sealedBox = try OpenSSL.AES.GCM.SealedBox(
    nonce: nonce,
    ciphertext: tlsRecord.encryptedPayload,
    tag: tlsRecord.authTag
)

let isValid = OpenSSL.AES.GCM.isAuthentic(
    sealedBox,
    using: trafficKey,
    authenticating: recordHeader
)

if isValid {
    print("TLS record is authentic")
}
```

### ChaCha20-Poly1305

```swift
// Same API, different cipher
let key = OpenSSL.SymmetricKey(size: .bits256)

let sealedBox = try OpenSSL.ChaChaPoly.seal(
    plaintext,
    using: key,
    authenticating: aad
)

let decrypted = try OpenSSL.ChaChaPoly.open(
    sealedBox,
    using: key,
    authenticating: aad
)
```

### From Combined Representation

```swift
// Parse from wire format (nonce || ciphertext || tag)
let sealedBox = try OpenSSL.AES.GCM.SealedBox(combined: wireData)

// Or from separate components
let sealedBox = try OpenSSL.AES.GCM.SealedBox(
    nonce: nonce,
    ciphertext: ciphertext,
    tag: tag
)
```

---

## OpenSSL Function Mapping

| Swift API | OpenSSL Functions |
|-----------|-------------------|
| `AES.GCM.seal` | `EVP_EncryptInit_ex(EVP_aes_256_gcm())`, `EVP_EncryptUpdate` (AAD), `EVP_EncryptUpdate` (plaintext), `EVP_EncryptFinal_ex`, `EVP_CIPHER_CTX_ctrl(EVP_CTRL_GCM_GET_TAG)` |
| `AES.GCM.open` | `EVP_DecryptInit_ex`, `EVP_DecryptUpdate` (AAD), `EVP_DecryptUpdate` (ciphertext), `EVP_CIPHER_CTX_ctrl(EVP_CTRL_GCM_SET_TAG)`, `EVP_DecryptFinal_ex` |
| `ChaChaPoly.seal` | `EVP_EncryptInit_ex(EVP_chacha20_poly1305())`, ... |
| `ChaChaPoly.open` | `EVP_DecryptInit_ex(EVP_chacha20_poly1305())`, ... |

### Key Size Selection (AES-GCM)

```c
// Select cipher based on key size
const EVP_CIPHER* cipher;
switch (key_bits) {
    case 128: cipher = EVP_aes_128_gcm(); break;
    case 192: cipher = EVP_aes_192_gcm(); break;
    case 256: cipher = EVP_aes_256_gcm(); break;
    default: return error;
}
```

---

## Implementation Notes

### Tag Size

- AES-GCM tag: 16 bytes (128 bits) — this is the standard and recommended size
- ChaCha20-Poly1305 tag: 16 bytes (128 bits)

### Nonce Reuse

**CRITICAL**: Never reuse a nonce with the same key. Nonce reuse completely breaks GCM security.

- If caller provides a nonce, use it
- If nonce is nil, generate a cryptographically random 12-byte nonce
- For TLS, nonces are derived from a sequence number (handled by caller)

### Error Cases

```swift
public enum OpenSSLError {
    // ... existing cases ...
    
    /// Authentication tag verification failed.
    case authenticationFailure
}
```

### Thread Safety

- All methods are static and stateless
- OpenSSL `EVP_CIPHER_CTX` is created per-call
- Fully `Sendable`

---

## File Structure

```
Sources/OpenSSL/
├── AEAD/
│   ├── AES-GCM.swift           # AES.GCM namespace and API
│   ├── ChaChaPoly.swift        # ChaChaPoly namespace and API
│   ├── Nonce.swift             # Shared nonce handling
│   └── SealedBox.swift         # Shared sealed box concept
└── (uses SymmetricKey from Keys/)
```
