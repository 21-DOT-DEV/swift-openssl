# HKDF Specification

> **Parent:** [overview.md](overview.md)  
> **Status:** Draft  
> **Priority:** 2 (Foundation)

## Overview

HKDF (HMAC-based Key Derivation Function) per RFC 5869 for deriving cryptographic keys from input key material. API matches swift-crypto's `HKDF<H: HashFunction>` pattern.

---

## Namespace

```swift
extension OpenSSL {
    /// HKDF (HMAC-based Key Derivation Function) operations.
    /// Implements RFC 5869.
    public struct HKDF<H: HashFunction>: Sendable {}
}
```

---

## Types

Uses types from HMAC spec:
- `OpenSSL.SymmetricKey`
- `OpenSSL.HashedAuthenticationCode<H>`
- `OpenSSL.HashFunction` protocol

---

## API

### One-Shot Key Derivation

```swift
extension OpenSSL.HKDF {
    /// Derives a symmetric key from input key material.
    ///
    /// This is the recommended API for most use cases. It performs both
    /// extract and expand in a single call.
    ///
    /// - Parameters:
    ///   - inputKeyMaterial: The main key or passcode to derive from.
    ///   - salt: Optional salt value (recommended for security).
    ///   - info: Optional context/application-specific info.
    ///   - outputByteCount: The desired output key length in bytes.
    /// - Returns: The derived symmetric key.
    public static func deriveKey<Salt: DataProtocol, Info: DataProtocol>(
        inputKeyMaterial: SymmetricKey,
        salt: Salt,
        info: Info,
        outputByteCount: Int
    ) -> SymmetricKey
    
    /// Derives a symmetric key with info but no salt.
    public static func deriveKey<Info: DataProtocol>(
        inputKeyMaterial: SymmetricKey,
        info: Info,
        outputByteCount: Int
    ) -> SymmetricKey
    
    /// Derives a symmetric key with salt but no info.
    public static func deriveKey<Salt: DataProtocol>(
        inputKeyMaterial: SymmetricKey,
        salt: Salt,
        outputByteCount: Int
    ) -> SymmetricKey
    
    /// Derives a symmetric key with no salt or info.
    public static func deriveKey(
        inputKeyMaterial: SymmetricKey,
        outputByteCount: Int
    ) -> SymmetricKey
}
```

### Extract-Then-Expand (Fine-Grained Control)

```swift
extension OpenSSL.HKDF {
    /// Extracts a pseudorandom key from input key material.
    ///
    /// The output can be used with `expand(pseudoRandomKey:info:outputByteCount:)`
    /// to generate multiple derived keys from the same PRK.
    ///
    /// - Parameters:
    ///   - inputKeyMaterial: The main key or passcode.
    ///   - salt: Optional salt value. If nil, uses a string of zeros.
    /// - Returns: A pseudorandom key as a hashed authentication code.
    public static func extract<Salt: DataProtocol>(
        inputKeyMaterial: SymmetricKey,
        salt: Salt?
    ) -> HashedAuthenticationCode<H>
    
    /// Expands a pseudorandom key into output key material.
    ///
    /// - Parameters:
    ///   - prk: The pseudorandom key from `extract`.
    ///   - info: Optional context/application-specific info.
    ///   - outputByteCount: The desired output length in bytes.
    /// - Returns: The derived symmetric key.
    public static func expand<PRK: ContiguousBytes, Info: DataProtocol>(
        pseudoRandomKey prk: PRK,
        info: Info?,
        outputByteCount: Int
    ) -> SymmetricKey
}
```

---

## Usage Examples

### Basic Key Derivation

```swift
import OpenSSL

// Derive a 32-byte key from a password
let password = OpenSSL.SymmetricKey(data: "my-secret-password".utf8)
let salt = Data("random-salt-value".utf8)
let info = Data("my-app-context".utf8)

let derivedKey = OpenSSL.HKDF<OpenSSL.SHA256>.deriveKey(
    inputKeyMaterial: password,
    salt: salt,
    info: info,
    outputByteCount: 32
)
```

### Derive Multiple Keys from Same Source

```swift
// Extract once
let prk = OpenSSL.HKDF<OpenSSL.SHA256>.extract(
    inputKeyMaterial: sharedSecret,
    salt: salt
)

// Expand to different keys for different purposes
let encryptionKey = OpenSSL.HKDF<OpenSSL.SHA256>.expand(
    pseudoRandomKey: prk,
    info: Data("encryption".utf8),
    outputByteCount: 32
)

let authenticationKey = OpenSSL.HKDF<OpenSSL.SHA256>.expand(
    pseudoRandomKey: prk,
    info: Data("authentication".utf8),
    outputByteCount: 32
)
```

### TLS-Style Key Derivation

```swift
// For TLS 1.3, the caller builds the labeled info manually
func tls13ExpandLabel(
    secret: SymmetricKey,
    label: String,
    context: Data,
    length: Int
) -> SymmetricKey {
    // Build TLS 1.3 HkdfLabel structure
    var info = Data()
    info.append(contentsOf: withUnsafeBytes(of: UInt16(length).bigEndian) { Array($0) })
    let labelBytes = Data("tls13 \(label)".utf8)
    info.append(UInt8(labelBytes.count))
    info.append(labelBytes)
    info.append(UInt8(context.count))
    info.append(context)
    
    return OpenSSL.HKDF<OpenSSL.SHA256>.expand(
        pseudoRandomKey: secret,
        info: info,
        outputByteCount: length
    )
}

// Usage
let clientSecret = tls13ExpandLabel(
    secret: handshakeSecret,
    label: "c hs traffic",
    context: transcriptHash,
    length: 32
)
```

### Different Hash Functions

```swift
// HKDF-SHA384 (for TLS 1.3 with SHA384 cipher suites)
let key384 = OpenSSL.HKDF<OpenSSL.SHA384>.deriveKey(
    inputKeyMaterial: ikm,
    salt: salt,
    info: info,
    outputByteCount: 48
)

// HKDF-SHA512
let key512 = OpenSSL.HKDF<OpenSSL.SHA512>.deriveKey(
    inputKeyMaterial: ikm,
    salt: salt,
    info: info,
    outputByteCount: 64
)
```

---

## OpenSSL Function Mapping

| Swift API | OpenSSL Functions |
|-----------|-------------------|
| `deriveKey(...)` | `EVP_KDF_fetch("HKDF")`, `EVP_KDF_CTX_new`, `EVP_KDF_derive` with mode `EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND` |
| `extract(...)` | `EVP_KDF_derive` with mode `EVP_KDF_HKDF_MODE_EXTRACT_ONLY` |
| `expand(...)` | `EVP_KDF_derive` with mode `EVP_KDF_HKDF_MODE_EXPAND_ONLY` |

### EVP_KDF Parameters

```c
// Set parameters for HKDF
OSSL_PARAM params[] = {
    OSSL_PARAM_utf8_string("digest", "SHA256", 0),
    OSSL_PARAM_utf8_string("mode", "EXTRACT_AND_EXPAND", 0),
    OSSL_PARAM_octet_string("key", ikm, ikm_len),
    OSSL_PARAM_octet_string("salt", salt, salt_len),
    OSSL_PARAM_octet_string("info", info, info_len),
    OSSL_PARAM_END
};

EVP_KDF_derive(kctx, out, out_len, params);
```

---

## Implementation Notes

### Output Length Limits

- Maximum output length: `255 * H.digestByteCount` bytes
- For SHA-256: 255 × 32 = 8,160 bytes max
- For SHA-384: 255 × 48 = 12,240 bytes max
- Requesting more should throw `OpenSSLError.invalidInput`

### Salt Handling

- If salt is `nil` or empty, use a string of `H.digestByteCount` zero bytes
- This matches RFC 5869 specification

### PRK Type

- `extract()` returns `HashedAuthenticationCode<H>` (same as HMAC output)
- This type conforms to `ContiguousBytes`, so it can be passed directly to `expand()`

### Thread Safety

- All methods are static and stateless
- OpenSSL `EVP_KDF_CTX` is created per-call
- Fully `Sendable`

---

## File Structure

```
Sources/OpenSSL/
├── KDF/
│   └── HKDF.swift              # HKDF<H> type with all methods
└── (uses types from HMAC/)
```
