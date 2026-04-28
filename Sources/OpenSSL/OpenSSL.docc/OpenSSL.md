# ``OpenSSL``

@Metadata {
    @TitleHeading("Framework")
}

Modern Swift bindings for OpenSSL 3.x cryptographic primitives and the foundational OpenSSL runtime used by other Swift packages requiring OpenSSL.

## Overview

`OpenSSL` is the idiomatic Swift face of this package. It wraps a vendored build of [OpenSSL 3.6.2](https://github.com/openssl/openssl) with a type-safe Swift 6.1 API that avoids leaking raw `OpaquePointer`s or `EVP_*` C handles through its public surface. The module runs on macOS 13+, iOS 16+, tvOS 16+, watchOS 9+, visionOS 1+, and Linux, and builds under Swift's strict concurrency (`swiftLanguageModes: [.v6]`).

Direct-use capabilities shipping today:

- **SHA-256** ([FIPS PUB 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final), [RFC 6234](https://datatracker.ietf.org/doc/html/rfc6234)) — 32-byte / 256-bit digests over `Data` or `String`, returning a typed ``SHA256/SHA256Digest``.
- **Base64URL** ([RFC 4648 §5](https://datatracker.ietf.org/doc/html/rfc4648#section-5)) — URL-safe unpadded encoding used by JWT ([RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)), JWS, WebAuthn, and Nostr NIP-19.
- **RSA PEM ingestion** (PKCS#1 / [RFC 8017](https://datatracker.ietf.org/doc/html/rfc8017), PKCS#8 / [RFC 5958](https://datatracker.ietf.org/doc/html/rfc5958)) — parse into ``RSA/PrivateKey`` and ``RSA/PublicKey`` typed values.
- **Runtime version auditing** — ``SSL/versionString`` reports the OpenSSL build linked into this package for CVE cross-referencing against the [OpenSSL security advisories](https://www.openssl.org/news/vulnerabilities.html).

```swift
let digest = SHA256.hash(string: "Hello, World!")
print(digest.hexString)
// dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f

print(SSL.versionString)
// OpenSSL 3.6.2 ...
```

### Foundation Runtime for Swift Network-Crypto Stacks

Beyond its direct API, this package ships the raw `libcrypto` and `libssl` C binding products that other Swift packages link against when they need a full OpenSSL runtime. The canonical example is [`swift-tor`](https://github.com/21-DOT-DEV/swift-tor), which depends on `swift-openssl` and `swift-event` (libevent bindings) to build a Swift-native Tor client; its `libtor` target lists `libcrypto` and `libssl` from this package as direct dependencies. Other packages requiring OpenSSL's C surface — certificate tooling, TLS relays, protocol bridges — can link the same runtime without duplicating it. See <doc:ChoosingLibcryptoVsOpenSSL> for product-selection guidance.

API positioning: `OpenSSL` complements [`swift-crypto`](https://github.com/apple/swift-crypto) and Apple's `CryptoKit`, not replaces them. Reach for `OpenSSL` when you need algorithms Apple's frameworks don't cover (full PKCS#1 padding, PEM I/O, legacy ciphers), when you need to interop with existing OpenSSL-based C/C++ code, or when you need to audit the exact OpenSSL version shipping with your binary.

### Where to start

New to `OpenSSL`? Begin with <doc:GettingStarted> for a task-oriented walkthrough of SHA-256 hashing, Base64URL encoding, RSA PEM parsing, and runtime version auditing. Picking between the idiomatic Swift API and the raw C binding products is covered in <doc:ChoosingLibcryptoVsOpenSSL>. Production-readiness caveats, disabled-algorithm rationale, and CVE-auditing guidance live in <doc:SecurityConsiderations>.

## Topics

### Guides

- <doc:GettingStarted>
- <doc:ChoosingLibcryptoVsOpenSSL>

### Concepts

- <doc:SecurityConsiderations>

### Essentials

- ``SSL``

### Hashing

- ``SHA256``
- ``SHA256/SHA256Digest``

### Encoding

- ``Base64URL``

### RSA

- ``RSA``
- ``RSA/PrivateKey``
- ``RSA/PublicKey``

### Errors

- ``OpenSSLError``
