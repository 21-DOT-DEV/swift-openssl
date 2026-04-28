# Getting Started with OpenSSL in Swift

@Metadata {
    @TitleHeading("Article")
}

A task-oriented walkthrough of the four shipping capabilities in `OpenSSL`: SHA-256 hashing, Base64URL encoding, RSA PEM ingestion, and runtime version auditing.

## Overview

Each section below solves one concrete task. All executable examples come from files under `Snippets/` that compile on every `swift build`, so the code you see here stays in lock-step with the public API.

### Adding OpenSSL to Your Project

Add `swift-openssl` as a Swift Package Manager dependency. Because the package is pre-1.0, pin an exact version to avoid unexpected breaking changes when resolving ([SemVer major version zero](https://semver.org/#spec-item-4) reserves this as the "anything may change at any time" range):

```swift
// Package.swift
.package(url: "https://github.com/21-DOT-DEV/swift-openssl.git", exact: "0.1.0"),
```

```swift
// Target dependencies
.target(name: "<target>", dependencies: [
    .product(name: "OpenSSL", package: "swift-openssl"),
]),
```

Then `import OpenSSL` in any Swift file that needs it. For the raw `libcrypto` and `libssl` C binding products (used when linking OpenSSL into another Swift package that exposes its own C sources), see <doc:ChoosingLibcryptoVsOpenSSL>. For production-readiness caveats before depending on the package, read <doc:SecurityConsiderations> — vulnerability reports go through [`SECURITY.md`](https://github.com/21-DOT-DEV/swift-openssl/blob/main/SECURITY.md).

### Computing a SHA-256 Digest

[FIPS PUB 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final) SHA-256 produces a fixed 32-byte digest. The Swift API exposes two entry points — one for arbitrary bytes (``SHA256/hash(data:)``) and one for UTF-8 strings (``SHA256/hash(string:)``) — both returning a typed ``SHA256/SHA256Digest`` with a ``SHA256/SHA256Digest/hexString`` accessor that matches the canonical lowercase hex representation used in JWT fingerprints, Nostr NIP-01 event IDs, and Git-style blob hashes.

@Snippet(path: "swift-openssl/Snippets/BasicHashing")

Use ``SHA256/hash(data:)`` whenever the input is already a `Data` value — it is byte-exact and matches every [RFC 6234 §8.5](https://datatracker.ietf.org/doc/html/rfc6234#section-8.5) test vector. Reach for ``SHA256/hash(string:)`` only when hashing Swift strings directly; remember that it hashes the UTF-8 byte sequence, so Unicode-normalization differences change the digest (see the `> Warning:` on ``SHA256/hash(string:)``).

### Encoding and Decoding Base64URL

Base64URL, defined in [RFC 4648 §5](https://datatracker.ietf.org/doc/html/rfc4648#section-5), is the URL-safe unpadded encoding used by JSON Web Tokens ([RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)), JSON Web Signatures ([RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515)), WebAuthn credential blobs, and Nostr NIP-19 identifiers. The alphabet replaces `+` with `-` and `/` with `_` relative to standard Base64, and strips the `=` padding — producing strings that can be dropped into URL path segments, query parameters, HTTP headers, and filename components without escaping.

@Snippet(path: "swift-openssl/Snippets/Base64URLRoundTrip")

``Base64URL/encode(_:)`` never emits `+`, `/`, or `=`; ``Base64URL/decode(_:)`` accepts both padded and unpadded inputs and returns `nil` on malformed text rather than throwing.

### Parsing RSA Keys from PEM

> Warning: **Signing and verification are not yet functional.** The steps below parse PEM key material and round-trip it through typed ``RSA/PrivateKey`` / ``RSA/PublicKey`` values, but they cannot produce or verify signatures. That path requires the OpenSSL provider layer, which is not integrated in this MVP. See <doc:SecurityConsiderations> for the complete MVP gap list.

`OpenSSL` accepts PEM-encoded RSA keys in the traditional PKCS#1 framing ([RFC 8017](https://datatracker.ietf.org/doc/html/rfc8017)) and the modern PKCS#8 framing ([RFC 5958](https://datatracker.ietf.org/doc/html/rfc5958), encoded per [RFC 7468](https://datatracker.ietf.org/doc/html/rfc7468)). Public keys must use the SubjectPublicKeyInfo (SPKI) form, `-----BEGIN PUBLIC KEY-----` from [RFC 5280 §4.1.2.7](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.7); the legacy PKCS#1 public framing is not accepted — convert with `openssl rsa -RSAPublicKey_in -pubout` first.

@Snippet(path: "swift-openssl/Snippets/ParsingPEMKeys")

Parsing succeeds when the outer PEM frame is intact; the underlying DER is not structurally validated until the provider layer lands. Use ``RSA/PrivateKey/pemData`` and ``RSA/PublicKey/pemData`` to round-trip the original bytes to storage.

### Auditing the Runtime OpenSSL Version

``SSL/versionString`` exposes the value of [`OpenSSL_version(OPENSSL_VERSION)`](https://docs.openssl.org/3.6/man3/OpenSSL_version/) from the `libcrypto` runtime compiled into this package. Cross-reference the major/minor/patch triple against the [OpenSSL security advisories](https://www.openssl.org/news/vulnerabilities.html) before cutting a release build — the string is the canonical way to tell which CVE surface your deployed binary carries. Runtime auditing applies equally to transitive consumers: a package that depends on `swift-tor`, which depends on `swift-openssl`, sees the same linked runtime.

@Snippet(path: "swift-openssl/Snippets/AuditingRuntimeVersion")

### When to Reach for OpenSSL Instead of CryptoKit

`OpenSSL` complements [`swift-crypto`](https://github.com/apple/swift-crypto) and Apple's CryptoKit rather than replacing them. Use this decision table:

| Use case | Framework |
| --- | --- |
| SHA-256 / SHA-2 family, AES-GCM, ChaCha20-Poly1305, HKDF, Curve25519 | `swift-crypto` / CryptoKit |
| RSA with explicit PKCS#1 v1.5 or PSS padding | `OpenSSL` (post-provider integration) |
| PEM parsing and round-tripping | `OpenSSL` |
| Base64URL encoding with JOSE-compliant alphabet | `OpenSSL` |
| Legacy ciphers (AES-CBC with custom IV, DES variants) | `OpenSSL` |
| Runtime OpenSSL version auditing | `OpenSSL` |
| TLS client or server from scratch | [`swift-nio-ssl`](https://github.com/apple/swift-nio-ssl) |
| Interop with existing OpenSSL-based C or C++ code | `libcrypto` / `libssl` (this package) |

### Using swift-openssl as a Runtime Dependency

Other Swift packages can consume `libcrypto` and `libssl` from this package directly without going through the `OpenSSL` Swift API. The canonical example is [`swift-tor`](https://github.com/21-DOT-DEV/swift-tor), which declares `swift-openssl` as a branch-pinned dependency and wires `libcrypto` and `libssl` into its `libtor` target:

```swift
// From swift-tor's Package.swift
dependencies: [
    .package(url: "https://github.com/21-DOT-DEV/swift-openssl.git", branch: "main"),
    .package(url: "https://github.com/21-DOT-DEV/swift-event.git", branch: "main"),
],
targets: [
    .target(
        name: "libtor",
        dependencies: [
            .product(name: "libcrypto", package: "swift-openssl"),
            .product(name: "libssl", package: "swift-openssl"),
            .product(name: "libevent", package: "swift-event"),
        ],
        // ...
    ),
],
```

This pattern is the intended way to bring a full OpenSSL runtime into a Swift package that has its own C sources (Tor's event-driven networking, for example) without bundling duplicate OpenSSL builds across the dependency graph. See <doc:ChoosingLibcryptoVsOpenSSL> for the full product-selection rationale.

## See Also

- <doc:SecurityConsiderations>
- <doc:ChoosingLibcryptoVsOpenSSL>
- ``OpenSSLError``
