# Choosing Between OpenSSL, libcrypto, and libssl

@Metadata {
    @TitleHeading("Explanation")
}

This package ships three library products — which one should you link? This article covers the decision boundary, the canonical consumer example (`swift-tor`), and the stability guarantees that differ between the idiomatic Swift API and the raw C bindings.

## Overview

This article walks the decision boundary product-by-product, covers the canonical `swift-tor` consumption pattern, explains the differing stability guarantees, and closes with how the three products compose inside a single binary.

### The Three Products

`Package.swift` defines three public library products:

- **`OpenSSL`** — the idiomatic Swift API (`SHA256`, ``RSA``, ``SSL``, ``Base64URL``, ``OpenSSLError``). Type-safe, `Sendable` throughout, no raw C pointers in the public surface.
- **`libcrypto`** — raw C bindings to OpenSSL's crypto library (ciphers, digests, PKI primitives, random number generation, X.509 parsing at the C level).
- **`libssl`** — raw C bindings to OpenSSL's SSL/TLS library (protocol state machines, record layer, QUIC primitives at the C level).

All three share a single statically linked copy of upstream OpenSSL 3.6.2. A binary that imports `OpenSSL`, `libcrypto`, and `libssl` in different targets pulls in one runtime, not three.

From `Package.swift`:

```swift
products: [
    // WARNING: These APIs should not be considered stable and may change at any time.
    .library(name: "libcrypto", targets: ["libcrypto"]),
    .library(name: "libssl", targets: ["libssl"]),
    .library(name: "OpenSSL", targets: ["OpenSSL"])
],
```

That `WARNING` comment is deliberate: it applies to all three products while the package is pre-1.0, but the `libcrypto` and `libssl` products will *continue* to track upstream OpenSSL's C ABI even after `OpenSSL` reaches 1.0 — see [Stability Guarantees](#Stability-Guarantees) below.

### When to Import `OpenSSL`

Default choice for Swift callers. Import `OpenSSL` when:

- You want a type-safe, `Sendable` API with no raw `OpaquePointer` or `EVP_PKEY *` leakage.
- You need algorithms or utilities Apple's frameworks don't cover well — full PKCS#1 padding variants (post-provider integration), PEM I/O, Base64URL with the JOSE alphabet, or runtime OpenSSL version auditing.
- You want your code to compile against Swift 6.1 strict concurrency without `unchecked Sendable` escape hatches.
- You're writing application code rather than a dependency that re-exports a C runtime.

The `OpenSSL` surface is deliberately narrower than upstream's. It complements [`swift-crypto`](https://github.com/apple/swift-crypto) (Apple's portable CryptoKit-compatible implementation) — `swift-crypto` wins for SHA-2, HKDF, AES-GCM, ChaCha20-Poly1305, and Curve25519; `OpenSSL` wins for RSA with explicit padding, PEM I/O, and interop with OpenSSL-based C/C++ code. Choose both in the same target when your workload spans both sets.

### When to Import `libcrypto` Directly

Reach for the raw C bindings when:

- You need an algorithm or function that the `OpenSSL` Swift API hasn't wrapped yet (e.g. `EVP_CIPHER`-based AES-CBC, `RAND_bytes`, `X509_STORE`).
- You're bridging existing C or C++ code that already uses OpenSSL's API — exposing the same symbols to Swift via `libcrypto` avoids duplicating the runtime.
- You're building another Swift package that needs a full OpenSSL runtime to back its own C sources.

**Canonical example**: [`swift-tor`](https://github.com/21-DOT-DEV/swift-tor) links both `libcrypto` and `libssl` from this package. Its `libtor` target vendors the Tor source tree — which is C code that calls `EVP_*`, `RSA_*`, `EC_*`, and `SSL_*` routines — and resolves those symbols through these products rather than system OpenSSL, ensuring the Tor library uses the same statically-linked, vendor-controlled OpenSSL version that the rest of the dependency graph sees. The relevant declarations in `swift-tor`'s `Package.swift`:

```swift
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

This is the intended consumption pattern for packages that need OpenSSL as a runtime substrate rather than as a Swift API.

### When to Import `libssl` Directly

Reach for `libssl` when you need TLS or DTLS protocol primitives that the Swift-level `SSL` namespace hasn't wrapped yet — session setup (`SSL_CTX_new`, `SSL_new`), certificate verification callbacks, custom ALPN selection, or lower-level record-layer access. The concept surface is documented upstream at [`ssl(7)`](https://docs.openssl.org/3.6/man7/ssl/).

Theoretical compatibility note: [`swift-nio-ssl`](https://github.com/apple/swift-nio-ssl) ships its own `BoringSSL`-based C target and describes itself as designed to work with OpenSSL-compatible libraries generally. This package's `libssl` is structurally in the same category (OpenSSL 3.x's `libssl` C ABI), though **integration with `swift-nio-ssl` has not been verified in this project** — treat it as a theoretical combination rather than a tested one.

### Stability Guarantees

The package-level "pre-1.0" warning applies differently to each product:

- **`OpenSSL` (Swift API)**: Pre-1.0 ([SemVer `0.y.z`](https://semver.org/#spec-item-4)). The public surface — type names, function signatures, the set of ``OpenSSLError`` cases — may change across `0.y.z` releases. Pin `exact:` and audit each upgrade. The path to 1.0 hardens this surface.
- **`libcrypto` and `libssl` (C bindings)**: Stable *relative to upstream OpenSSL 3.x's own C ABI*. If upstream OpenSSL 3.7 renames or removes a function, this package will pass that change through. If upstream keeps a function stable, so does this package. The version pin is in `subtree.yaml` (currently `openssl-3.6.2`); updating it follows the extraction recipe in [`Vendor/AGENTS.md`](https://github.com/21-DOT-DEV/swift-openssl/blob/main/Vendor/AGENTS.md).

Consumers of `libcrypto`/`libssl` (like `swift-tor`) inherit the OpenSSL 3.x stability contract directly. Consumers of `OpenSSL` (like an application importing the Swift API) inherit this package's own pre-1.0 policy on top.

### Mixing Products

A single target can import any combination of `OpenSSL`, `libcrypto`, and `libssl` without runtime duplication. Because all three resolve to the same statically-linked OpenSSL, there is exactly one copy of the global `CRYPTO_*` state machinery in the final binary.

Transitive consumers behave the same way. An application that depends on `swift-tor` (which pulls in `libcrypto` and `libssl` from this package) and separately imports `OpenSSL` to hash a payload will see one OpenSSL runtime, not two. The ``SSL/versionString`` reported from the Swift side is identical to the version `libtor` is calling internally — which makes runtime CVE auditing (see <doc:SecurityConsiderations>) sound across the whole graph.

## See Also

- <doc:GettingStarted>
- <doc:SecurityConsiderations>
- ``OpenSSL``
