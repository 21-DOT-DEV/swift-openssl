[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Apple Platforms](https://github.com/21-DOT-DEV/swift-openssl/actions/workflows/apple-builds.yml/badge.svg)](https://github.com/21-DOT-DEV/swift-openssl/actions/workflows/apple-builds.yml)
[![Docker Builds](https://github.com/21-DOT-DEV/swift-openssl/actions/workflows/docker-builds.yml/badge.svg)](https://github.com/21-DOT-DEV/swift-openssl/actions/workflows/docker-builds.yml)

# 🗝️ swift-openssl

Modern Swift bindings for [OpenSSL 3.x](https://github.com/openssl/openssl) — a type-safe Swift 6.1 API for SHA-256, Base64URL, and RSA, plus raw `libcrypto` and `libssl` products other Swift packages can link for a full OpenSSL runtime.

> [!CAUTION]
> Pre-1.0 and cryptographic test vectors are not yet integrated. Do not use in production until proper verification is in place. See the [Security Considerations](Sources/OpenSSL/OpenSSL.docc/SecurityConsiderations.md) guide for the full MVP-gap list.

## Why swift-openssl?

`OpenSSL` complements — rather than replaces — [swift-crypto](https://github.com/apple/swift-crypto) and Apple's CryptoKit. Reach for this package when you need algorithms Apple's frameworks don't cover (PKCS#1 padding variants, PEM I/O, Base64URL with the JOSE alphabet), when you need to interop with existing OpenSSL-based C/C++ code, or when you need to audit the exact OpenSSL version shipping with your binary. For packages like [swift-tor](https://github.com/21-DOT-DEV/swift-tor) that embed C code calling `EVP_*` / `SSL_*` symbols, the raw `libcrypto` and `libssl` products provide a statically linked, vendor-controlled runtime.

## Features

- **Modern Swift API** for SHA-256 ([FIPS 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final)), Base64URL ([RFC 4648 §5](https://datatracker.ietf.org/doc/html/rfc4648#section-5)), and RSA PEM ingestion (PKCS#1 / PKCS#8).
- **Raw `libcrypto` and `libssl` C bindings** for Swift packages that need a full OpenSSL runtime — used by [swift-tor](https://github.com/21-DOT-DEV/swift-tor) for its Tor daemon.
- **OpenSSL 3.6.2 statically vendored** via [subtree](https://github.com/21-DOT-DEV/subtree) — no system OpenSSL dependency at runtime.
- **Swift 6.1 strict concurrency**, `Sendable` throughout, zero raw `OpaquePointer` leakage in the public API.
- **Apple platforms + Linux**: macOS 13+, iOS 16+, tvOS 16+, watchOS 9+, visionOS 1+, Ubuntu 22.04+.

## Installation

Add the package to your `Package.swift`:

```swift
.package(url: "https://github.com/21-DOT-DEV/swift-openssl.git", exact: "0.1.0"),
```

> [!WARNING]
> Pin with `exact:` while the package is pre-1.0 ([SemVer major version zero](https://semver.org/#spec-item-4) reserves this range as "anything may change at any time").

Include `OpenSSL` in your target:

```swift
.target(name: "<target>", dependencies: [
    .product(name: "OpenSSL", package: "swift-openssl"),
]),
```

Or use Xcode: **File → Add Packages…**, then enter `https://github.com/21-DOT-DEV/swift-openssl`.

## Quick Start

```swift
import OpenSSL

let digest = SHA256.hash(string: "Hello, World!")
print(digest.hexString)
// dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f
```

For **Base64URL encoding**, **RSA PEM parsing**, **runtime version auditing**, and the **product-selection guide** (`OpenSSL` vs `libcrypto` vs `libssl`), see the DocC catalog under [`Sources/OpenSSL/OpenSSL.docc/`](Sources/OpenSSL/OpenSSL.docc/) — start with [Getting Started](Sources/OpenSSL/OpenSSL.docc/GettingStarted.md). Every example there is backed by an executable SwiftPM snippet and a test, so nothing drifts from the code. Build the full hyperlinked archive locally with `swift package generate-documentation --target OpenSSL`.

## Requirements

| Tool | Minimum version |
| --- | --- |
| Swift | 6.1 |
| Xcode | 16.3 |
| macOS | 13 |
| iOS / iPadOS | 16 |
| tvOS | 16 |
| watchOS | 9 |
| visionOS | 1 |
| Linux | Ubuntu 22.04+ (glibc) |

## Contributing

Bug reports and pull requests are welcome. Start with:

- [AGENTS.md](AGENTS.md) — project architecture, Swift-target boundaries, extraction flow.
- [Vendor/AGENTS.md](Vendor/AGENTS.md) — OpenSSL subtree sync rules and the Configure regeneration recipe for minor/major bumps.
- [21-DOT-DEV contributing guidelines](https://github.com/21-DOT-DEV/.github/blob/main/CONTRIBUTING.md) — branching and commit conventions.

## Security

For vulnerability reports, follow the private-disclosure process in [SECURITY.md](SECURITY.md). For shipped-today security caveats — MVP gaps, disabled algorithms, constant-time-comparison rules, and runtime CVE auditing — see the [Security Considerations](Sources/OpenSSL/OpenSSL.docc/SecurityConsiderations.md) guide.

## License

Released under the MIT License — see [LICENSE](LICENSE). OpenSSL itself is licensed under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).
