[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

# 🗝️ swift-openssl

Swift package providing OpenSSL cryptographic functionality with modern Swift APIs. Uses Swift's C interoperability with [OpenSSL](https://github.com/openssl/openssl).

## Contents

- [Features](#features)
- [Installation](#installation)
- [Usage Examples](#usage-examples)
- [Development](#development)
- [Security](#security)
- [Contributing](#contributing)
- [License](#license)

## Features

- Provide modern Swift bindings for OpenSSL cryptographic operations
- Offer a familiar API design inspired by [Swift Crypto](https://github.com/apple/swift-crypto)
- Expose libcrypto and libssl bindings for full control of the implementation
- Ensure availability for Linux and Apple platform ecosystems
- Maintain automatic updates for Swift and OpenSSL versions

## Installation

This package uses Swift Package Manager. To add it to your project:

### Using Xcode

1. Go to `File > Add Packages...`
2. Enter the package URL: `https://github.com/21-DOT-DEV/swift-openssl`
3. Select the desired version

### Using Package.swift (Recommended)

Add the following to your `Package.swift` file:

```swift
.package(url: "https://github.com/21-DOT-DEV/swift-openssl.git", from: "0.1.0"),
```

> [!WARNING]
> This package is pre-1.0 ([SemVer major version zero](https://semver.org/#spec-item-4)). The public API should not be considered stable and may change with any release. Pin a version using `exact:` to avoid unexpected breaking changes.

Then, include `OpenSSL` as a dependency in your target:

```swift
.target(name: "<target>", dependencies: [
    .product(name: "OpenSSL", package: "swift-openssl")
]),
```

## Usage Examples

> [!CAUTION]
> This package has not yet implemented cryptographic test vectors. Do not use in production until proper verification is in place.

### SHA-256 Hashing

```swift
import OpenSSL

// Hash data
let data = "Hello, World!".data(using: .utf8)!
let digest = SHA256.hash(data: data)
print(digest.hexString)

// Hash string directly
let stringDigest = SHA256.hash(string: "Hello, World!")
print(stringDigest.hexString)
```

### Base64URL Encoding

```swift
import OpenSSL

// Encode data as base64url (useful for JWT)
let data = "Hello, World!".data(using: .utf8)!
let encoded = Base64URL.encode(data)
print(encoded)

// Decode base64url string
if let decoded = Base64URL.decode(encoded) {
    print(String(data: decoded, encoding: .utf8)!)
}
```

### RSA Key Parsing

```swift
import OpenSSL

let privateKeyPEM = """
-----BEGIN RSA PRIVATE KEY-----
...
-----END RSA PRIVATE KEY-----
"""

// Parse PEM-encoded keys
let privateKey = try RSA.PrivateKey(pemRepresentation: privateKeyPEM)
print(privateKey.pemData)
```

> [!NOTE]
> RSA signing and verification require the OpenSSL provider layer, which is not yet included. Key parsing is functional.

### OpenSSL Version

```swift
import OpenSSL

// Get the OpenSSL version string
print(SSL.versionString)
```

## Development

### Requirements

- Swift 6.1+
- macOS 13+, iOS 16+, tvOS 16+, watchOS 9+, visionOS 1+

### Updating OpenSSL Version

OpenSSL is vendored via git subtree. Update procedure depends on the release scale:

#### Minimal recipe (patch releases — e.g., `3.6.0` → `3.6.2`)

```bash
# 1. Bump the subtree to a new tag (updates subtree.yaml + commits Vendor with git-subtree-* trailers)
swift package --build-path .build/subtree \
  --allow-writing-to-package-directory \
  --allow-network-connections all \
  subtree update openssl --ref openssl-3.6.2

# 2. Re-extract (--force overwrites previously-extracted sources)
swift package --build-path .build/subtree \
  --allow-writing-to-package-directory \
  subtree extract --name openssl --force

# 3. Verify
swift build && swift test
```

If step 3 is green, you're done. The Configure-generated files already under `Sources/libcrypto/` survive because we skip `--clean`.

#### Full recipe (minor/major bumps, or when `swift build` fails)

Patch releases can still change Configure `.h.in` templates (e.g., new `OSSL_CMP_PKISTATUS_*` constants in 3.6.2). If step 3 above fails with missing identifiers, run the full Configure dance:

```bash
# Regenerate Configure outputs
cd Vendor/openssl
./Configure darwin64-arm64-cc no-asm no-shared no-apps no-docs no-tests \
    no-rc5 no-rc2 no-idea no-bf no-cast no-seed no-camellia \
    no-mdc2 no-whirlpool no-md2 no-md4 \
    no-sm2 no-sm3 no-sm4 no-aria no-gost no-blake2 \
    no-lms no-ml-dsa no-ml-kem no-slh-dsa \
    no-ec_nistp_64_gcc_128 no-padlockeng
make build_all_generated
cd ../..

# Re-extract to pick up regenerated .h and generated .c files
swift package --build-path .build/subtree \
  --allow-writing-to-package-directory \
  subtree extract --name openssl --force

# Clean Vendor (IMPORTANT — generated files must NOT be committed to Vendor/)
( cd Vendor/openssl && make distclean )

# Verify
swift build && swift test
```

**Configure-generated files** (live under `Sources/libcrypto/`, NOT in upstream `Vendor/openssl/`):

- `include/openssl/configuration.h` — build configuration + `OPENSSL_NO_*` defines
- `include/openssl/*.h` from `.h.in` templates — `cmp.h`, `ssl.h`, `asn1.h`, `bio.h`, `x509.h`, etc.
- `internal_include/crypto/buildinf.h` — build info (compiler, date, platform)
- `providers/providers/fips/include/fips/fipsindicator.h` — FIPS indicator macros
- Provider `.c` files generated from `.c.in` templates

**Disabled algorithms:**
| Category | Algorithms | Rationale |
|----------|------------|-----------|
| Legacy ciphers | RC5, RC2, IDEA, BF, CAST, SEED, Camellia | Deprecated, rarely used |
| Legacy hashes | MDC2, Whirlpool, MD2, MD4, Blake2 | Deprecated or specialized |
| Regional standards | SM2, SM3, SM4, ARIA, GOST | Chinese/Korean/Russian standards |
| Post-quantum | LMS, ML-DSA, ML-KEM, SLH-DSA | Experimental, increases binary size |
| Platform-specific | ec-nistp-64-gcc-128, padlockeng | Requires specific compiler/hardware |

**Important:** Always run `make distclean` after extraction. Generated files must NOT be committed to `Vendor/openssl/` as they will conflict with subtree operations.

### Project Structure

```
Sources/
├── OpenSSL/           # Swift wrapper API
├── libcrypto/         # OpenSSL crypto library (extracted + generated)
│   ├── crypto/        # Core crypto sources
│   ├── include/       # Public headers (openssl/*.h)
│   ├── internal_include/  # Internal headers (crypto/*.h, internal/*.h)
│   └── providers/     # Provider headers
└── libssl/            # OpenSSL SSL/TLS library (extracted)
    ├── src/           # SSL sources
    └── include/       # SSL headers
```

## Security

For information on reporting security vulnerabilities, see [SECURITY.md](SECURITY.md).

## Contributing

Contributions are welcome. Please read the [21-DOT-DEV contributing guidelines](https://github.com/21-DOT-DEV/.github/blob/main/CONTRIBUTING.md) for branching and commit guidelines. For AI-assisted development guidance, see [AGENTS.md](AGENTS.md).

## License

This project is released under the MIT License. See [LICENSE](LICENSE) for details.

OpenSSL is licensed under the Apache License 2.0.