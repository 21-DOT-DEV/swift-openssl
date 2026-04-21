# Security Considerations

@Metadata {
    @TitleHeading("Explanation")
}

Production-readiness caveats, MVP gaps, disabled algorithms, and runtime auditing guidance for `swift-openssl`. This article is the single source of truth for whether to depend on this package in a given threat model.

## Overview

> Warning: From [README.md](https://github.com/21-DOT-DEV/swift-openssl/blob/main/README.md): *"This package has not yet implemented cryptographic test vectors. Do not use in production until proper verification is in place."* The sections below describe the specific gaps that motivate that caution and the compensating controls available today.

### Pre-1.0 API Stability

The package is pre-1.0 and uses [SemVer major version zero](https://semver.org/#spec-item-4), which reserves `0.y.z` as *"anything may change at any time."* The README states this plainly: *"The public API should not be considered stable and may change with any release. Pin a version using `exact:` to avoid unexpected breaking changes."*

Practical consequences:

- Do **not** use `from:` or `upToNextMinor:` requirements in `Package.swift`. Pin `exact: "0.x.y"` until the package reaches 1.0.
- Inspect each upgrade. The observable behavior of ``OpenSSLError`` (including its associated `String` reasons) is part of the API contract for tests that pattern-match on it.
- When an upgrade changes a citation, a test vector, or the set of ``OpenSSLError`` cases produced on a code path, bump your own pin deliberately.

### MVP Scope and Missing Capabilities

Shipping today:

- ``SHA256/hash(data:)`` and ``SHA256/hash(string:)`` — functional, test-vector-matching against FIPS 180-4 canonical values.
- ``Base64URL/encode(_:)`` and ``Base64URL/decode(_:)`` — functional, RFC 4648 §5 compliant.
- ``RSA/PrivateKey/init(pemRepresentation:)`` and ``RSA/PublicKey/init(pemRepresentation:)`` — PEM frame validation only, no DER structural checks.
- ``SSL/versionString`` — functional, reports the runtime-linked `libcrypto` version.

Not shipping today (future work):

- **RSA signing and verification**. Requires the OpenSSL provider layer (`OSSL_PROVIDER_load`, `EVP_PKEY_sign_init`, `EVP_PKEY_verify_init`), which is not integrated. The README confirms: *"RSA signing and verification require the OpenSSL provider layer, which is not yet included. Key parsing is functional."*
- **TLS client or server context setup**. The `SSL` namespace exposes only ``SSL/versionString``. No session API, no context builder, no ALPN helpers.
- **X.509 certificate chain validation**.
- **HMAC, HKDF, AEAD, Ed25519, X25519, ECDH, ECDSA** Swift wrappers. `libcrypto` ships the C surface for these; no Swift API layer exists yet.
- **Key generation** for any algorithm family.
- **Algorithm-level test-vector validation** (see next section).

For algorithms Apple's frameworks already cover well — SHA-2, AES-GCM, ChaCha20-Poly1305, HKDF, Curve25519 — prefer [`swift-crypto`](https://github.com/apple/swift-crypto) or CryptoKit until this package grows the corresponding idiomatic surface.

### Cryptographic Test Vectors

The README `> [!CAUTION]` quoted above captures the core constraint: **cryptographic test vectors have not been integrated into the test suite.** This package's CI runs a small set of hand-picked digest and base64 vectors and negative tests on malformed PEM input; it does **not** run against [Project Wycheproof](https://github.com/google/wycheproof) or [NIST CAVP](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program) vector sets.

What this means for callers:

- SHA-256 output is independently verifiable against the short vectors in [RFC 6234 §8.5](https://datatracker.ietf.org/doc/html/rfc6234#section-8.5) and the FIPS 180-4 §A.1 empty-input digest. These are the test vectors this project relies on today.
- Any algorithm not already shipping behind a Swift API in `OpenSSL` is untested at the vector level *from this project*. The underlying `libcrypto` C code is upstream OpenSSL 3.6.2 — its own CI covers CAVP — but the Swift wrappers that will sit on top of it are not yet written, let alone validated.
- Project constitution Principle II requires published-vector validation (Wycheproof, NIST CAVP, RFC vectors) for every algorithm family before it is marked "tested." Phase 2 of the roadmap backfills SHA-256 coverage and adds HMAC / HKDF / AEAD as those APIs land.

Production users needing FIPS 140-3 validation should not treat this package as fulfilling that requirement; the Swift layer is out-of-scope for any upstream FIPS module validation.

### Disabled Algorithms

Multiple algorithms are intentionally disabled via both `subtree.yaml` extraction excludes and `OPENSSL_NO_*` defines in the generated `configuration.h`. Attempting to use them — even via the raw `libcrypto` C bindings — will fail to link. The list matches the README's disabled-algorithms table:

| Category | Algorithms | Rationale |
| --- | --- | --- |
| Legacy ciphers | RC5, RC2, IDEA, Blowfish, CAST, SEED, Camellia | Deprecated, rarely used |
| Legacy hashes | MDC2, Whirlpool, MD2, MD4, Blake2 | Deprecated or specialized |
| Regional standards | SM2, SM3, SM4, ARIA, GOST | Chinese/Korean/Russian national standards |
| Post-quantum | LMS, ML-DSA, ML-KEM, SLH-DSA | Experimental; increases binary size significantly |
| Platform-specific | `ec-nistp-64-gcc-128`, `padlockeng` | Require specific compiler or hardware |

Re-enabling an algorithm requires updating both places (subtree excludes and the Configure flag set) and running the full extraction recipe documented in the README. Do not patch one without the other.

### Constant-Time Comparison

``SHA256/SHA256Digest`` conforms to `Equatable` via Foundation's `Data` equality, which is **not** constant-time. Using `==` on two secret-derived digests leaks timing information proportional to the first differing byte.

Rules:

- Do not compare MAC tags, authenticator values, or any secret-derived digest with `==`.
- Use a constant-time comparison primitive from your HMAC or AEAD layer when available (CryptoKit's `HashedAuthenticationCode` values compare constant-time internally via Apple's implementation).
- When no such primitive is at hand, implement one: iterate byte-by-byte, accumulating `a[i] ^ b[i]` into an `UInt8` result, and check equality only on the aggregate. Never branch on intermediate results.

``Base64URL/encode(_:)`` and ``Base64URL/decode(_:)`` are also not constant-time: their running time depends on both input length and content. Do not pass secret-dependent material through them on side-channel-sensitive paths.

### PEM Parsing Limitations

``RSA/PrivateKey/init(pemRepresentation:)`` and ``RSA/PublicKey/init(pemRepresentation:)`` perform outer-frame validation only. Specifically:

- The input must be valid UTF-8.
- The input must contain both a `-----BEGIN` marker and the appropriate `PRIVATE KEY-----` or `PUBLIC KEY-----` marker.
- **The base64-encoded DER payload inside the PEM frame is not structurally validated.** A malformed SubjectPublicKeyInfo or PKCS#8 envelope will pass ingestion and surface as an error only once the provider layer lands and attempts to use the bytes.

Consumers that need structural validation today must decode and re-verify the DER themselves — typically by attempting a parse with a Swift ASN.1 library or by exporting to OpenSSL's CLI via `openssl asn1parse -inform PEM -in key.pem`. The PEM frame grammar itself is defined by [RFC 7468](https://datatracker.ietf.org/doc/html/rfc7468).

### Runtime OpenSSL Version Auditing

Every binary that ships this package carries a specific OpenSSL version statically compiled into `libcrypto`. Use ``SSL/versionString`` to report it at runtime, then cross-reference against the [OpenSSL security advisories](https://www.openssl.org/news/vulnerabilities.html) before cutting a release build.

```swift
import OpenSSL
print(SSL.versionString)
// OpenSSL 3.6.2 ...
```

Guidance:

- Run this check in a release-gate CI step that fails if the reported version falls below your minimum acceptable patch level.
- Transitive consumers (a package that depends on `swift-tor`, which depends on `swift-openssl`) inherit the same linked runtime and the same CVE surface. Audit the whole graph, not just your direct dependency.
- The version is compile-time baked, not load-time dynamic. A binary shipped with OpenSSL 3.6.2 stays at 3.6.2 until rebuilt against a newer vendored source tree.

### Reporting Vulnerabilities

Security issues in this package are handled per [`SECURITY.md`](https://github.com/21-DOT-DEV/swift-openssl/blob/main/SECURITY.md) and the umbrella [21-DOT-DEV security policy](https://github.com/21-DOT-DEV/.github/blob/main/SECURITY.md). Do not open public GitHub issues for suspected vulnerabilities — follow the private disclosure process documented in those files.

Vulnerabilities in upstream OpenSSL itself should be reported directly to [the OpenSSL project](https://openssl-library.org/policies/general-supporting-policies/vulnerabilities/); this package will pick them up via a subtree update once fixed upstream.
