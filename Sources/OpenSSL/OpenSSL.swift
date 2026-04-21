//
//  OpenSSL.swift
//  21-DOT-DEV/swift-openssl
//
//  Copyright (c) 2026 Timechain Software Initiative, Inc.
//  Distributed under the MIT software license
//
//  See the accompanying file LICENSE for information
//

import Foundation
import libcrypto
import libssl

/// Namespace for RSA cryptographic types backed by OpenSSL.
///
/// `RSA` groups the Swift types that represent RSA keys and, in future
/// releases, signing and verification operations. The namespace is a
/// caseless enum so it cannot be instantiated; all members are nested
/// types or static functions.
///
/// The currently shipping surface is PEM ingestion: ``RSA/PrivateKey`` and
/// ``RSA/PublicKey`` accept PEM-encoded key material (PKCS#1, RFC 8017 or
/// PKCS#8, RFC 5958) and retain the original bytes for later use. These
/// types exist primarily so consumers can pass typed values through their
/// own APIs while the underlying provider integration is still in progress.
///
/// > Warning: Signing (`RSA.PrivateKey`) and verification (`RSA.PublicKey`)
/// > are **not yet functional**. They require the OpenSSL provider layer
/// > (`OSSL_PROVIDER_load`, `EVP_PKEY_sign_init`), which is not wired up in
/// > this package. See <doc:SecurityConsiderations> for the full list of
/// > MVP gaps before depending on this in production.
///
/// - SeeAlso: ``RSA/PrivateKey``, ``RSA/PublicKey``, ``OpenSSLError``
public enum RSA {}

/// Namespace for the SHA-256 hashing algorithm.
///
/// `SHA256` exposes the canonical 32-byte / 256-bit digest defined by
/// [FIPS PUB 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final)
/// and [RFC 6234](https://datatracker.ietf.org/doc/html/rfc6234). It is
/// suitable for integrity checks, HMAC-SHA256 key derivation, and
/// content-addressed identifiers (JWT payload fingerprints, Nostr event
/// IDs per NIP-01, and Git-style blob hashes).
///
/// All entry points are `static` and live on this enum; the namespace is
/// caseless and cannot be instantiated. Typical calls go through
/// ``hash(data:)`` or ``hash(string:)``, both of which return a
/// ``SHA256/SHA256Digest``.
///
/// > Note: Internally the implementation calls the legacy
/// > [`SHA256_Init`](https://docs.openssl.org/3.6/man3/SHA256_Init/),
/// > `SHA256_Update`, and `SHA256_Final` routines. Upstream marked these
/// > deprecated in OpenSSL 3.0 in favor of the `EVP_MD` high-level
/// > interface; this wrapper retains the legacy path for simplicity and
/// > may migrate to `EVP_MD` in a future release with no public-API
/// > change.
///
/// - SeeAlso: ``SHA256/hash(data:)``, ``SHA256/hash(string:)``,
///   ``SHA256/SHA256Digest``
public enum SHA256 {}

/// Namespace for TLS/SSL utility bindings exposed by this package.
///
/// `SSL` is the home for Swift-level helpers that sit alongside the raw
/// `libssl` C bindings. Today it carries a single property,
/// ``versionString``, used primarily for CVE auditing of deployed
/// binaries. Additional surface (TLS client/server context setup,
/// certificate-chain validation, ALPN helpers) will land as the package
/// matures past its pre-1.0 MVP.
///
/// The enum is caseless and cannot be instantiated; members are all
/// `static`. For raw protocol primitives or for building custom TLS
/// contexts today, import the `libssl` C binding product directly and
/// consult the upstream [`ssl(7)`](https://docs.openssl.org/3.6/man7/ssl/)
/// concept page.
///
/// > Note: This namespace does not offer a TLS client or server API yet.
/// > Do not use `SSL` as a stand-in for `URLSession`, `Network.framework`,
/// > or `swift-nio-ssl`. See <doc:ChoosingLibcryptoVsOpenSSL> for the
/// > product boundary discussion.
///
/// - SeeAlso: ``SSL/versionString``, <doc:SecurityConsiderations>
public enum SSL {
    /// The OpenSSL version string compiled into this package's `libcrypto`.
    ///
    /// The value comes from
    /// [`OpenSSL_version(OPENSSL_VERSION)`](https://docs.openssl.org/3.6/man3/OpenSSL_version/)
    /// and takes the form `"OpenSSL x.y.z <day> <Mon> <YYYY>"` — for
    /// example `"OpenSSL 3.6.2 14 Nov 2025"`. Cross-reference the
    /// major/minor/patch triple against the
    /// [OpenSSL security advisories](https://www.openssl.org/news/vulnerabilities.html)
    /// before cutting a release build; the string is the canonical way to
    /// tell which CVE surface the deployed binary carries.
    ///
    /// The value is deterministic for a given build of this package: it
    /// reflects the `libcrypto` source vendored via `subtree.yaml` and is
    /// not read from any system-provided OpenSSL library. Across repeated
    /// calls, reference identity of the returned `String` is not
    /// guaranteed, but equality (via `==`) is.
    ///
    /// > Note: Because `libcrypto` is statically linked into the package,
    /// > this reports the *compiled-in* version. Applications that swap in
    /// > a different OpenSSL runtime at load time (not supported by this
    /// > package) would need to query that runtime directly.
    ///
    /// - Returns: A human-readable string beginning with the literal
    ///   `"OpenSSL "` followed by the version triple and build date. Use
    ///   `String.hasPrefix(_:)` to gate on the major version.
    public static var versionString: String {
        String(cString: OpenSSL_version(OPENSSL_VERSION))
    }
}

/// Namespace for URL-safe unpadded Base64 encoding (base64url).
///
/// `Base64URL` implements the URL-safe, unpadded alphabet defined in
/// [RFC 4648 §5](https://datatracker.ietf.org/doc/html/rfc4648#section-5).
/// The alphabet swaps `+` for `-` and `/` for `_` relative to standard
/// Base64, and strips the trailing `=` padding — producing strings that
/// can be embedded directly in URLs, HTTP headers, JSON values, and
/// filename segments without further escaping.
///
/// This encoding is the canonical transport form for JOSE (JWS per
/// [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515) and JWT per
/// [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)),
/// [WebAuthn](https://www.w3.org/TR/webauthn-3/) credential blobs,
/// [Nostr NIP-19](https://github.com/nostr-protocol/nips/blob/master/19.md)
/// identifiers, and DID documents. The namespace is caseless; call
/// ``encode(_:)`` and ``decode(_:)`` as `static` entry points.
///
/// > Note: This namespace is pure Swift on top of Foundation's
/// > `Data(base64Encoded:)` / `base64EncodedString()`. It does **not**
/// > call into `libcrypto` and is not constant-time — do not feed it
/// > secret-dependent material that needs side-channel resistance.
///
/// - SeeAlso: ``Base64URL/encode(_:)``, ``Base64URL/decode(_:)``
public enum Base64URL {}

/// The unified error type thrown by every `OpenSSL` Swift API.
///
/// `OpenSSLError` is the single failure surface for this module. Each case
/// carries a human-readable `String` that describes the specific failure
/// condition; the string is surfaced verbatim by ``errorDescription`` to
/// Foundation's `LocalizedError` machinery, so it can be displayed in
/// logs, alerts, or error UI without further processing.
///
/// Instances are produced exclusively by this package's Swift code — no
/// raw `ERR_get_error()` C values bleed through. Equality compares the
/// case *and* the associated `String`, which is convenient for tests but
/// means the `String` contents are part of the observable API contract
/// for those tests.
///
/// > Note: Some cases are reserved for future API surface
/// > (``OpenSSLError/signingFailed(_:)``,
/// > ``OpenSSLError/verificationFailed(_:)``,
/// > ``OpenSSLError/invalidSignature(_:)``) and are not produced by any
/// > code path shipping today. They exist so adding the corresponding
/// > operations later is non-breaking for consumers who already pattern-
/// > match on the full case list.
///
/// - SeeAlso: ``RSA/PrivateKey/init(pemRepresentation:)``,
///   ``SHA256/SHA256Digest/init(rawValue:)``,
///   [Foundation `LocalizedError`](https://developer.apple.com/documentation/foundation/localizederror)
public enum OpenSSLError: Error, Equatable, Sendable {
    /// Thrown when PEM key material fails ingestion.
    ///
    /// Produced by ``RSA/PrivateKey/init(pemRepresentation:)`` and
    /// ``RSA/PublicKey/init(pemRepresentation:)`` when the input is not
    /// valid UTF-8 or does not contain the expected `-----BEGIN ... KEY-----`
    /// frame. The associated `String` describes which check failed.
    ///
    /// Typical remediation: confirm the string was read from disk with the
    /// correct encoding (UTF-8, not UTF-16 with BOM) and that the file has
    /// not been truncated or line-ending-mangled by a text editor.
    case invalidKey(String)

    /// Reserved for future signature-ingestion APIs.
    ///
    /// Not produced by any shipping code path; listed here so future
    /// additions (e.g. a `RSASignature(rawRepresentation:)` initializer)
    /// can throw through a stable case. Do not write code that relies on
    /// this case firing today.
    case invalidSignature(String)

    /// Reserved for future signing APIs.
    ///
    /// Not produced by any shipping code path. Signing requires the
    /// OpenSSL provider layer, which has not landed yet — see
    /// <doc:SecurityConsiderations>. This case is in the API contract so
    /// a future signing operation can throw through it non-breakingly.
    case signingFailed(String)

    /// Reserved for future signature-verification APIs.
    ///
    /// Not produced by any shipping code path. Verification likewise
    /// depends on the OpenSSL provider layer. See
    /// <doc:SecurityConsiderations> for the full MVP gap list.
    case verificationFailed(String)

    /// Thrown when raw input bytes do not satisfy a size or format
    /// constraint.
    ///
    /// Produced by ``SHA256/SHA256Digest/init(rawValue:)`` when the caller
    /// supplies a `Data` value whose length is not exactly 32 bytes. The
    /// associated `String` explains the constraint and the observed input.
    ///
    /// Typical remediation: fix the call site to supply bytes of the
    /// required length; never pad, truncate, or silently retry — the
    /// constraint exists because the downstream consumer cannot interpret
    /// a partial digest.
    case invalidInput(String)

    /// Reserved for surfacing errors from the underlying OpenSSL C API.
    ///
    /// Not produced by any shipping code path. Once future APIs start
    /// invoking the provider layer, this case will carry the string
    /// produced by `ERR_error_string_n` so callers can log the exact
    /// upstream reason. Today it exists solely to preserve API stability
    /// across that transition.
    case underlyingError(String)
}

extension OpenSSLError: LocalizedError {
    /// A user-presentable description of the failure.
    ///
    /// Conforms to Foundation's
    /// [`LocalizedError`](https://developer.apple.com/documentation/foundation/localizederror)
    /// contract: returns a short, human-readable string that begins with a
    /// noun phrase identifying the failure category (e.g. `"Invalid key: "`)
    /// and ends with the associated reason carried by the case. The
    /// returned string is the same value surfaced by
    /// `(error as NSError).localizedDescription` and by
    /// `String(describing:)` via `error.localizedDescription`.
    ///
    /// The value is deterministic for a given case-and-reason pair; it is
    /// not a cached property but recomputes each call. Callers that log
    /// or display the description should treat it as plain text suitable
    /// for end-user surfaces — it does not contain sensitive material
    /// such as key bytes or stack frames.
    ///
    /// > Note: The return type is `String?` to match the `LocalizedError`
    /// > protocol, but every case in ``OpenSSLError`` produces a non-`nil`
    /// > value. Callers may safely unwrap with `??` against an empty
    /// > fallback.
    ///
    /// - Returns: A non-`nil` localized description for every case.
    public var errorDescription: String? {
        switch self {
        case .invalidKey(let reason):
            return "Invalid key: \(reason)"
        case .invalidSignature(let reason):
            return "Invalid signature: \(reason)"
        case .signingFailed(let reason):
            return "Signing failed: \(reason)"
        case .verificationFailed(let reason):
            return "Verification failed: \(reason)"
        case .invalidInput(let reason):
            return "Invalid input: \(reason)"
        case .underlyingError(let reason):
            return "OpenSSL error: \(reason)"
        }
    }
}
