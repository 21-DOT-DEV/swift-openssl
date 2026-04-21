//
//  RSA.swift
//  21-DOT-DEV/swift-openssl
//
//  Copyright (c) 2026 Timechain Software Initiative, Inc.
//  Distributed under the MIT software license
//
//  See the accompanying file LICENSE for information
//

import Foundation
import libcrypto

// MARK: - RSA Private Key

extension RSA {
    /// A typed container for an RSA private key parsed from PEM text.
    ///
    /// `PrivateKey` accepts PEM input in either the traditional PKCS#1
    /// form ([RFC 8017](https://datatracker.ietf.org/doc/html/rfc8017),
    /// `-----BEGIN RSA PRIVATE KEY-----`) or the PKCS#8 form
    /// ([RFC 5958](https://datatracker.ietf.org/doc/html/rfc5958),
    /// `-----BEGIN PRIVATE KEY-----`). Instances are `Sendable` value
    /// types: constructing one copies the PEM bytes into the struct, so
    /// the resulting value can be shared across actors and tasks safely.
    /// The underlying C API that will eventually consume these values is
    /// documented in
    /// [`PEM_read_bio_PrivateKey(3)`](https://docs.openssl.org/3.6/man3/PEM_read_bio_PrivateKey/).
    ///
    /// Today this type is primarily a typed wrapper for key material
    /// flowing through application code. It is produced by
    /// ``init(pemRepresentation:)`` and round-tripped via ``pemData``.
    /// Use it wherever your own APIs currently pass a `String` or `Data`
    /// blob representing a PEM private key — getting a typed value out of
    /// the system makes future signing integration a non-breaking change.
    ///
    /// > Warning: **Signing is not yet functional.** Key parsing
    /// > validates the outer PEM frame, but `PrivateKey` cannot currently
    /// > produce signatures — that path requires the OpenSSL provider
    /// > layer (`OSSL_PROVIDER_load`, `EVP_PKEY_sign_init`), which is
    /// > not integrated in this MVP. Any calling code that reaches
    /// > `EVP_PKEY_sign` through a future API will fail until providers
    /// > land. See <doc:SecurityConsiderations> for the complete gap list.
    ///
    /// - SeeAlso: ``RSA/PublicKey``, ``pemData``,
    ///   ``init(pemRepresentation:)``
    public struct PrivateKey: Sendable {
        private let keyData: Data

        /// Parses an RSA private key from a PEM-encoded string.
        ///
        /// Performs outer-frame validation only: the implementation checks
        /// that the input is valid UTF-8 and contains both a `-----BEGIN`
        /// marker and a `PRIVATE KEY-----` marker. Both PKCS#1
        /// (`-----BEGIN RSA PRIVATE KEY-----`) and PKCS#8
        /// (`-----BEGIN PRIVATE KEY-----`) frames satisfy the check.
        /// Encrypted PEM keys (those carrying `Proc-Type:` and `DEK-Info:`
        /// headers per
        /// [RFC 1421](https://datatracker.ietf.org/doc/html/rfc1421)) are
        /// accepted at the string level today but cannot be decrypted —
        /// decryption requires the provider layer.
        ///
        /// > Warning: Validation is **string-marker-only**. A malformed
        /// > DER blob inside an otherwise valid PEM frame is not rejected.
        /// > Consumers that need ASN.1-structural validation must decode
        /// > the payload themselves or wait for the provider-backed
        /// > initializer in a future release.
        ///
        /// - Parameter pemRepresentation: The PEM-encoded private key.
        ///   Accepts both the traditional PKCS#1 framing and the modern
        /// PKCS#8 framing defined in
        ///   [RFC 7468](https://datatracker.ietf.org/doc/html/rfc7468).
        ///   Leading and trailing whitespace is preserved by the store.
        /// - Throws: ``OpenSSLError/invalidKey(_:)`` if the input is not
        ///   valid UTF-8 or lacks the expected frame markers.
        public init(pemRepresentation: String) throws {
            guard let data = pemRepresentation.data(using: .utf8) else {
                throw OpenSSLError.invalidKey("Invalid PEM encoding")
            }

            // Validate the PEM format
            guard pemRepresentation.contains("-----BEGIN") &&
                  pemRepresentation.contains("PRIVATE KEY-----") else {
                throw OpenSSLError.invalidKey("Not a valid PEM private key")
            }

            self.keyData = data
        }

        /// The original PEM bytes as supplied to ``init(pemRepresentation:)``.
        ///
        /// Returns the UTF-8 encoding of the input string verbatim — not
        /// a re-serialized PEM, and not a DER blob. This is the form
        /// expected by keychain imports, HSM shims, and on-disk key
        /// storage formats that treat the PEM text as an opaque transport
        /// envelope. Because the storage is the user-provided input,
        /// header comments and vendor annotations outside the `BEGIN`/
        /// `END` markers are preserved round-trip.
        ///
        /// > Important: The returned bytes contain private-key material.
        /// > Never log this value, never include it in crash reports or
        /// > analytics, and zero any backing buffer you copy it into
        /// > before releasing the memory. Foundation's `Data` does not
        /// > zeroize on deinit.
        ///
        /// - Returns: A `Data` containing the original PEM bytes in
        ///   UTF-8. Use it for persistence, transport to an HSM, or
        ///   future provider-backed signing APIs.
        public var pemData: Data { keyData }
    }
}

// MARK: - RSA Public Key

extension RSA {
    /// A typed container for an RSA public key parsed from PEM text.
    ///
    /// `PublicKey` accepts the SubjectPublicKeyInfo (SPKI) framing used
    /// almost universally in TLS certificates and JOSE key exchanges:
    /// `-----BEGIN PUBLIC KEY-----`, defined by
    /// [RFC 5280 §4.1.2.7](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.7)
    /// and encoded in
    /// [RFC 7468](https://datatracker.ietf.org/doc/html/rfc7468) PEM form.
    /// Unlike ``RSA/PrivateKey``, the legacy PKCS#1 `-----BEGIN RSA
    /// PUBLIC KEY-----` framing is **not** accepted; callers holding a
    /// PKCS#1 public key must convert it to SPKI first (OpenSSL CLI:
    /// `openssl rsa -RSAPublicKey_in -pubout`).
    ///
    /// Typical consumers: JWT verification pipelines (after the key has
    /// been extracted from a JWK), TLS pinning layers comparing against a
    /// known SPKI, and tooling that needs to round-trip a public key
    /// through storage without mutating it. The type is `Sendable`, so
    /// verification pipelines can cache instances across actor boundaries.
    ///
    /// > Warning: **Verification is not yet functional.** Frame
    /// > validation succeeds, but `PublicKey` cannot currently verify
    /// > signatures — that path requires the OpenSSL provider layer
    /// > (`EVP_PKEY_verify_init`), which is not integrated in this MVP.
    /// > See <doc:SecurityConsiderations> for the complete gap list.
    ///
    /// - SeeAlso: ``RSA/PrivateKey``, ``pemData``,
    ///   ``init(pemRepresentation:)``
    public struct PublicKey: Sendable {
        private let keyData: Data

        /// Parses an RSA public key from a PEM-encoded SPKI string.
        ///
        /// Performs outer-frame validation only: the input must be valid
        /// UTF-8 and must contain both a `-----BEGIN` marker and a
        /// `PUBLIC KEY-----` marker. The check is deliberately narrower
        /// than the private-key counterpart — a traditional PKCS#1
        /// `-----BEGIN RSA PUBLIC KEY-----` header would pass the
        /// `PUBLIC KEY-----` substring test but is rejected by downstream
        /// consumers of `pemData`; normalize to SPKI before calling.
        ///
        /// > Warning: Validation is **string-marker-only**. A malformed
        /// > SubjectPublicKeyInfo payload inside a valid PEM frame is
        /// > not detected here. Future provider-backed verification will
        /// > reject such inputs before use.
        ///
        /// - Parameter pemRepresentation: The PEM-encoded SPKI public
        ///   key. The RFC 7468 framing is mandatory; whitespace around
        ///   the markers and inside the base64 body is permitted.
        /// - Throws: ``OpenSSLError/invalidKey(_:)`` if the input is not
        ///   valid UTF-8 or lacks the expected frame markers.
        public init(pemRepresentation: String) throws {
            guard let data = pemRepresentation.data(using: .utf8) else {
                throw OpenSSLError.invalidKey("Invalid PEM encoding")
            }

            guard pemRepresentation.contains("-----BEGIN") &&
                  pemRepresentation.contains("PUBLIC KEY-----") else {
                throw OpenSSLError.invalidKey("Not a valid PEM public key")
            }

            self.keyData = data
        }

        /// The original PEM bytes as supplied to ``init(pemRepresentation:)``.
        ///
        /// Public-key PEM is not secret and may be logged, published in
        /// `.well-known/jwks.json` endpoints, or embedded in TLS
        /// certificate pinning lists. The bytes returned here are the
        /// UTF-8 encoding of the original input string verbatim — no
        /// re-serialization is performed, which preserves vendor
        /// annotations and whitespace around the SPKI frame.
        ///
        /// > Note: Because this is the literal input, two `PublicKey`
        /// > instances representing the same underlying key but parsed
        /// > from differently-formatted PEM strings will produce
        /// > different `pemData` values. If you need canonical equality,
        /// > normalize by round-tripping through a DER decoder first
        /// > — a future release will provide a canonical accessor.
        ///
        /// - Returns: A `Data` containing the input PEM bytes in UTF-8.
        ///   Suitable for publishing, fingerprinting (e.g. via
        ///   ``SHA256/hash(data:)``), and cross-process transport.
        public var pemData: Data { keyData }
    }
}
