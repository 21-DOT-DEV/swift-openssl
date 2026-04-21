//
//  SHA.swift
//  21-DOT-DEV/swift-openssl
//
//  Copyright (c) 2026 Timechain Software Initiative, Inc.
//  Distributed under the MIT software license
//
//  See the accompanying file LICENSE for information
//

import Foundation
import libcrypto

// MARK: - SHA256 Digest

extension SHA256 {
    /// A fixed-size SHA-256 digest produced by ``SHA256/hash(data:)`` or
    /// ``SHA256/hash(string:)``.
    ///
    /// A `SHA256Digest` wraps exactly 32 raw bytes (256 bits) — the output
    /// length fixed by [FIPS PUB 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final)
    /// and carried verbatim from `SHA256_Final`'s `md` buffer. The byte
    /// order matches the C routine: index 0 holds the most significant
    /// output byte, index 31 the least, matching every published test
    /// vector (RFC 6234, NIST CAVP).
    ///
    /// Instances are typically produced by the `static` `hash(_:)` family
    /// on ``SHA256``. Callers rarely need ``init(rawValue:)`` directly,
    /// but it exists for round-tripping a stored digest (e.g. one that
    /// was base64-decoded from a Nostr event ID) back into a typed value.
    /// Digests are value types: equality is bytewise, and `Sendable`
    /// conformance allows safe sharing across concurrency domains.
    ///
    /// > Note: `Equatable` on this type defers to `Data`'s built-in
    /// > equality, which is **not** constant-time. Do not compare
    /// > secret-derived digests with `==` on a side-channel-sensitive
    /// > path; use a constant-time comparison primitive from your HMAC or
    /// > AEAD layer instead. See <doc:SecurityConsiderations>.
    ///
    /// - SeeAlso: ``SHA256/hash(data:)``, ``SHA256/hash(string:)``,
    ///   ``hexString``
    public struct SHA256Digest: Sendable, Equatable {
        /// The 32 raw bytes (256 bits) of the SHA-256 output.
        ///
        /// The bytes are in MSB-first order, identical to the output of
        /// the C `SHA256_Final` routine and the test vectors in
        /// [RFC 6234 §8.5](https://datatracker.ietf.org/doc/html/rfc6234#section-8.5).
        /// Length is guaranteed to be exactly 32 by the initializers on
        /// this type; no shipping code path can produce a `SHA256Digest`
        /// whose `rawValue.count != 32`.
        ///
        /// Typical consumers: storing the digest in a database column,
        /// base64-encoding it for transport, or feeding it as input
        /// keying material to an HMAC/HKDF step. If you only need the
        /// human-readable form for logs or URLs, prefer ``hexString``
        /// which avoids an intermediate allocation at the call site.
        ///
        /// > Note: This property exposes the underlying storage directly.
        /// > `Data` value semantics keep mutation by the caller safe, but
        /// > do not treat the returned bytes as constant-time-comparable.
        ///
        /// - Returns: A `Data` of length 32. See ``hexString`` for the
        ///   lowercase hex form.
        public let rawValue: Data

        /// Constructs a digest by adopting a caller-supplied 32-byte value.
        ///
        /// Use this when materializing a previously computed digest back
        /// into a typed value — for example, after reading the raw bytes
        /// from persistent storage or decoding a Nostr NIP-01 event `id`
        /// from hex. The bytes are copied in by value (`Data` is a Swift
        /// value type), so the initializer has no ongoing aliasing with
        /// the caller's buffer.
        ///
        /// No cryptographic work is performed here — this initializer is
        /// purely a typed wrapper around an existing digest. Compute new
        /// digests through ``SHA256/hash(data:)`` or
        /// ``SHA256/hash(string:)``.
        ///
        /// - Parameter rawValue: The digest bytes. Must be exactly 32
        ///   bytes; any other length throws.
        /// - Throws: ``OpenSSLError/invalidInput(_:)`` with a message
        ///   describing the length mismatch when `rawValue.count != 32`.
        public init(rawValue: Data) throws {
            guard rawValue.count == 32 else {
                throw OpenSSLError.invalidInput("SHA256 digest must be 32 bytes")
            }
            self.rawValue = rawValue
        }

        internal init(unchecked rawValue: Data) {
            self.rawValue = rawValue
        }

        /// The digest rendered as a 64-character lowercase hexadecimal string.
        ///
        /// Each of the 32 bytes in ``rawValue`` is formatted as two hex
        /// digits with no separators, no `0x` prefix, and no uppercase
        /// characters — the form consumed by JSON payloads, URL path
        /// segments, log lines, Git object IDs, JWT payload fingerprints,
        /// and Nostr NIP-01 event IDs.
        ///
        /// Output length is always exactly 64 ASCII characters regardless
        /// of input size, because SHA-256 is a fixed-length digest per
        /// FIPS 180-4. The value is recomputed on each access; callers
        /// that need it hot in a tight loop should cache the result.
        ///
        /// > Note: The string matches the regex `[0-9a-f]{64}`. Use the
        /// > stricter `.allSatisfy(\.isHexDigit)` check only if you also
        /// > need to reject uppercase — Foundation's `isHexDigit` accepts
        /// > both cases.
        ///
        /// - Returns: A 64-character ASCII string. For raw byte access,
        ///   use ``rawValue``.
        public var hexString: String {
            rawValue.map { String(format: "%02x", $0) }.joined()
        }
    }

    /// Computes a SHA-256 digest of arbitrary bytes.
    ///
    /// Produces a fixed 32-byte / 256-bit digest per
    /// [FIPS PUB 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final)
    /// by wrapping the legacy C routines
    /// [`SHA256_Init`](https://docs.openssl.org/3.6/man3/SHA256_Init/),
    /// `SHA256_Update`, and `SHA256_Final`. Typical uses: integrity
    /// checks over arbitrary payloads, HMAC-SHA256 key derivation, and
    /// content-addressed identifiers (JWT payload fingerprints, Nostr
    /// NIP-01 event IDs, Git-style blob hashes).
    ///
    /// Every call allocates a fresh `SHA256_CTX` on the stack, so the
    /// function is safe to call concurrently from multiple tasks without
    /// synchronization. Output is stable across platforms and builds.
    ///
    /// > Note: The `SHA256_*` C family is deprecated in OpenSSL 3.0 in
    /// > favor of the `EVP_MD` high-level interface. This wrapper keeps
    /// > the legacy path for simplicity and may migrate to `EVP_MD` in
    /// > a future release — no public API change is expected.
    ///
    /// - Parameter data: The bytes to hash. May be empty; SHA-256 of the
    ///   empty string is the well-defined value
    ///   `e3b0c442...b855` per FIPS 180-4 §A.1.
    /// - Returns: A ``SHA256Digest`` of exactly 32 bytes. Obtain the
    ///   lowercase hex form via ``SHA256Digest/hexString``.
    public static func hash(data: Data) -> SHA256Digest {
        var digestBytes = [UInt8](repeating: 0, count: 32)
        var ctx = SHA256_CTX()
        
        SHA256_Init(&ctx)
        
        data.withUnsafeBytes { dataBytes in
            guard let dataPtr = dataBytes.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return
            }
            SHA256_Update(&ctx, dataPtr, data.count)
        }
        
        SHA256_Final(&digestBytes, &ctx)
        
        return SHA256Digest(unchecked: Data(digestBytes))
    }
    
    /// Computes a SHA-256 digest of a Swift `String` encoded as UTF-8.
    ///
    /// A convenience over ``hash(data:)`` that hashes the bytes returned
    /// by `Data(string.utf8)`. Behavior is identical to hashing those
    /// bytes directly; the return type, length, and test-vector
    /// conformance (RFC 6234, FIPS 180-4) are the same.
    ///
    /// > Warning: SHA-256 hashes a byte sequence, not a semantic string.
    /// > Two visually identical strings with different Unicode
    /// > normalization forms (NFC vs NFD) produce different digests. When
    /// > the input may come from user-visible text — filenames, labels,
    /// > display names — normalize explicitly (for example with
    /// > `String.precomposedStringWithCanonicalMapping`) before hashing.
    /// > See [UAX No. 15](https://www.unicode.org/reports/tr15/) for the
    /// > normalization forms.
    ///
    /// - Parameter string: The text to hash. UTF-8 encoding is applied
    ///   unconditionally; callers needing a different encoding should
    ///   call ``hash(data:)`` with explicitly encoded bytes.
    /// - Returns: A ``SHA256Digest`` of exactly 32 bytes.
    public static func hash(string: String) -> SHA256Digest {
        hash(data: Data(string.utf8))
    }
}

// MARK: - Base64URL Encoding

extension Base64URL {
    /// Encodes raw bytes using the URL-safe unpadded Base64 alphabet.
    ///
    /// Emits the encoding defined in
    /// [RFC 4648 §5](https://datatracker.ietf.org/doc/html/rfc4648#section-5):
    /// the standard Base64 alphabet with `+` replaced by `-`, `/`
    /// replaced by `_`, and the trailing `=` padding stripped. The
    /// output is safe to drop into URL path segments, query parameter
    /// values, HTTP header fields, JSON string values, JWS/JWT segments,
    /// and filename components without further escaping.
    ///
    /// Implementation detail: this is a thin layer over Foundation's
    /// `Data.base64EncodedString()` followed by alphabet translation and
    /// padding removal. It does not call into `libcrypto`.
    ///
    /// > Note: Not constant-time with respect to the input length or
    /// > content. Do not use on side-channel-sensitive material.
    ///
    /// - Parameter data: The bytes to encode. May be empty; the empty
    ///   input produces the empty string.
    /// - Returns: A Base64URL string consisting solely of characters
    ///   from the 64-symbol URL-safe alphabet plus no padding. Round-
    ///   tripped via ``decode(_:)`` to recover the original bytes.
    public static func encode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Decodes a URL-safe unpadded Base64 string to raw bytes.
    ///
    /// Reverses the transformation performed by ``encode(_:)``: restores
    /// `-`→`+`, `_`→`/`, re-appends the `=` padding that RFC 4648 §5
    /// permits to be omitted, and delegates the final decode to
    /// Foundation's `Data(base64Encoded:)`. Invalid input — characters
    /// outside the alphabet, or a length that cannot be padded to a
    /// multiple of four — returns `nil` rather than throwing.
    ///
    /// Typical consumers: JWT / JWS segments
    /// ([RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515)), Nostr
    /// NIP-19 `note` / `nevent` payloads, WebAuthn credential blobs, and
    /// DID document fields.
    ///
    /// > Note: This function is a pure Swift wrapper; no `libcrypto`
    /// > interaction occurs. Security-sensitive callers should prefer
    /// > authenticated transports (JWS, signed envelopes) over hand-
    /// > rolled Base64URL round-tripping.
    ///
    /// - Parameter string: The Base64URL-encoded text. Padding is
    ///   optional in the input; both padded and unpadded forms decode
    ///   successfully.
    /// - Returns: The decoded `Data`, or `nil` if the input contains
    ///   characters outside the URL-safe alphabet or cannot be aligned
    ///   to a four-character group with added padding.
    public static func decode(_ string: String) -> Data? {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        // Add padding if needed
        let paddingLength = (4 - base64.count % 4) % 4
        base64 += String(repeating: "=", count: paddingLength)

        return Data(base64Encoded: base64)
    }
}
