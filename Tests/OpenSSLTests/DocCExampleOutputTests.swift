//
//  DocCExampleOutputTests.swift
//  21-DOT-DEV/swift-openssl
//
//  Copyright (c) 2026 Timechain Software Initiative, Inc.
//  Distributed under the MIT software license
//
//  See the accompanying file LICENSE for information
//

import Foundation
import Testing
@testable import OpenSSL

/// Output-value assertions for the runnable examples embedded in DocC.
///
/// These tests complement the `Snippets/` files: snippets prove that the
/// examples still *compile* against the public API, while these tests prove
/// that the examples still *produce* the values shown in the documentation.
/// Any semantic drift in SHA-256, Base64URL, or the runtime version string
/// will fail here before a release ships.
@Suite("DocC Example Output")
struct DocCExampleOutputTests {

    // MARK: - BasicHashing snippet

    @Test("SHA256 of \"Hello, World!\" matches the value printed in BasicHashing.swift")
    func basicHashingStringDigest() {
        let digest = SHA256.hash(string: "Hello, World!")
        #expect(digest.hexString == "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f")
    }

    @Test("SHA256 of \"Hello\" bytes matches the value printed in BasicHashing.swift")
    func basicHashingDataDigest() {
        let bytes = Data([0x48, 0x65, 0x6c, 0x6c, 0x6f])
        let digest = SHA256.hash(data: bytes)
        #expect(digest.hexString == "185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969")
    }

    // MARK: - Base64URLRoundTrip snippet

    @Test("Base64URL round-trip preserves bytes for a UTF-8 payload")
    func base64URLRoundTripPreservesBytes() {
        let payload = Data("Hello, World!".utf8)
        let encoded = Base64URL.encode(payload)
        let decoded = Base64URL.decode(encoded)
        #expect(decoded == payload)
    }

    @Test("Base64URL output matches the exact string printed in Base64URLRoundTrip.swift")
    func base64URLEncodedStringIsStable() {
        let encoded = Base64URL.encode(Data("Hello, World!".utf8))
        #expect(encoded == "SGVsbG8sIFdvcmxkIQ")
    }

    @Test("Base64URL output is URL-safe and unpadded")
    func base64URLOutputIsURLSafe() {
        let encoded = Base64URL.encode(Data("Hello, World!".utf8))
        #expect(!encoded.contains("+"))
        #expect(!encoded.contains("/"))
        #expect(!encoded.contains("="))
    }

    // MARK: - AuditingRuntimeVersion snippet

    @Test("SSL.versionString has the \"OpenSSL 3.\" prefix shown in AuditingRuntimeVersion.swift")
    func runtimeVersionStringPrefix() {
        #expect(SSL.versionString.hasPrefix("OpenSSL 3."))
    }
}
