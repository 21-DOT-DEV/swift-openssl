//
//  OpenSSLTests.swift
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

@Suite("OpenSSL")
struct OpenSSLTests {

    // MARK: - SHA256 Tests

    @Test("SHA256 of empty string matches RFC vector")
    func sha256EmptyString() {
        let digest = SHA256.hash(string: "")
        // SHA256 of empty string: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        #expect(digest.hexString == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    }

    @Test("SHA256 of \"Hello, World!\"")
    func sha256HelloWorld() {
        let digest = SHA256.hash(string: "Hello, World!")
        #expect(digest.hexString == "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f")
    }

    @Test("SHA256 over Data")
    func sha256Data() {
        let data = Data([0x48, 0x65, 0x6c, 0x6c, 0x6f]) // "Hello" in ASCII
        let digest = SHA256.hash(data: data)
        // SHA256 of "Hello": 185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969
        #expect(digest.hexString == "185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969")
    }

    @Test("SHA256 digest equality")
    func sha256DigestEquality() {
        let digest1 = SHA256.hash(string: "test")
        let digest2 = SHA256.hash(string: "test")
        let digest3 = SHA256.hash(string: "different")

        #expect(digest1 == digest2)
        #expect(digest1 != digest3)
    }

    // MARK: - Base64URL Tests

    @Test("Base64URL encoding is URL-safe and unpadded")
    func base64URLEncode() {
        let data = Data("Hello, World!".utf8)
        let encoded = Base64URL.encode(data)
        #expect(encoded == "SGVsbG8sIFdvcmxkIQ")
        #expect(!encoded.contains("+"))
        #expect(!encoded.contains("/"))
        #expect(!encoded.contains("="))
    }

    @Test("Base64URL decoding recovers original bytes")
    func base64URLDecode() {
        let encoded = "SGVsbG8sIFdvcmxkIQ"
        let decoded = Base64URL.decode(encoded)
        #expect(decoded != nil)
        #expect(String(data: decoded!, encoding: .utf8) == "Hello, World!")
    }

    @Test("Base64URL encode/decode round-trip")
    func base64URLRoundTrip() {
        let original = Data("Test data for round trip!".utf8)
        let encoded = Base64URL.encode(original)
        let decoded = Base64URL.decode(encoded)
        #expect(decoded == original)
    }

    // MARK: - RSA Key Tests

    @Test("RSA private key rejects invalid PEM")
    func rsaPrivateKeyInvalidPEM() throws {
        let error = try #require(throws: OpenSSLError.self) {
            _ = try RSA.PrivateKey(pemRepresentation: "not a valid PEM")
        }
        guard case .invalidKey = error else {
            Issue.record("Expected OpenSSLError.invalidKey, got \(error)")
            return
        }
    }

    @Test("RSA public key rejects invalid PEM")
    func rsaPublicKeyInvalidPEM() throws {
        let error = try #require(throws: OpenSSLError.self) {
            _ = try RSA.PublicKey(pemRepresentation: "not a valid PEM")
        }
        guard case .invalidKey = error else {
            Issue.record("Expected OpenSSLError.invalidKey, got \(error)")
            return
        }
    }

    // MARK: - RSA Key Parsing Tests

    @Test("RSA private key accepts valid PEM format")
    func rsaPrivateKeyParsing() throws {
        // Test RSA private key format validation
        let validPEMFormat = """
        -----BEGIN RSA PRIVATE KEY-----
        MIIBogIBAAJBALRiMLAHudeSA2ai7Gv5e5r
        -----END RSA PRIVATE KEY-----
        """

        // Should not throw - format is valid even if key content is truncated
        let privateKey = try RSA.PrivateKey(pemRepresentation: validPEMFormat)
        #expect(!privateKey.pemData.isEmpty)
    }

    @Test("RSA public key accepts valid PEM format")
    func rsaPublicKeyParsing() throws {
        // Test RSA public key format validation
        let validPEMFormat = """
        -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
        -----END PUBLIC KEY-----
        """

        // Should not throw - format is valid
        let publicKey = try RSA.PublicKey(pemRepresentation: validPEMFormat)
        #expect(!publicKey.pemData.isEmpty)
    }
}
