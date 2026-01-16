//
//  OpenSSLTests.swift
//  21-DOT-DEV/swift-openssl
//
//  Copyright (c) 2025 21-DOT-DEV
//  Distributed under the MIT software license
//
//  See the accompanying file LICENSE for information
//

import XCTest
@testable import OpenSSL

final class OpenSSLTests: XCTestCase {
    
    // MARK: - SHA256 Tests

    func testSHA256EmptyString() {
        let digest = OpenSSL.SHA.sha256(string: "")
        // SHA256 of empty string: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        XCTAssertEqual(
            digest.hexString,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
    }
    
    func testSHA256HelloWorld() {
        let digest = OpenSSL.SHA.sha256(string: "Hello, World!")
        // Known SHA256 hash of "Hello, World!"
        XCTAssertEqual(
            digest.hexString,
            "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
        )
    }
    
    func testSHA256Data() {
        let data = Data([0x48, 0x65, 0x6c, 0x6c, 0x6f]) // "Hello" in ASCII
        let digest = OpenSSL.SHA.sha256(data: data)
        // SHA256 of "Hello": 185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969
        XCTAssertEqual(
            digest.hexString,
            "185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969"
        )
    }
    
    func testSHA256DigestEquality() {
        let digest1 = OpenSSL.SHA.sha256(string: "test")
        let digest2 = OpenSSL.SHA.sha256(string: "test")
        let digest3 = OpenSSL.SHA.sha256(string: "different")
        
        XCTAssertEqual(digest1, digest2)
        XCTAssertNotEqual(digest1, digest3)
    }
    
    // MARK: - Base64URL Tests
    
    func testBase64URLEncode() {
        let data = Data("Hello, World!".utf8)
        let encoded = OpenSSL.Base64URL.encode(data)
        XCTAssertEqual(encoded, "SGVsbG8sIFdvcmxkIQ")
        XCTAssertFalse(encoded.contains("+"))
        XCTAssertFalse(encoded.contains("/"))
        XCTAssertFalse(encoded.contains("="))
    }
    
    func testBase64URLDecode() {
        let encoded = "SGVsbG8sIFdvcmxkIQ"
        let decoded = OpenSSL.Base64URL.decode(encoded)
        XCTAssertNotNil(decoded)
        XCTAssertEqual(String(data: decoded!, encoding: .utf8), "Hello, World!")
    }
    
    func testBase64URLRoundTrip() {
        let original = Data("Test data for round trip!".utf8)
        let encoded = OpenSSL.Base64URL.encode(original)
        let decoded = OpenSSL.Base64URL.decode(encoded)
        XCTAssertEqual(decoded, original)
    }
    
    // MARK: - RSA Key Tests
    
    func testRSAPrivateKeyInvalidPEM() {
        XCTAssertThrowsError(try OpenSSL.RSA.PrivateKey(pemRepresentation: "not a valid PEM")) { error in
            guard case OpenSSLError.invalidKey = error else {
                XCTFail("Expected invalidKey error")
                return
            }
        }
    }
    
    func testRSAPublicKeyInvalidPEM() {
        XCTAssertThrowsError(try OpenSSL.RSA.PublicKey(pemRepresentation: "not a valid PEM")) { error in
            guard case OpenSSLError.invalidKey = error else {
                XCTFail("Expected invalidKey error")
                return
            }
        }
    }
    
    // MARK: - RSA Key Parsing Tests
    
    func testRSAPrivateKeyParsing() throws {
        // Test RSA private key format validation
        let validPEMFormat = """
        -----BEGIN RSA PRIVATE KEY-----
        MIIBogIBAAJBALRiMLAHudeSA2ai7Gv5e5r
        -----END RSA PRIVATE KEY-----
        """
        
        // Should not throw - format is valid even if key content is truncated
        let privateKey = try OpenSSL.RSA.PrivateKey(pemRepresentation: validPEMFormat)
        XCTAssertFalse(privateKey.pemData.isEmpty)
    }
    
    func testRSAPublicKeyParsing() throws {
        // Test RSA public key format validation
        let validPEMFormat = """
        -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
        -----END PUBLIC KEY-----
        """
        
        // Should not throw - format is valid
        let publicKey = try OpenSSL.RSA.PublicKey(pemRepresentation: validPEMFormat)
        XCTAssertFalse(publicKey.pemData.isEmpty)
    }
}
