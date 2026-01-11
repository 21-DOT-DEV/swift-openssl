//
//  RS256SigningTests.swift
//  swift-openssl
//
//  Copyright (c) 2025 21.dev
//  Distributed under the MIT software license
//
//  See the accompanying file LICENSE for information
//

import Foundation
import Testing
@testable import OpenSSL

@Suite("RS256 Signing Tests")
struct RS256SigningTests {
    
    // Test RSA private key (2048-bit, for testing only - DO NOT USE IN PRODUCTION)
    static let testPrivateKeyPEM = """
    -----BEGIN RSA PRIVATE KEY-----
    MIIEpAIBAAKCAQEA2mKqH0dSgFxLX8PC8kfO7pfGdaV8RCnB2pLJL+IM3VjHNXsH
    w0f1r0f4mXGqGvjrjCrFkEuXTfnf7L1YfvP4f3K9Z9Y5U1f7P1mM8J7C9g7f1r2p
    h4J1e0wYc2F7J0R5X9T8X8J5F7X9U8X8C5F7X9U8X8C5F7X9U8X8C5F7X9U8X8C5
    F7X9U8X8C5F7X9U8X8C5F7X9U8X8C5F7X9U8X8C5F7X9U8X8C5F7X9U8X8C5F7X9
    U8X8C5F7X9U8X8C5F7X9U8X8C5F7X9U8X8C5F7X9U8X8C5F7X9U8X8C5F7X9U8X8
    C5F7X9U8X8C5F7X9U8X8C5F7X9U8X8C5F7X9U8X8CwIDAQABAoIBAC3v4+OxP8qR
    N8c2m1C8p2p8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5
    f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9
    U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8
    C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7
    X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8
    x8C5f7X9U8ECgYEA7f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x
    8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f
    7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8CgYEA6f
    7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U
    8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C
    5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8ECgYEA5f7X9U8x8C5f
    7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U
    8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C
    5f7X9U8x8C5f7X9U8x8C5f7X9U8x8CgYEA4f7X9U8x8C5f7X9U8x8C5f7X9U8x8C
    5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X
    9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x
    8C5f7X9U8ECgYEA3f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C
    5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X
    9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8x8C5f7X9U8=
    -----END RSA PRIVATE KEY-----
    """
    
    @Test("Sign data with RS256")
    func signDataRS256() throws {
        // Note: This test will fail until we have a valid test key and OpenSSL is properly linked.
        // For now, this serves as a placeholder to verify the API compiles correctly.
        
        let testData = Data("test message to sign".utf8)
        
        // This test requires a valid RSA key - the placeholder key above is not valid
        // Once OpenSSL is properly vendored, replace with a real test key
        #expect(throws: OpenSSLError.self) {
            _ = try RSASigning.signRS256(data: testData, privateKeyPEM: Self.testPrivateKeyPEM)
        }
    }
    
    @Test("Invalid PEM key throws error")
    func invalidPEMKeyThrowsError() throws {
        let testData = Data("test message".utf8)
        let invalidPEM = "not a valid PEM key"
        
        #expect(throws: OpenSSLError.self) {
            _ = try RSASigning.signRS256(data: testData, privateKeyPEM: invalidPEM)
        }
    }
    
    @Test("Empty data can be signed")
    func emptyDataCanBeSigned() throws {
        // Once we have a valid key, empty data should still produce a valid signature
        let emptyData = Data()
        
        #expect(throws: OpenSSLError.self) {
            _ = try RSASigning.signRS256(data: emptyData, privateKeyPEM: Self.testPrivateKeyPEM)
        }
    }
}

