//
//  RSA.swift
//  21-DOT-DEV/swift-openssl
//
//  Copyright (c) 2025 21-DOT-DEV
//  Distributed under the MIT software license
//
//  See the accompanying file LICENSE for information
//

import Foundation
import libcrypto

// MARK: - RSA Private Key

extension OpenSSL.RSA {
    /// An RSA private key for signing operations.
    /// 
    /// Note: RSA signing requires the full OpenSSL provider layer which is not yet
    /// included in this MVP. Key parsing is validated but signing will fail until
    /// providers are added.
    public struct PrivateKey: Sendable {
        private let keyData: Data
        
        /// Creates a private key from PEM-encoded data.
        /// - Parameter pemRepresentation: The PEM-encoded private key string.
        /// - Throws: `OpenSSLError.invalidKey` if the PEM data is invalid.
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
        
        /// The raw PEM data for this key.
        public var pemData: Data { keyData }
    }
}

// MARK: - RSA Public Key

extension OpenSSL.RSA {
    /// An RSA public key for verification operations.
    ///
    /// Note: RSA verification requires the full OpenSSL provider layer which is not yet
    /// included in this MVP. Key parsing is validated but verification will fail until
    /// providers are added.
    public struct PublicKey: Sendable {
        private let keyData: Data
        
        /// Creates a public key from PEM-encoded data.
        /// - Parameter pemRepresentation: The PEM-encoded public key string.
        /// - Throws: `OpenSSLError.invalidKey` if the PEM data is invalid.
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
        
        /// The raw PEM data for this key.
        public var pemData: Data { keyData }
    }
}
