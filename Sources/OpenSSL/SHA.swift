//
//  SHA.swift
//  21-DOT-DEV/swift-openssl
//
//  Copyright (c) 2025 21-DOT-DEV
//  Distributed under the MIT software license
//
//  See the accompanying file LICENSE for information
//

import Foundation
import libcrypto

// MARK: - SHA256 Digest

extension OpenSSL.SHA {
    /// A SHA256 digest result.
    public struct SHA256Digest: Sendable, Equatable {
        /// The raw digest bytes (32 bytes).
        public let rawValue: Data
        
        /// Creates a digest from raw bytes.
        /// - Parameter rawValue: The 32-byte digest.
        /// - Throws: `OpenSSLError.invalidInput` if the data is not 32 bytes.
        public init(rawValue: Data) throws {
            guard rawValue.count == 32 else {
                throw OpenSSLError.invalidInput("SHA256 digest must be 32 bytes")
            }
            self.rawValue = rawValue
        }
        
        internal init(unchecked rawValue: Data) {
            self.rawValue = rawValue
        }
        
        /// Returns the digest as a hexadecimal string.
        public var hexString: String {
            rawValue.map { String(format: "%02x", $0) }.joined()
        }
    }
    
    /// Computes the SHA256 hash of the given data.
    /// - Parameter data: The data to hash.
    /// - Returns: The SHA256 digest.
    public static func sha256(data: Data) -> SHA256Digest {
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
    
    /// Computes the SHA256 hash of the given string.
    /// - Parameter string: The string to hash (UTF-8 encoded).
    /// - Returns: The SHA256 digest.
    public static func sha256(string: String) -> SHA256Digest {
        sha256(data: Data(string.utf8))
    }
}

// MARK: - Base64URL Encoding

extension OpenSSL {
    /// Utilities for Base64URL encoding (used in JWT).
    public enum Base64URL {
        /// Encodes data as base64url (URL-safe base64 without padding).
        /// - Parameter data: The data to encode.
        /// - Returns: The base64url-encoded string.
        public static func encode(_ data: Data) -> String {
            data.base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
        }
        
        /// Decodes a base64url string to data.
        /// - Parameter string: The base64url-encoded string.
        /// - Returns: The decoded data, or nil if decoding fails.
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
}
