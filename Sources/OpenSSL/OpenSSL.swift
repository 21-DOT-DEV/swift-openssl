//
//  OpenSSL.swift
//  21-DOT-DEV/swift-openssl
//
//  Copyright (c) 2025 21-DOT-DEV
//  Distributed under the MIT software license
//
//  See the accompanying file LICENSE for information
//

import Foundation
import libcrypto
import libssl

/// OpenSSL namespace for cryptographic operations.
public enum OpenSSL {
    /// RSA cryptographic operations.
    public enum RSA {}
    
    /// SHA hash functions.
    public enum SHA {}
    
    /// SSL/TLS operations.
    public enum SSL {
        /// Returns the OpenSSL version string.
        public static var versionString: String {
            String(cString: OpenSSL_version(OPENSSL_VERSION))
        }
    }
}

/// Errors that can occur during OpenSSL operations.
public enum OpenSSLError: Error, Equatable, Sendable {
    /// The key data is invalid or malformed.
    case invalidKey(String)
    
    /// The signature is invalid or malformed.
    case invalidSignature(String)
    
    /// A signing operation failed.
    case signingFailed(String)
    
    /// A verification operation failed.
    case verificationFailed(String)
    
    /// The input data is invalid.
    case invalidInput(String)
    
    /// An underlying OpenSSL error occurred.
    case underlyingError(String)
}

extension OpenSSLError: LocalizedError {
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
