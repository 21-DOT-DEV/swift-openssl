// snippet.hide
import Foundation
import OpenSSL
// snippet.end

// Parse an RSA private key from a PEM-encoded string.
// PKCS#8 framing: -----BEGIN PRIVATE KEY----- / -----END PRIVATE KEY-----.
// PKCS#1 framing: -----BEGIN RSA PRIVATE KEY----- / -----END RSA PRIVATE KEY-----.
let privatePEM = """
-----BEGIN RSA PRIVATE KEY-----
MIIBogIBAAJBALRiMLAHudeSA2ai7Gv5e5r
-----END RSA PRIVATE KEY-----
"""

let privateKey = try RSA.PrivateKey(pemRepresentation: privatePEM)
print("Parsed private key, \(privateKey.pemData.count) PEM bytes retained.")

// Parse the matching RSA public key (SubjectPublicKeyInfo, RFC 5280 §4.1.2.7).
let publicPEM = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
-----END PUBLIC KEY-----
"""

let publicKey = try RSA.PublicKey(pemRepresentation: publicPEM)
print("Parsed public key, \(publicKey.pemData.count) PEM bytes retained.")

// NOTE: Signing and verification are not functional in the current MVP —
// they require the OpenSSL provider layer, which is not yet integrated.
// Parsed keys can be stored and round-tripped, but cannot produce or
// verify signatures until a future release. See SecurityConsiderations.
