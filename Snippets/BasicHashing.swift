// snippet.hide
import Foundation
import OpenSSL
// snippet.end

// Compute a SHA-256 digest of a UTF-8 string.
let stringDigest = SHA256.hash(string: "Hello, World!")
print(stringDigest.hexString)
// Prints: dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f

// Compute a SHA-256 digest of arbitrary bytes.
let bytes = Data([0x48, 0x65, 0x6c, 0x6c, 0x6f])  // "Hello"
let bytesDigest = SHA256.hash(data: bytes)
print(bytesDigest.hexString)
// Prints: 185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969

// Digest equality compares the 32 raw bytes.
precondition(SHA256.hash(string: "Hello, World!") == stringDigest)
