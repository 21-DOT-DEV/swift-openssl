// snippet.hide
import Foundation
import OpenSSL
// snippet.end

// Encode an arbitrary byte payload using the URL-safe unpadded
// alphabet from RFC 4648 §5.
let payload = Data("Hello, World!".utf8)
let encoded = Base64URL.encode(payload)
print(encoded)
// Prints: SGVsbG8sIFdvcmxkIQ

// Output never contains '+', '/', or '=' — safe to drop into JSON, URLs,
// HTTP headers, or JWT/JWS segments without further escaping.
precondition(!encoded.contains("+") && !encoded.contains("/") && !encoded.contains("="))

// Decode restores padding automatically before delegating to Foundation.
let decoded = Base64URL.decode(encoded)
precondition(decoded == payload)
print(String(data: decoded!, encoding: .utf8) ?? "")
// Prints: Hello, World!
