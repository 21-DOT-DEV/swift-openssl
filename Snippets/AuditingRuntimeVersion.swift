// snippet.hide
import OpenSSL
// snippet.end

// Report the OpenSSL build linked at runtime.
// The string begins with "OpenSSL 3." followed by the minor/patch version
// and the build date — e.g. "OpenSSL 3.6.2 14 Nov 2025".
//
// Cross-reference the minor/patch number against
// https://www.openssl.org/news/vulnerabilities.html before shipping
// a release build.
print(SSL.versionString)
