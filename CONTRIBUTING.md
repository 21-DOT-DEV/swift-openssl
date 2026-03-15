# Contributing to swift-openssl

Thank you for your interest in contributing to swift-openssl! This document provides guidelines and information for contributors.

## Scope

swift-openssl is a Swift package providing modern Swift APIs for OpenSSL cryptographic operations. It is focused on verification-oriented workflows (signatures, certificates, CT) with a Swift Crypto-compatible API design.

Contributions of new functionality are welcome, provided they are within the project's scope. When proposing significant additions, please open an issue first to discuss the design and ensure alignment with project goals.

## How to Report a Bug

Please [open an issue](https://github.com/21-DOT-DEV/swift-openssl/issues/new) and include the following:

- swift-openssl version or commit hash
- Swift version (output of `swift --version`)
- OS version and the output of `uname -a`
- Contextual information (what you were trying to achieve)
- Simplest possible steps to reproduce
  - A pull request with a failing test case is preferred, but pasting the test case into the issue description is fine.

## Security Vulnerabilities

If you believe you have found a security vulnerability, **do not open a public issue**. Please report it through [GitHub Security Advisories](https://github.com/21-DOT-DEV/swift-openssl/security/advisories). See [SECURITY.md](SECURITY.md) for full details.

## Writing a Patch

A good swift-openssl patch is:

1. **Concise** — contains as few changes as needed to achieve the end result.
2. **Tested** — any tests provided must fail before the patch and pass after it.
3. **Documented** — adds or updates API documentation as needed to cover new or changed functionality.
4. **Well-described** — accompanied by a clear commit message explaining *what* changed and *why*.

## Testing

Run the full test suite with:

```
swift test
```

New features should include corresponding tests, and bug fixes should include a regression test.

## How to Contribute

1. Fork the repository and create your branch from `main`.
2. Make your changes following the guidelines above.
3. Ensure all tests pass (`swift test`).
4. Open a pull request at https://github.com/21-DOT-DEV/swift-openssl.
5. Wait for CI to pass and code review.

## Legal

By submitting a pull request, you represent that you have the right to license your contribution to the project and the community, and agree by submitting the patch that your contributions are licensed under the [MIT License](LICENSE).
