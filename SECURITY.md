# Security Policy

## Reporting a Vulnerability

To report a security vulnerability in swift-openssl, please use [GitHub Security Advisories](https://github.com/21-DOT-DEV/swift-openssl/security/advisories).

**Do not file a public issue.**

When reporting, please include:

- A description of the vulnerability
- Steps to reproduce or a proof of concept
- Potential impact assessment

We will acknowledge receipt within 7 days and provide an initial assessment as soon as possible.

## Supported Versions

This package is pre-1.0 ([SemVer major version zero](https://semver.org/#spec-item-4)). Only the latest minor release receives security fixes.

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Upstream Dependencies

This package wraps [OpenSSL](https://github.com/openssl/openssl) via Swift's C interoperability.

Vulnerabilities in the underlying C library should be reported directly to the OpenSSL project:

- **OpenSSL**: See [openssl/openssl SECURITY.md](https://github.com/openssl/openssl/blob/master/SECURITY.md)

