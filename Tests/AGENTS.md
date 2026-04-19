# AGENTS.md (Tests)

This directory contains SwiftPM test targets using **Swift Testing** (`import Testing`, `@Test`, `@Suite`, `#expect`, `#require`).

## Test targets

- `OpenSSLTests` — tests for the `OpenSSL` Swift API (SHA256, Base64URL, RSA key parsing). Manually maintained.

## Test vector backlog (Phase 2+)

- **Current state (Phase 1)**: Smoke tests only — small set of hand-picked digest/base64 vectors and malformed-PEM negative cases.
- **Phase 2 requirement**: Constitution Principle II MUST-level requires validation against published test vectors (Wycheproof, NIST CAVP, RFC test vectors) for every algorithm family. Phase 2 backfills SHA-256 with Wycheproof + NIST CAVP and adds HMAC / HKDF / AEAD coverage as those APIs land.
- Do NOT mark algorithms as "tested" until published-vector coverage exists.

## Conventions

- Bug fixes MUST include a regression test (constitution Principle V).
- Cover both happy-path and error-path behavior for every public API (constitution Principle V).
- Error-path tests on `OpenSSLError` cases with associated values use `try #require(throws: OpenSSLError.self) { ... }` + pattern-match (the `#expect(throws: SomeError.case)` overload doesn't accept cases with associated values).
- Never log or assert on secret material (keys, nonces); per Principle III all secrets stay in OpenSSL-managed memory.
