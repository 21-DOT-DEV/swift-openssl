<!--
Sync Impact Report:
- Version: N/A → 1.0.0 (Initial constitution)
- Change Type: Initial creation
- Scope: swift-openssl package (/Users/csjones/Developer/swift-openssl)
- Structure: Two-tier (7 core principles + implementation practices in nested format)
- Core Principles:
  I. Scope & swift-crypto Alignment
  II. Cryptographic Correctness
  III. Key & Secret Handling
  IV. API Design & Safety
  V. Spec-First & Test-Driven Development
  VI. Cross-Platform CI & Quality Gates
  VII. Open Source Excellence
- Enforcement: Three-tier model (MUST/SHOULD/MAY) with explicit MUST NOT
- Governance: BDFL model with security-relevant change protocols
- Compliance: Continuous CI + event-driven strategic review
- Templates Status:
  ⚠ spec-template.md - Requires alignment review
  ⚠ plan-template.md - Requires alignment review
  ⚠ tasks-template.md - Requires alignment review
  ⚠ checklist-template.md - Requires alignment review
- Follow-up TODOs:
  • Set up SwiftLint/SwiftFormat infrastructure before Phase 2
  • Backfill Phase 1 SHA-256 with Wycheproof/NIST test vectors during Phase 2
-->

# Constitution for swift-openssl

## Preamble

This constitution governs the **swift-openssl** package, a Swift package providing modern, type-safe bindings for OpenSSL cryptographic operations using Swift's C interoperability.

**Scope**: This repository only. Covers the `OpenSSL` Swift wrapper module and its underlying C targets (`libcrypto`, `libssl`), plus the vendored OpenSSL 3.x source managed via git subtree.

**Philosophy**: Principles are technology-agnostic where possible. This is a cryptographic library wrapping a battle-tested C implementation — correctness, safety, and API clarity take precedence over features.

---

## Core Principles

### I. Scope & swift-crypto Alignment

**Statement**: The package MUST provide Swift-native, type-safe bindings for OpenSSL cryptographic operations, matching swift-crypto's API style where applicable. OpenSSL 3.x is the sole cryptographic backend.

**Rationale**: A familiar API design (inspired by swift-crypto) lowers adoption friction and reduces misuse. Using OpenSSL as the sole backend avoids fragmentation and leverages its extensive algorithm support and audit history.

**Practices**:
- **MUST** provide high-level Swift APIs for OpenSSL cryptographic operations (hashing, HMAC, HKDF, AEAD, RSA-PSS, X.509, CT)
- **MUST** align API naming and patterns with swift-crypto conventions where applicable
- **MUST** use OpenSSL 3.x as the sole source of cryptographic primitives
- **MUST** maintain zero runtime dependencies beyond OpenSSL C bindings
- **MUST NOT** add Swift dependencies without constitutional review and explicit justification
- **MUST NOT** implement novel, unreviewed cryptographic constructions outside of OpenSSL
- **SHOULD** expose `libcrypto` and `libssl` as separate products for advanced users requiring full control
- **MAY** extend scope to additional OpenSSL capabilities that fit naturally into the swift-crypto API model

**Compliance**: PRs adding new algorithm families or dependencies MUST include justification and constitutional review.

---

### II. Cryptographic Correctness

**Statement**: All primitives MUST be mathematically correct, using vetted algorithms and parameters from OpenSSL and recognized cryptographic standards. Implementation safety (constant-time behavior) MUST be preserved at wrapper boundaries.

**Rationale**: Cryptographic correctness is non-negotiable. Leveraging OpenSSL's battle-tested core reduces the risk of subtle bugs. The Swift wrapper layer must not introduce timing side channels or weaken OpenSSL's guarantees.

**Practices**:
- **MUST** preserve constant-time behavior for all operations on secret data by using OpenSSL's constant-time utilities (e.g., `CRYPTO_memcmp` for MAC comparison)
- **MUST** avoid data-dependent branches and memory access patterns on secrets in the Swift wrapper layer
- **MUST** validate against published test vectors (Wycheproof, NIST CAVP, RFC test vectors) for every algorithm family
- **MUST** validate inputs rigorously and reject malformed encodings, invalid keys, and out-of-range parameters
- **MUST** use OpenSSL's EVP (high-level) APIs rather than deprecated low-level functions
- **MUST NOT** implement custom cryptographic constructions ("don't roll your own crypto")
- **MUST NOT** use deprecated OpenSSL APIs (`SHA256_Init`, `SHA256_Update`, `SHA256_Final`, etc.) in new code
- **SHOULD** backfill Phase 1 code with proper test vectors and EVP API migration during Phase 2
- **SHOULD** incorporate third-party security reviews for significant changes
- **MAY** add property-based tests for edge cases beyond test vector coverage

**Compliance**: Test vector validation runs on every PR. PRs modifying cryptographic code require explicit review.

---

### III. Key & Secret Handling

**Statement**: Private keys, symmetric keys, nonces, and other secrets MUST be managed in OpenSSL memory via pointer wrappers and never exposed as raw `Data` through public APIs.

**Rationale**: OpenSSL's memory management functions (`*_free`, `OPENSSL_cleanse`) handle secret zeroing reliably. Swift's value semantics and ARC make zeroing guarantees imperfect for `Data` — keeping secrets in OpenSSL-managed memory avoids this fundamental tension.

**Practices**:
- **MUST** keep secrets in OpenSSL memory via reference-counted pointer wrappers with `deinit`-based cleanup
- **MUST** expose secret access only through `withUnsafeBytes` closures (prevents callers from holding persistent copies)
- **MUST** use cryptographically secure pseudo-random number generators (OpenSSL's CSPRNG) for key and nonce generation
- **MUST NOT** log private keys, symmetric keys, nonces, or intermediate secrets
- **MUST NOT** expose secrets in error messages, debug descriptions, or crash reports
- **MUST NOT** use predictable or hardcoded nonces (especially critical for AES-GCM where nonce reuse is catastrophic)
- **MUST NOT** expose raw `Data` representations of private key material through public API
- **SHOULD** use `OPENSSL_cleanse()` for any Swift-side temporary buffers holding secret material
- **SHOULD** document limitations of Swift ARC regarding secret lifetime guarantees
- **MAY** provide unsafe escape hatches for expert users, clearly documented as such

**Compliance**: Code review MUST verify secret handling. Pointer wrappers MUST call appropriate `*_free()` in `deinit`.

---

### IV. API Design & Safety

**Statement**: Public APIs MUST follow a Swift-native, swift-crypto-inspired design with safe defaults, top-level types, and `Sendable` conformance throughout.

**Rationale**: Familiar API design lowers learning curve and reduces misuse. Safe defaults protect typical users. `Sendable` conformance enables safe use in Swift's structured concurrency model.

**Practices**:
- **MUST** use top-level types within the `OpenSSL` module (e.g., `SHA256`, `RSA`, `HMAC<H>`, not `OpenSSL.SHA256`)
- **MUST** follow swift-crypto naming conventions (e.g., `SHA256.hash(data:)`, `HMAC<H>.authenticationCode(for:using:)`, `isValidSignature`)
- **MUST** ensure all public types conform to `Sendable`
- **MUST** provide `Bool`-returning fast paths for verification (`isValid*()` — no throws for invalid signatures/MACs)
- **MUST** use strongly-typed errors (`OpenSSLError` enum with `Equatable`, `Sendable`, `LocalizedError`)
- **MUST** ensure errors do not leak secret material in descriptions
- **MUST NOT** expose OpenSSL C types (`OpaquePointer`, `EVP_PKEY*`, etc.) in public API
- **SHOULD** provide both one-shot and incremental APIs where applicable (e.g., HMAC)
- **SHOULD** support PEM, DER, and certificate-based key initialization
- **SHOULD** document all public types and functions with Swift doc comments

**Compliance**: Code review enforces API naming conventions, `Sendable` conformance, and documentation requirements.

---

### V. Spec-First & Test-Driven Development

**Statement**: Every feature MUST start with a specification. All code MUST follow test-driven development: tests written first, verified to fail, then implementation proceeds. Existing code SHOULD be backfilled with proper test coverage.

**Rationale**: Specifications ensure alignment with user needs and provide measurable success criteria. TDD prevents regressions, enables confident refactoring, and documents expected behavior. Retroactive backfill ensures the entire codebase meets quality standards.

**Practices - Specification Requirements**:
- **MUST** create specifications (roadmap phase files or `spec.md`) for every feature before development
- **MUST** represent a single feature or small subfeature (not multiple unrelated features)
- **MUST** be independently testable (no dependencies on incomplete specs)
- **MUST** define user scenarios, acceptance criteria, and success metrics
- **MUST NOT** combine multiple unrelated features in one spec
- **MUST NOT** describe implementation details instead of user-facing behavior

**Practices - Test-Driven Development**:
- **MUST** write tests before implementation (red → green → refactor)
- **MUST** verify tests fail initially
- **MUST** validate against published test vectors (Wycheproof, NIST CAVP, RFC vectors) for cryptographic operations
- **MUST** maintain separate unit and integration tests where appropriate
- **SHOULD** backfill Phase 1 code with proper test vectors during Phase 2 refactoring
- **SHOULD** develop outside-in (user's perspective first)

**Compliance**: PRs MUST include tests written first. CI blocks merges if tests missing or immediately passing. Specs combining multiple features MUST be rejected in review.

---

### VI. Cross-Platform CI & Quality Gates

**Statement**: The package MUST maintain support for all advertised platforms with CI coverage ensuring features compile and tests pass on each. Linting MUST be enforced once infrastructure is in place.

**Rationale**: Cross-platform reliability is a core value proposition. Determinism is critical for testability and reproducibility. Consistent code style reduces friction in reviews and AI-assisted development.

**Practices**:
- **MUST** test across all supported platforms (macOS, iOS, tvOS, watchOS, visionOS, Linux)
- **MUST** test on both Intel and ARM architectures where applicable
- **MUST** ensure deterministic behavior: given same inputs, operations produce same outputs across all platforms
- **MUST** pass all unit and integration tests before merge
- **MUST** enforce linting (SwiftLint, SwiftFormat) as merge gates once infrastructure is set up
- **MUST NOT** merge code that breaks any supported platform
- **SHOULD** set up SwiftLint and SwiftFormat infrastructure before Phase 2 development begins
- **SHOULD** run fuzzing on schedule for cryptographic functions
- **MAY** provide platform-specific optimizations where beneficial (e.g., assembly for specific architectures in future phases)

**Compliance**: CI pipeline enforces all MUST-level gates. Platform failures block merge. Linting becomes a MUST gate once tooling is configured.

---

### VII. Open Source Excellence

**Statement**: All development MUST follow open source best practices: comprehensive documentation, welcoming contributions, clear licensing, and simplicity over cleverness.

**Rationale**: Good documentation reduces friction. Clear decisions preserve knowledge. Simplicity encourages contributions and reduces maintenance burden.

**Practices**:
- **MUST** document architecture decisions
- **MUST** maintain clear README with setup instructions and usage examples
- **MUST** provide contribution guidelines (CONTRIBUTING.md)
- **MUST** include LICENSE file (MIT for Swift wrapper; Apache 2.0 for vendored OpenSSL)
- **MUST** write clear, human-readable code (readability over cleverness)
- **MUST** apply KISS and DRY principles
- **MUST** document all public APIs with inline doc comments
- **MUST** include minimal, complete examples for each API family (hashing, HMAC, AEAD, RSA, X.509, etc.)
- **SHOULD** maintain security disclosure process (SECURITY.md)
- **SHOULD** maintain AI agent guidance (AGENTS.md)
- **SHOULD** respond to community contributions promptly and respectfully

**Compliance**: PRs MUST include documentation updates for new features or API changes. Code reviews enforce readability.

---

## Implementation Guidance

### Security Disclosure Process

**Statement**: A clear process for reporting vulnerabilities MUST be documented.

**Requirements**:
- **MUST** provide SECURITY.md with reporting instructions
- **MUST** include preferred contact method (GitHub Security Advisories)
- **MUST** define expected response timeline (e.g., acknowledgment within 48 hours)
- **MUST** commit to coordinated disclosure timeline
- **SHOULD** acknowledge reporters in release notes (with permission)

**Security-Relevant Changes**:
- Maintainer MUST document security implications in PR description
- 48-72 hour merge delay for community review opportunity
- Explicit "security-reviewed" label required before merge

---

### OpenSSL Subtree Management

**Purpose**: The vendored OpenSSL 3.x source is managed via git subtree and requires careful governance.

**Algorithm Selection Policy**:
- **MUST** disable legacy ciphers (RC5, RC2, IDEA, BF, CAST, SEED, Camellia)
- **MUST** disable legacy hashes (MDC2, Whirlpool, MD2, MD4)
- **MUST** disable regional standards (SM2, SM3, SM4, ARIA, GOST)
- **MUST** disable post-quantum algorithms until standardization matures (LMS, ML-DSA, ML-KEM, SLH-DSA)
- **MUST** build with `no-asm` for cross-platform portability
- **MUST** document all disabled algorithms with rationale in README
- **MAY** re-enable post-quantum algorithms in future phases after NIST standardization

**Update Procedures**:
- **MUST** use `subtree pull` for OpenSSL version updates
- **MUST** re-extract sources via `subtree extract` after updates
- **MUST** run `make distclean` in `Vendor/openssl/` after extracting Configure-generated files
- **MUST** verify all tests pass on all platforms after OpenSSL updates
- **SHOULD** track OpenSSL security advisories and update promptly for CVEs

**Binary Size**:
- **SHOULD** minimize compiled binary size through algorithm selection and provider trimming
- Phase 5 (Binary Size Optimization) defines specific targets and strategies

---

## Technology Stack (Current Implementation)

**Note**: Constitution defines technology-agnostic principles. This section documents current choices, which may change without constitutional amendments.

### Supported Platforms

- **macOS** 13+ (arm64, x86_64)
- **iOS** 16+ (arm64)
- **tvOS** 16+ (arm64)
- **watchOS** 9+ (arm64)
- **visionOS** 1+ (arm64)
- **Linux** (x86_64, arm64)

### Current Stack (2026-03-14)

**Language**: Swift 6.0+
**Build**: Swift Package Manager (SPM)
**Testing**: XCTest (Phase 1), swift-testing planned for Phase 2+
**CI**: GitHub Actions (apple-builds.yml, docker-builds.yml)
**Linting**: TODO — SwiftLint + SwiftFormat setup required before Phase 2
**OpenSSL**: 3.x (vendored via git subtree in `Vendor/openssl/`)

### Products

| Product | Type | Description |
|---------|------|-------------|
| `OpenSSL` | Swift wrapper | Primary high-level API (swift-crypto-style) |
| `libcrypto` | C bindings | Raw bindings to OpenSSL crypto library |
| `libssl` | C bindings | Raw bindings to OpenSSL SSL/TLS library |

### Dependencies

**Runtime**: Zero Swift dependencies beyond OpenSSL C bindings
**Development only**: swift-plugin-subtree (vendored source management)

---

## Governance

### Authority

This constitution supersedes all other development practices. Deviations MUST be explicitly justified and approved.

**Model**: Project owner (BDFL) can amend constitution directly. Community proposes changes via GitHub issues.

### Security-Relevant Changes

Changes affecting cryptographic behavior require additional scrutiny:

| Requirement | Purpose |
|-------------|---------|
| Document security implications in PR description | Creates audit trail |
| 48-72 hour merge delay | Allows community review |
| Explicit "security-reviewed" label | Signals intentional consideration |

**Security-relevant changes include**:
- New cryptographic algorithm families
- Changes to key/secret handling APIs
- OpenSSL version updates (especially security patches)
- Modifications to algorithm selection (Configure flags)

### Amendment Process

1. Project owner proposes amendment with rationale and impact analysis
2. Version updated (semantic versioning):
   - **MAJOR**: Backward-incompatible changes or principle removals
   - **MINOR**: New principle or materially expanded guidance
   - **PATCH**: Clarifications, wording fixes
3. Update dependent templates in `.specify/templates/`
4. Document changes in Sync Impact Report
5. Commit with descriptive message

### Compliance Review Triggers

| Trigger | Action |
|---------|--------|
| Adding new cryptographic algorithm families | Full constitutional alignment check |
| OpenSSL upstream updates | Verify behavior consistency, security advisory check |
| Changes to key/secret handling APIs | Security review required |
| Breaking API changes (semver major) | Stability signaling review |
| Algorithm selection changes (Configure flags) | Binary size and scope review |

### Versioning & Stability

**Pre-1.0** (current):
- No stability guarantees
- Immediate breaking changes acceptable
- Users advised to pin exact versions

**Post-1.0** (future):
- Semantic versioning strictly enforced
- Deprecation period (one minor version) before removal
- Breaking changes require major version bump

### Enforcement

- PR reviewers verify constitutional alignment
- CI pipeline enforces MUST-level (blocking), SHOULD-level (warnings)
- Three-tier enforcement:
  - **MUST**: Blocks merge
  - **SHOULD**: Warning, requires override justification
  - **MAY**: Informational only

---

## Version History

**Version**: 1.0.0
**Ratified**: 2026-03-14
**Last Amended**: 2026-03-14

**Changelog**:
- **1.0.0** (2026-03-14): Initial constitution with 7 core principles, three-tier enforcement, BDFL governance, OpenSSL subtree management, security-relevant change protocols. Modeled after swift-secp256k1 constitution v1.0.0.
