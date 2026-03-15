# swift-openssl Roadmap

> **Version:** v2.0.0  
> **Last Updated:** 2026-03-14

## Vision & Goals

Provide modern, type-safe Swift bindings for OpenSSL cryptographic operations — matching swift-crypto's API style — across Apple platforms and Linux. Enable verification-focused workflows (signatures, certificates, CT) with minimal binary footprint.

## Phases Overview

| Phase | Name | Status | File |
|-------|------|--------|------|
| 1 | Core Extraction | ✅ Complete | [phase-1-core-extraction.md](roadmap/phase-1-core-extraction.md) |
| 2 | Foundation Crypto | ⏳ Planned | [phase-2-foundation-crypto.md](roadmap/phase-2-foundation-crypto.md) |
| 3 | Verification | ⏳ Planned | [phase-3-verification.md](roadmap/phase-3-verification.md) |
| 4 | Advanced Validation | ⏳ Planned | [phase-4-advanced-validation.md](roadmap/phase-4-advanced-validation.md) |
| 5 | Binary Size Optimization | ⏳ Planned | [phase-5-binary-optimization.md](roadmap/phase-5-binary-optimization.md) |
| 6 | Advanced Extensions | ⏳ Planned | [phase-6-advanced-extensions.md](roadmap/phase-6-advanced-extensions.md) |

### High-Level Dependencies

- Phase 1 (extraction) is the foundation for everything
- Phase 2 (foundation crypto) must land before Phase 3 (shared types: SymmetricKey, HashFunction, error types, pointer wrappers)
- Phase 3 (verification) depends on Phase 2 foundation types; X.509 basic from Phase 2 enables RSA-PSS + CT
- Phase 4 (chain validation) depends on Phase 3 X.509 + RSA-PSS + CT
- Phase 5 (binary optimization) is independent — can be done anytime after Phase 1
- Phase 6 (extensions) depends on Phases 3–4 for base verification APIs

## Product-Level Metrics & Success Criteria

- **API Coverage**: ≥ 7 cryptographic API families shipped (HMAC, HKDF, AEAD, RSA-PSS, CT, X.509, X.509 Chain)
- **swift-crypto Parity**: API patterns recognizable to swift-crypto users (same naming, generics, static methods)
- **Platform Support**: All APIs build and test on macOS 13+ and Ubuntu 20.04+
- **Test Vector Coverage**: Wycheproof or RFC test vectors for every shipped algorithm
- **Binary Size**: Measurable reduction after Phase 5 optimizations vs. baseline
- **Documentation**: Every public type and method has Swift doc comments

## Deferred / Out of Scope

| Item | Description | Rationale |
|------|-------------|-----------|
| **ASM Optimization** | Platform-specific assembly | Complexity vs. portability tradeoff |
| **FIPS Module** | FIPS 140-2 compliance | Not needed for typical embedded use |

## Change Log

| Version | Date | Change Type | Description |
|---------|------|-------------|-------------|
| v1.0.0 | 2026-02-02 | Initial | Created roadmap with binary size optimization phase |
| v2.0.0 | 2026-03-14 | Major | Merged Draft APIs into roadmap as Phases 2–4 and 6; moved Binary Size Optimization to Phase 5; added product-level metrics |
