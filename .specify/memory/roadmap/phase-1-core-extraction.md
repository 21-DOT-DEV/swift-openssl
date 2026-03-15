# Phase 1: Core Extraction

> **Status:** ✅ Complete  
> **Last Updated:** 2026-02-02

## Goal

Extract OpenSSL 3.x sources into a Swift Package Manager structure with C bindings, providing the foundation for all subsequent Swift API work.

## Features

### OpenSSL Source Extraction

- **Purpose**: Vendor OpenSSL source code via git subtree for reproducible, version-pinned builds
- **Success Metrics**:
  - OpenSSL 3.x sources extracted and building via SPM
  - Subtree configuration tracked in `subtree.yaml`
  - Extract/update workflow documented in README
- **Dependencies**: None (foundational)

### SPM Build Configuration

- **Purpose**: Enable `import OpenSSL` from Swift with correct C module maps for libcrypto and libssl
- **Success Metrics**:
  - Builds on macOS 13+ (Xcode) and Linux (Swift 6.0+)
  - `libcrypto` and `libssl` exposed as separate SPM targets
  - Public and internal headers correctly mapped
- **Dependencies**: OpenSSL Source Extraction

### Algorithm Selection

- **Purpose**: Minimize binary size by disabling unused cipher suites and hash algorithms at compile time
- **Success Metrics**:
  - `no-asm` for cross-platform portability
  - Legacy ciphers disabled (RC5, RC2, IDEA, BF, CAST, SEED, Camellia)
  - Legacy hashes disabled (MDC2, Whirlpool, MD2, MD4, Blake2)
  - Regional/PQ algorithms disabled (SM2/3/4, ARIA, GOST, LMS, ML-DSA, ML-KEM, SLH-DSA)
  - `configuration.h` generated and committed
- **Dependencies**: SPM Build Configuration

## Phase Metrics

- All three features shipped and verified
- `swift build` succeeds on macOS and Linux
- `swift test` passes (existing test suite)

## Notes

- Generated files (`configuration.h`, `buildinf.h`) are committed to the repo — not regenerated on every build
- `Vendor/openssl/` must be cleaned after regeneration (`make distclean`)
