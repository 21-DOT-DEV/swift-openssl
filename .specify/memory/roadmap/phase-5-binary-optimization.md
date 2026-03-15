# Phase 5: Binary Size Optimization

> **Status:** ⏳ Planned  
> **Last Updated:** 2026-03-14

## Goal

Reduce binary size by removing unused OpenSSL subsystems (engines, hardware support, dynamic provider loading) that are unnecessary for embedded/mobile builds.

## Features

### No-Engine Build

- **Purpose**: Exclude OpenSSL engine sources and defines to reduce binary size — standard iOS best practice per OpenSSL wiki
- **Success Metrics**:
  - `OPENSSL_NO_ENGINE` added to `configuration.h`
  - `src/crypto/engine/` excluded via `subtree.yaml`
  - `ENGINESDIR` define removed from `Package.swift`
  - Build succeeds on all platforms without engine-related symbols
- **Dependencies**: Phase 1 (Core Extraction)
- **Notes**: Equivalent to `./Configure ... no-engine`; engines are never used in embedded builds where paths are set programmatically

### No-HW Build

- **Purpose**: Disable hardware engine support to further reduce binary size
- **Success Metrics**:
  - `OPENSSL_NO_HW` added to `configuration.h`
  - Build succeeds on all platforms
  - No hardware-engine-related symbols in final binary
- **Dependencies**: No-Engine Build (logical grouping)

### Provider Trimming

- **Purpose**: Evaluate and potentially remove `MODULESDIR` by disabling dynamic provider loading
- **Success Metrics**:
  - Assessment of whether `MODULESDIR` can be safely removed
  - If removable: `MODULESDIR` define removed from `Package.swift`
  - If not: documented rationale for keeping it
  - Build succeeds on all platforms
- **Dependencies**: Phase 1 (Core Extraction)

## Dependencies & Sequencing

```
Phase 1 (Core Extraction) ──→ No-Engine Build ──→ No-HW Build
                           ──→ Provider Trimming (independent)
```

- This phase is independent of Phases 2–4 (API work)
- Can be done anytime after Phase 1, but scheduled here to prioritize API surface first

## Phase Metrics

- Binary size measured before and after each optimization
- All existing tests continue to pass after each change
- `swift build` succeeds on macOS + Linux
- No regressions in API functionality from Phases 2–4

## Implementation Notes

1. Update `subtree.yaml` to exclude `src/crypto/engine/` directory
2. Regenerate `configuration.h` with `no-engine no-hw` flags
3. Remove `ENGINESDIR` from `Package.swift`
4. Verify build on all platforms
5. Measure and document binary size delta

## Rationale

The paths `OPENSSLDIR`, `ENGINESDIR`, `MODULESDIR` are compile-time fallbacks returned by `ossl_get_*dir()` functions. In embedded builds where paths are set programmatically, these are never used. Removing engine support matches the standard iOS configuration: `./Configure ios64-cross no-shared no-dso no-hw no-engine`.
