# Phase 6: Advanced Extensions

> **Status:** ⏳ Planned  
> **Last Updated:** 2026-03-14

## Goal

Extend the verification and cryptographic API surface with advanced capabilities: Merkle proofs, RSA-PSS signing, OCSP response handling, and TLS session introspection.

## Features

### Merkle Inclusion Proofs

- **Purpose**: Verify that an SCT corresponds to a certificate logged in a CT log's Merkle tree, providing stronger assurance than signature-only verification
- **Success Metrics**:
  - `CT.MerkleInclusionProof` type for proof data
  - `CT.verifyInclusion(sct:proof:sth:)` verification API
  - Proof fetching from CT log HTTP endpoints (optional — may be caller responsibility)
  - Integration with existing `CT.SCTReport` for combined reporting
- **Dependencies**: Phase 3 (CT verification API)
- **Note**: Extends Phase 3 CT API with Merkle tree verification for stronger assurance beyond signature-only checks

### RSA-PSS Signing

- **Purpose**: Enable RSA-PSS signature creation (Phase 3 provides verification only), completing the RSA-PSS API for bidirectional use
- **Success Metrics**:
  - `RSA.PSS.PrivateKey` type with PEM/DER initialization
  - `signature(for:parameters:)` signing method
  - Round-trip test: sign → verify with existing `PublicKey.isValidSignature`
  - Key generation API (optional)
- **Dependencies**: Phase 3 (RSA-PSS verification)
- **Note**: Completes the RSA-PSS API — Phase 3 provides `RSA.PSS.PublicKey` (verify), this adds `RSA.PSS.PrivateKey` (sign)

### OCSP Response Handling

- **Purpose**: Parse OCSP responses and extract SCTs from stapled OCSP responses, supporting real-time certificate revocation checking
- **Success Metrics**:
  - `OCSP.Response` parsing type
  - SCT extraction from stapled OCSP responses
  - Revocation status checking integration with Phase 4 chain verification
  - `Sendable` conformance
- **Dependencies**: Phase 3 (CT for SCT extraction), Phase 4 (chain verification for revocation)

### TLS Session Info

- **Purpose**: Extract protocol version, cipher suite, and session metadata from TLS connections for auditing and verification
- **Success Metrics**:
  - `SSL.SessionInfo` type with protocol version, cipher suite, peer certificate
  - Read-only introspection (no TLS handshake management)
  - `Sendable` conformance
- **Dependencies**: Phase 3 (AEAD for cipher suite context), Phase 4 (X.509 chain for peer cert)

## Dependencies & Sequencing

```
Phase 3 (CT) ──────────→ Merkle Inclusion Proofs
Phase 3 (RSA-PSS) ─────→ RSA-PSS Signing
Phase 3 (CT) + Phase 4 → OCSP Response Handling
Phase 3 + Phase 4 ─────→ TLS Session Info
```

- Merkle Proofs and RSA-PSS Signing can start as soon as their Phase 3 prerequisites ship
- OCSP and TLS Session Info require both Phase 3 and Phase 4

## Phase Metrics

- 4 features shipped
- All types conform to `Sendable`
- Round-trip tests for signing features
- `swift build` and `swift test` pass on macOS + Linux

## Test Vector Strategy

- **Merkle Proofs**: CT test log inclusion proofs from certificate.transparency.dev
- **RSA-PSS Signing**: Wycheproof vectors (sign then verify round-trip)
- **OCSP**: Real-world stapled OCSP responses with embedded SCTs
- **TLS Session Info**: Mock session data for property extraction tests
