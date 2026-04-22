# AGENTS.md (swift-openssl)

A Swift 6.1 wrapper around [OpenSSL 3.x](https://github.com/openssl/openssl) providing modern, type-safe bindings for cryptographic operations with a [swift-crypto](https://github.com/apple/swift-crypto)-aligned API. Supports macOS 13+, iOS 16+, tvOS 16+, watchOS 9+, visionOS 1+, and Linux. Uses Swift 6 strict concurrency (`swiftLanguageModes: [.v6]`). Three products: `libcrypto` (raw C bindings), `libssl` (raw C bindings), and `OpenSSL` (idiomatic Swift API).

## Commands

- Build: `swift build`
- Test: `swift test`
- Linux build: `docker build .`
- Subtree update: `swift package --build-path .build/subtree --allow-writing-to-package-directory --allow-network-connections all subtree update openssl --ref <tag>`
- Subtree extract: `swift package --build-path .build/subtree --allow-writing-to-package-directory subtree extract --name openssl --force`

## Non-obvious patterns

- **Conditional dev deps**: `Package.swift` uses `Context.gitInformation?.currentTag` to exclude `swift-plugin-subtree` at tagged releases. Consumers resolving a tagged version get zero transitive dependencies; the package has no runtime dependencies.
- **Three-product split**: `libcrypto` + `libssl` are raw C bindings (consumable standalone); `OpenSSL` is the idiomatic Swift API with top-level types (`SHA256`, `RSA`, `SSL`, `Base64URL`) — no namespace enum, matching swift-crypto. Never leak raw C types (`OpaquePointer`, `EVP_PKEY*`) through `OpenSSL`'s public API.
- **Extraction flow**: OpenSSL upstream is extracted via `subtree.yaml` (remote `openssl/openssl`, tag `openssl-3.6.2`). `Vendor/openssl` → `Sources/libcrypto/**` + `Sources/libssl/**`. Do NOT edit `Sources/libcrypto/**` or `Sources/libssl/**` directly; changes are overwritten on the next extraction. Manually maintained files live under `Sources/OpenSSL/`.
- **Configure-generated headers**: A subset of headers under `Sources/libcrypto/**` are NOT in upstream — they are generated from `.h.in` templates by OpenSSL's Perl-based Configure script (e.g., `include/openssl/configuration.h`, `include/openssl/cmp.h`, `crypto/buildinf.h`, `providers/fips/include/fips/fipsindicator.h`). They must be regenerated whenever a bump changes a `.h.in` template or the `OPENSSL_NO_*` flag set. See `Vendor/AGENTS.md` for the Configure recipe.
- **Bump tiering**: For patch releases (e.g., `3.6.0 → 3.6.2`), `subtree update --ref <tag>` + `subtree extract --force` is usually sufficient. Run the full Configure + `make build_all_generated` + re-extract + `make distclean` dance only when `swift build` reports missing identifiers (indicates a `.h.in` template changed) or for minor/major upstream bumps.
- **Algorithm selection is double-encoded**: `subtree.yaml` `exclude:` lists AND `OPENSSL_NO_*` defines in `Sources/libcrypto/include/openssl/configuration.h` must stay synchronized. Disabling a new algorithm requires both updating excludes and adding the flag to the Configure command in `Vendor/AGENTS.md`.
- **Runtime fallback paths**: `Package.swift` defines `OPENSSLDIR` (`/usr/local/ssl`), `ENGINESDIR` (`/usr/local/lib/engines`), and `MODULESDIR` (`/usr/local/lib/ossl-modules`) for OpenSSL's runtime path lookups. Changing them affects `x509_def.c`, `eng_list.c`, and `provider_core.c` defaults.
- **Linux-only C define**: `_GNU_SOURCE` is defined on Linux only, to enable glibc features like `pthread_rwlock_t` and full POSIX support.
- **iOS `clear_cache` shim**: Not applicable here (this is swift-openssl, not swift-tor). OpenSSL uses `OPENSSL_NO_ASM` to avoid platform-specific assembly.

## Boundaries

- **Never**: emit private keys or sensitive material; weaken constant-time code in vendored C sources; edit files under `Vendor/**`, `Sources/libcrypto/**`, or `Sources/libssl/**` directly; broaden GitHub Actions `permissions` without justification; add runtime dependencies; re-enable algorithms disabled by constitution (legacy ciphers, regional standards, post-quantum until standardized).
- **Ask first**: add new third-party dependencies (dev or runtime); modify `subtree.yaml` extraction patterns; change the `Configure` flag set; add a new platform.
- See the [21-DOT-DEV contributing guidelines](https://github.com/21-DOT-DEV/.github/blob/main/CONTRIBUTING.md) for branching and commit guidelines. See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## Scoped guidance

Directory-specific `AGENTS.md` files provide additional context:

- `.github/AGENTS.md` — CI workflows and Actions security policy
- `Sources/AGENTS.md` — Swift targets, C bindings, extraction paths, header-search-path layout
- `Tests/AGENTS.md` — Swift Testing framework, cryptographic test-vector backlog
- `Vendor/AGENTS.md` — vendored OpenSSL sources, subtree sync rules, Configure regeneration recipe

## Maintenance

- Keep scoped `AGENTS.md` files limited to deltas; avoid duplicating root guidance.
- Update when build/test workflows, toolchain versions, platform support, or extraction patterns change.
