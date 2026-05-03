// Configure — pure-logic portion of the OpenSSL Configure recipe:
//   - target string + algorithm-disable flag list (constants).
//   - path rewrites mapping `scripts/vendir-preserve.txt` entries
//     (Sources-relative) back to upstream-relative paths for the make+copy
//     step in `--regenerate`.
//   - manifest parsing and the (upstream, sourcesPath) map derivation.
//
// Process orchestration (`./Configure`, `make`, file copy) lives in the
// executable shell — see `Sources/VendirSync/Regenerate.swift`.

import Foundation

public enum Configure {
    /// Configure target string. The resulting `buildinf.h` PLATFORM string is
    /// informational only; runtime behavior is determined by other means, so
    /// we always pass `darwin64-arm64-cc` regardless of host.
    public static let target = "darwin64-arm64-cc"

    /// Algorithm-disable flag set. Each entry suppresses one OpenSSL feature
    /// area we don't ship. Must stay in sync with the `OPENSSL_NO_*` defines
    /// in the generated `configuration.h` (which Configure produces from
    /// these flags) and with the `excludePaths` in `vendir.yml` blocks 4+5
    /// and 6 (which prevent the disabled algorithms' upstream sources from
    /// being copied into Sources/).
    public static let flags: [String] = [
        "no-asm",
        "no-shared",
        "no-apps",
        "no-docs",
        "no-tests",
        "no-rc5",
        "no-rc2",
        "no-idea",
        "no-bf",
        "no-cast",
        "no-seed",
        "no-camellia",
        "no-mdc2",
        "no-whirlpool",
        "no-md2",
        "no-md4",
        "no-sm2",
        "no-sm3",
        "no-sm4",
        "no-aria",
        "no-gost",
        "no-blake2",
        "no-lms",
        "no-ml-dsa",
        "no-ml-kem",
        "no-slh-dsa",
        "no-ec_nistp_64_gcc_128",
        "no-padlockeng",
    ]

    /// Map a preserve-manifest entry (Sources-relative) → upstream-relative
    /// path. The four prefix rewrites mirror vendir.yml's `directories[].path`
    /// + `contents[].path` shape, restated explicitly here for the inverse
    /// (Sources → upstream) direction needed for the `--regenerate` copy.
    /// Returns nil for entries that don't have an upstream counterpart
    /// (e.g., Placeholder paths).
    public static func upstreamPath(forPreserveEntry entry: String) -> String? {
        let rewrites: [(sources: String, upstream: String)] = [
            ("Sources/libcrypto/include/openssl/", "include/openssl/"),
            ("Sources/libcrypto/internal_include/include/crypto/", "include/crypto/"),
            ("Sources/libcrypto/src/crypto/", "crypto/"),
            ("Sources/libcrypto/providers/providers/", "providers/"),
        ]
        for (sources, upstream) in rewrites {
            if entry.hasPrefix(sources) {
                return upstream + entry.dropFirst(sources.count)
            }
        }
        return nil
    }

    /// Parse `scripts/vendir-preserve.txt` text into a list of preserve
    /// entries — one path per line, with comment lines (`#…`) and blanks
    /// dropped, surrounding whitespace trimmed.
    public static func parsePreserveManifest(_ text: String) -> [String] {
        text.split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("#") }
    }

    /// Map a preserve manifest's text into the (upstream-relative,
    /// Sources-relative) pairs used by `--regenerate`'s make+copy step.
    /// Entries without an upstream mapping (e.g., Placeholders) are dropped.
    public static func generatedFileMap(manifestText: String) -> [(upstream: String, sourcesPath: String)] {
        parsePreserveManifest(manifestText).compactMap { entry in
            guard let upstream = upstreamPath(forPreserveEntry: entry) else { return nil }
            return (upstream, entry)
        }
    }
}
