import Foundation
import Testing

@testable import VendirSyncLib

@Suite("Configure.upstreamPath")
struct UpstreamPathTests {
    @Test("rewrites public-headers prefix")
    func publicHeadersPrefix() {
        let result = Configure.upstreamPath(
            forPreserveEntry: "Sources/libcrypto/include/openssl/asn1.h"
        )
        #expect(result == "include/openssl/asn1.h")
    }

    @Test("rewrites internal-config prefix")
    func internalIncludePrefix() {
        let result = Configure.upstreamPath(
            forPreserveEntry: "Sources/libcrypto/internal_include/include/crypto/bn_conf.h"
        )
        #expect(result == "include/crypto/bn_conf.h")
    }

    @Test("rewrites crypto-source prefix")
    func cryptoSrcPrefix() {
        let result = Configure.upstreamPath(
            forPreserveEntry: "Sources/libcrypto/src/crypto/buildinf.h"
        )
        #expect(result == "crypto/buildinf.h")
    }

    @Test("rewrites doubled-providers prefix")
    func providersPrefix() {
        let result = Configure.upstreamPath(
            forPreserveEntry: "Sources/libcrypto/providers/providers/common/der/der_digests_gen.c"
        )
        #expect(result == "providers/common/der/der_digests_gen.c")
    }

    @Test(
        "returns nil for entries without an upstream mapping",
        arguments: [
            "Sources/libcrypto/include/Placeholder.h",
            "Sources/libcrypto/src/Placeholder.c",
            "Sources/libssl/include/Placeholder.h",
            "Sources/libssl/src/Placeholder.c",
            "Sources/OpenSSL/RSA.swift",
            "vendir.yml",
            ""
        ]
    )
    func nilForUnmappable(entry: String) {
        #expect(Configure.upstreamPath(forPreserveEntry: entry) == nil)
    }
}

@Suite("Configure.parsePreserveManifest")
struct ParsePreserveManifestTests {
    @Test("filters out comments and blanks, trims whitespace")
    func filtersCommentsAndBlanks() {
        let manifest = """
            # comment line
              # indented comment
            Sources/foo.h
              Sources/bar.c

            # another comment
            Sources/baz.inc
            """
        let parsed = Configure.parsePreserveManifest(manifest)
        #expect(parsed == [
            "Sources/foo.h",
            "Sources/bar.c",
            "Sources/baz.inc"
        ])
    }

    @Test("returns empty array for empty input")
    func emptyInput() {
        #expect(Configure.parsePreserveManifest("") == [])
    }

    @Test("returns empty array when only comments")
    func onlyComments() {
        let manifest = """
            # one
            # two
              # three
            """
        #expect(Configure.parsePreserveManifest(manifest) == [])
    }

    @Test("preserves the actual production manifest with all 104 entries")
    func parsesProductionManifest() throws {
        let manifestURL = repoRoot
            .appendingPathComponent("scripts/vendir-preserve.txt")
        let text = try String(contentsOf: manifestURL, encoding: .utf8)
        let parsed = Configure.parsePreserveManifest(text)
        #expect(parsed.count == 104)
        // First and last entries are stable anchors that detect ordering regressions.
        #expect(parsed.first == "Sources/libcrypto/include/openssl/asn1.h")
        #expect(parsed.last == "Sources/libssl/src/Placeholder.c")
    }
}

@Suite("Configure.generatedFileMap")
struct GeneratedFileMapTests {
    @Test("drops Placeholder paths and rewrites the rest")
    func dropsPlaceholders() {
        let manifest = """
            # configure-generated
            Sources/libcrypto/include/openssl/asn1.h
            Sources/libcrypto/src/crypto/buildinf.h
            # placeholders (no upstream mapping)
            Sources/libcrypto/include/Placeholder.h
            Sources/libssl/src/Placeholder.c
            """
        let map = Configure.generatedFileMap(manifestText: manifest)
        let upstreamPaths = map.map { $0.upstream }
        #expect(upstreamPaths == [
            "include/openssl/asn1.h",
            "crypto/buildinf.h"
        ])
    }

    @Test("production manifest yields 100 mappable entries (Placeholders excluded)")
    func productionManifestYields100() throws {
        let manifestURL = repoRoot
            .appendingPathComponent("scripts/vendir-preserve.txt")
        let text = try String(contentsOf: manifestURL, encoding: .utf8)
        let map = Configure.generatedFileMap(manifestText: text)
        #expect(map.count == 100)
        // Every output upstream path is non-empty and rooted at one of the
        // known upstream subtrees Configure produces into.
        for entry in map {
            #expect(!entry.upstream.isEmpty)
            let validRoot = entry.upstream.hasPrefix("include/")
                || entry.upstream.hasPrefix("crypto/")
                || entry.upstream.hasPrefix("providers/")
            #expect(validRoot, "\(entry.upstream) doesn't start with a known upstream subtree")
        }
    }
}

@Suite("Configure.flags")
struct ConfigureFlagsTests {
    @Test("flag list is non-empty and uses no-* convention")
    func wellFormed() {
        #expect(!Configure.flags.isEmpty)
        for flag in Configure.flags {
            #expect(flag.hasPrefix("no-"), "flag '\(flag)' should follow no-* convention")
        }
    }

    @Test("flag list has no duplicates")
    func noDuplicates() {
        #expect(Configure.flags.count == Set(Configure.flags).count)
    }
}

// MARK: - Helpers

/// Locate the repo root by walking up from the current source file's directory
/// looking for the `vendir.yml` marker. Lets tests reference real fixtures
/// (like `scripts/vendir-preserve.txt`) by repo-relative path regardless of
/// where `swift test` is invoked from.
private let repoRoot: URL = {
    var dir = URL(fileURLWithPath: #filePath)
    while !FileManager.default.fileExists(atPath: dir.appendingPathComponent("vendir.yml").path) {
        let parent = dir.deletingLastPathComponent()
        if parent.path == dir.path {
            fatalError("vendir.yml not found walking up from \(#filePath)")
        }
        dir = parent
    }
    return dir
}()
