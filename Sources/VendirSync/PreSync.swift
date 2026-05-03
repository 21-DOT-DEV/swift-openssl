// PreSync — maintains `.vendir-cache/openssl/` as a single shallow clone at
// the upstream ref pinned in `scripts/vendir-upstream.json`, then writes the
// resulting commit sha + timestamp back to that file.
//
// Why this exists: vendir's native `git:` source clones once per `contents`
// entry. With five contents pointing at the same upstream, that's five clones
// of OpenSSL — empirically >10 minutes per clone for swift-openssl. By
// pre-populating a single cache and using `directory:` source in vendir.yml,
// we pay the network cost once per ref bump.
//
// Trade-off: vendir.lock.yml records local paths (not upstream shas) when the
// source type is `directory:`. The `UpstreamConfig` schema in VendirSyncLib
// is the sidecar that recovers that provenance.

import Foundation
import VendirSyncLib

enum PreSync {
    static func run(repoRoot: URL) throws {
        let configURL = repoRoot.appendingPathComponent("scripts/vendir-upstream.json")
        let cacheURL = repoRoot.appendingPathComponent(".vendir-cache/openssl")

        let configData = try Data(contentsOf: configURL)
        var config = try JSONDecoder().decode(UpstreamConfig.self, from: configData)

        let fileManager = FileManager.default
        let cacheGitDir = cacheURL.appendingPathComponent(".git")

        let needsClone: Bool
        if !fileManager.fileExists(atPath: cacheGitDir.path) {
            needsClone = true
        } else {
            let (status, output) = try runProcess(
                "git",
                ["-C", cacheURL.path, "describe", "--tags", "--exact-match", "HEAD"],
                capture: true
            )
            let currentTag = output.trimmingCharacters(in: .whitespacesAndNewlines)
            needsClone = (status != 0 || currentTag != config.ref)
        }

        if needsClone {
            print("[1/3] PreSync: cloning \(config.url) @ \(config.ref) → \(cacheURL.path)")
            try? fileManager.removeItem(at: cacheURL)
            try fileManager.createDirectory(
                at: cacheURL.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            mustRun("git", [
                "clone",
                "--depth", "1",
                "--branch", config.ref,
                config.url,
                cacheURL.path
            ])
        } else {
            print("[1/3] PreSync: cache already at \(config.ref), skipping fetch")
        }

        let (revStatus, revOutput) = try runProcess(
            "git",
            ["-C", cacheURL.path, "rev-parse", "HEAD"],
            capture: true
        )
        guard revStatus == 0 else {
            FileHandle.standardError.write(Data("PreSync: rev-parse failed: \(revOutput)\n".utf8))
            exit(revStatus)
        }
        let newSha = revOutput.trimmingCharacters(in: .whitespacesAndNewlines)

        let (tsStatus, tsOutput) = try runProcess(
            "git",
            ["-C", cacheURL.path, "show", "-s", "--format=%ct", "HEAD"],
            capture: true
        )
        guard tsStatus == 0 else {
            FileHandle.standardError.write(Data("PreSync: failed to read commit timestamp: \(tsOutput)\n".utf8))
            exit(tsStatus)
        }
        let trimmedTs = tsOutput.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let newEpoch = Int(trimmedTs) else {
            FileHandle.standardError.write(Data("PreSync: could not parse commit epoch: \(trimmedTs)\n".utf8))
            exit(1)
        }
        let formatter = ISO8601DateFormatter()
        let newCommittedAt = formatter.string(from: Date(timeIntervalSince1970: TimeInterval(newEpoch)))

        let shaChanged = config.sha != newSha
        let timestampChanged = config.committedAtEpoch != newEpoch

        if shaChanged || timestampChanged {
            config.sha = newSha
            config.committedAt = newCommittedAt
            config.committedAtEpoch = newEpoch
            if shaChanged {
                config.fetchedAt = ISO8601DateFormatter().string(from: Date())
            }
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let json = try encoder.encode(config) + Data("\n".utf8)
            try json.write(to: configURL)
            print("[1/3] PreSync: updated scripts/vendir-upstream.json (sha=\(newSha))")
        }
    }
}
