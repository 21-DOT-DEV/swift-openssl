// VendirSync — orchestrates upstream prefetch + `vendir sync` + preserved-file
// restoration. Replaces the swift-plugin-subtree workflow.
//
// Default mode (`swift run VendirSync`):
//   1. PreSync clones (or refreshes) `.vendir-cache/openssl/` to the ref pinned
//      in `scripts/vendir-upstream.json`, then writes the resulting upstream
//      sha + commit timestamp back to that file. The cache is the single
//      shallow clone reused by every `vendir.yml` `directory:` source.
//   2. `vendir sync` reads `vendir.yml` and copies filtered subsets of the
//      cache into Sources/.
//   3. Restore re-applies the paths in `scripts/vendir-preserve.txt` from
//      git HEAD (configure-generated artifacts and Placeholder stubs that
//      vendir would otherwise wipe).
//   4. Drift check: compare current upstream sha against the
//      `lastRegenSha` recorded in `scripts/vendir-upstream.json`. If they
//      differ, error with "run --regenerate". Leverages git's tree hashing
//      — any commit-level change is sha-detectable; no parallel snapshot
//      needed.
//
// Regenerate mode (`swift run VendirSync --regenerate`):
//   1–3. Same as default.
//   4. Configure.regenerate: runs OpenSSL Configure + make against the cache
//      and copies the ~100 configure-generated artifacts into Sources/,
//      overwriting the Restore step's output.
//   5. Update `scripts/vendir-upstream.json`'s `lastRegenSha` to current
//      upstream sha.
//
// Dev-only target — gated out of tagged releases so consumers don't pay for
// it. See Package.swift's `Target.developmentTargets`.
//
// `Process` (used throughout this target) is unavailable on iOS / tvOS /
// watchOS / visionOS. The `#if os(macOS) || os(Linux)` gate below makes
// non-supported platforms see a stub-only `main.swift` so xcodebuild's
// multi-platform builds (apple-builds.yml) don't fail compilation. The
// supported-platform code is unchanged.

import Foundation

#if os(macOS) || os(Linux)

import VendirSyncLib

let repoRoot: URL = {
    var dir = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
    while !FileManager.default.fileExists(atPath: dir.appendingPathComponent("vendir.yml").path) {
        let parent = dir.deletingLastPathComponent()
        if parent.path == dir.path {
            FileHandle.standardError.write(Data("VendirSync: vendir.yml not found in current working tree\n".utf8))
            exit(1)
        }
        dir = parent
    }
    return dir
}()

func runProcess(_ tool: String, _ args: [String], capture: Bool = false, cwd: URL? = nil) throws -> (status: Int32, output: String) {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
    process.arguments = [tool] + args
    if let cwd { process.currentDirectoryURL = cwd }

    if capture {
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        try process.run()
        process.waitUntilExit()
        let data = (try? pipe.fileHandleForReading.readToEnd()) ?? Data()
        return (process.terminationStatus, String(data: data, encoding: .utf8) ?? "")
    }

    try process.run()
    process.waitUntilExit()
    return (process.terminationStatus, "")
}

@discardableResult
func mustRun(_ tool: String, _ args: [String], cwd: URL? = nil) -> Int32 {
    do {
        let (status, _) = try runProcess(tool, args, capture: false, cwd: cwd)
        if status != 0 {
            FileHandle.standardError.write(Data("VendirSync: `\(tool) \(args.joined(separator: " "))` exited \(status)\n".utf8))
            exit(status)
        }
        return status
    } catch {
        FileHandle.standardError.write(Data("VendirSync: failed to launch `\(tool)`: \(error)\n".utf8))
        exit(1)
    }
}

func runVendirSync() {
    print("[2/3] vendir sync")
    mustRun("vendir", ["sync"], cwd: repoRoot)
}

func restorePreservedFiles() throws {
    let manifestURL = repoRoot.appendingPathComponent("scripts/vendir-preserve.txt")
    let manifestText = try String(contentsOf: manifestURL, encoding: .utf8)
    let paths = Configure.parsePreserveManifest(manifestText)

    guard !paths.isEmpty else {
        print("[3/3] restore: manifest empty, skipping")
        return
    }
    print("[3/3] restore: \(paths.count) preserved path(s) from scripts/vendir-preserve.txt")
    mustRun("git", ["checkout", "HEAD", "--"] + paths, cwd: repoRoot)
}

/// Compare the current upstream sha against the sha at last `--regenerate`.
/// Errors if they differ, prompting the maintainer to run `--regenerate`.
/// Leverages git's tree hashing — no parallel hash snapshot needed.
func checkRegenerationDrift() throws {
    let configURL = repoRoot.appendingPathComponent("scripts/vendir-upstream.json")
    let configData = try Data(contentsOf: configURL)
    let upstream = try JSONDecoder().decode(UpstreamConfig.self, from: configData)

    switch upstream.driftState {
    case .noBaseline:
        print("[4/4] drift check: no lastRegenSha recorded, skipping (run --regenerate to set)")
    case .match:
        print("[4/4] drift check: upstream sha matches last regenerate")
    case .drifted(let currentSha, let lastRegenSha):
        FileHandle.standardError.write(Data("""
            VendirSync: upstream sha has advanced since last regenerate.
              current sha:        \(currentSha)
              last regenerate at: \(lastRegenSha)
            Run `swift run VendirSync --regenerate` to refresh configure-generated artifacts.

            """.utf8))
        exit(1)
    }
}

/// Run `Configure.regenerate` against the cache, then record the current
/// upstream sha as `lastRegenSha` in `scripts/vendir-upstream.json`.
func runRegenerate() throws {
    let configURL = repoRoot.appendingPathComponent("scripts/vendir-upstream.json")
    let cacheURL = repoRoot.appendingPathComponent(".vendir-cache/openssl")

    let configData = try Data(contentsOf: configURL)
    var upstream = try JSONDecoder().decode(UpstreamConfig.self, from: configData)
    guard let epoch = upstream.committedAtEpoch else {
        FileHandle.standardError.write(Data("VendirSync: scripts/vendir-upstream.json missing committedAtEpoch (run default sync first)\n".utf8))
        exit(1)
    }
    guard let currentSha = upstream.sha else {
        FileHandle.standardError.write(Data("VendirSync: scripts/vendir-upstream.json missing sha (run default sync first)\n".utf8))
        exit(1)
    }

    try Configure.regenerate(repoRoot: repoRoot, cacheURL: cacheURL, sourceDateEpoch: epoch)

    upstream.lastRegenSha = currentSha
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    let json = try encoder.encode(upstream) + Data("\n".utf8)
    try json.write(to: configURL)
    print("regenerate: recorded lastRegenSha=\(currentSha) in scripts/vendir-upstream.json")
}

let regenerateRequested = CommandLine.arguments.contains("--regenerate")

do {
    try PreSync.run(repoRoot: repoRoot)
    runVendirSync()
    try restorePreservedFiles()
    if regenerateRequested {
        try runRegenerate()
        print("VendirSync: done (regenerated)")
    } else {
        try checkRegenerationDrift()
        print("VendirSync: done")
    }
} catch {
    FileHandle.standardError.write(Data("VendirSync failed: \(error)\n".utf8))
    exit(1)
}

#else

// Stub for unsupported platforms (iOS / tvOS / watchOS / visionOS).
// Process is unavailable; this binary cannot run here. The stub ensures
// xcodebuild can compile the target as part of multi-platform package
// builds without breaking.
FileHandle.standardError.write(Data("VendirSync requires macOS or Linux\n".utf8))
exit(1)

#endif
