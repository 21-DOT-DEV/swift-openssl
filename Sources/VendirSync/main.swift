// VendirSync — orchestrates upstream prefetch + `vendir sync` + preserved-file
// restoration. Replaces the swift-plugin-subtree workflow.
//
//   1. PreSync clones (or refreshes) `.vendir-cache/openssl/` to the ref pinned
//      in `scripts/vendir-upstream.json`, then writes the resulting upstream
//      sha back to that file. The cache is the single shallow clone reused by
//      every `vendir.yml` `directory:` source.
//   2. `vendir sync` reads `vendir.yml` and copies filtered subsets of the
//      cache into Sources/.
//   3. Restore re-applies the paths in `scripts/vendir-preserve.txt` from
//      git HEAD (configure-generated artifacts and Placeholder stubs that
//      vendir would otherwise wipe).
//
// Dev-only target — gated out of tagged releases so consumers don't pay for
// it. See Package.swift's `Target.developmentTargets`.

import Foundation

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
    let manifest = try String(contentsOf: manifestURL, encoding: .utf8)
    let paths = manifest
        .split(whereSeparator: \.isNewline)
        .map { $0.trimmingCharacters(in: .whitespaces) }
        .filter { !$0.isEmpty && !$0.hasPrefix("#") }

    guard !paths.isEmpty else {
        print("[3/3] restore: manifest empty, skipping")
        return
    }
    print("[3/3] restore: \(paths.count) preserved path(s) from scripts/vendir-preserve.txt")
    mustRun("git", ["checkout", "HEAD", "--"] + paths, cwd: repoRoot)
}

do {
    try PreSync.run(repoRoot: repoRoot)
    runVendirSync()
    try restorePreservedFiles()
    print("VendirSync: done")
} catch {
    FileHandle.standardError.write(Data("VendirSync failed: \(error)\n".utf8))
    exit(1)
}
