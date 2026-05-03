// Regenerate — runs OpenSSL's Configure + make against the cache to reproduce
// the ~100 configure-generated artifacts that vendir cannot extract from
// upstream (they're produced from `.h.in` / `.c.in` templates by upstream's
// own build system).
//
// Replaces the manual recipe formerly documented in `Vendor/AGENTS.md`. Run
// during bumps that change `.h.in` / `.c.in` templates; routine syncs use
// `git checkout HEAD --` against the committed copies (see Restore in
// main.swift).
//
// Approach:
//   1. `git clean -fdx` the cache to a pristine state.
//   2. `./Configure <target> <flags…>` in the cache via its
//      `#!/usr/bin/env perl` shebang (in-tree — matches the manual
//      recipe's path conventions).
//   3. `make <100 explicit targets>` with `SOURCE_DATE_EPOCH` set from the
//      upstream commit timestamp so `buildinf.h` is deterministic.
//   4. Copy each generated file from cache → Sources/ at the path recorded
//      in `scripts/vendir-preserve.txt`.
//   5. `git clean -fdx` again to leave the cache pristine.
//
// Pure-logic portions (algorithm flag list, target string, path rewrites,
// manifest parsing) live in VendirSyncLib's `Configure.swift` so they're
// unit-testable without invoking external processes.

import Foundation
import VendirSyncLib

extension Configure {
    /// Regenerate all configure-generated artifacts. Caller must ensure the
    /// cache is populated at the desired ref before invoking (PreSync does this).
    static func regenerate(repoRoot: URL, cacheURL: URL, sourceDateEpoch: Int) throws {
        let manifestURL = repoRoot.appendingPathComponent("scripts/vendir-preserve.txt")
        let manifestText = try String(contentsOf: manifestURL, encoding: .utf8)
        let copyMap = generatedFileMap(manifestText: manifestText)

        print("[regen 1/5] cleaning cache (git clean -fdx)")
        mustRun("git", ["-C", cacheURL.path, "clean", "-fdx"])

        print("[regen 2/5] running ./Configure \(target) + \(flags.count) flags")
        // Invoke ./Configure directly via its `#!/usr/bin/env perl` shebang —
        // matches OpenSSL's documented invocation. Bypasses runProcess (which
        // routes through `/usr/bin/env <name>` for PATH lookup) since
        // executableURL handles the path directly.
        let configureProcess = Process()
        configureProcess.executableURL = cacheURL.appendingPathComponent("Configure")
        configureProcess.arguments = [target] + flags
        configureProcess.currentDirectoryURL = cacheURL
        let configurePipe = Pipe()
        configureProcess.standardOutput = configurePipe
        configureProcess.standardError = configurePipe
        try configureProcess.run()
        configureProcess.waitUntilExit()
        guard configureProcess.terminationStatus == 0 else {
            let data = (try? configurePipe.fileHandleForReading.readToEnd()) ?? Data()
            FileHandle.standardError.write(Data("Configure failed:\n".utf8))
            FileHandle.standardError.write(data)
            exit(configureProcess.terminationStatus)
        }

        print("[regen 3/5] make-ing \(copyMap.count) generated files (SOURCE_DATE_EPOCH=\(sourceDateEpoch))")
        let makeArgs = ["make"] + copyMap.map { $0.upstream }
        let makeProcess = Process()
        makeProcess.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        makeProcess.arguments = makeArgs
        makeProcess.currentDirectoryURL = cacheURL
        var env = ProcessInfo.processInfo.environment
        env["SOURCE_DATE_EPOCH"] = String(sourceDateEpoch)
        makeProcess.environment = env
        let makePipe = Pipe()
        makeProcess.standardOutput = makePipe
        makeProcess.standardError = makePipe
        try makeProcess.run()
        makeProcess.waitUntilExit()
        guard makeProcess.terminationStatus == 0 else {
            let data = (try? makePipe.fileHandleForReading.readToEnd()) ?? Data()
            FileHandle.standardError.write(Data("make failed:\n".utf8))
            FileHandle.standardError.write(data)
            exit(makeProcess.terminationStatus)
        }

        print("[regen 4/5] copying \(copyMap.count) artifacts into Sources/")
        let fileManager = FileManager.default
        for (upstream, sourcesPath) in copyMap {
            let src = cacheURL.appendingPathComponent(upstream)
            let dst = repoRoot.appendingPathComponent(sourcesPath)
            try fileManager.createDirectory(
                at: dst.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            if fileManager.fileExists(atPath: dst.path) {
                try fileManager.removeItem(at: dst)
            }
            try fileManager.copyItem(at: src, to: dst)
        }

        print("[regen 5/5] cleaning cache (git clean -fdx)")
        mustRun("git", ["-C", cacheURL.path, "clean", "-fdx"])
    }
}
