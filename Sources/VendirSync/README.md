# VendirSync

Development tool that orchestrates swift-openssl's vendoring of upstream
OpenSSL source. Replaces the legacy `subtree.yaml` + `swift-plugin-subtree`
workflow.

> **Status:** Internal to swift-openssl. Planned for extraction into a
> standalone `swift-vendir` package — see [SWIFT_VENDIR_PLAN.md](../../SWIFT_VENDIR_PLAN.md).
>
> **Platforms:** macOS + Linux only (uses `Process`). The target builds to
> a no-op stub on iOS/tvOS/watchOS/visionOS so xcodebuild's multi-platform
> jobs don't fail.

## What it does

Three orchestrated phases on every run:

1. **PreSync** — clones (or refreshes) `.vendir-cache/openssl/` to the ref
   pinned in [`vendir-upstream.json`](../../vendir-upstream.json), then
   captures the resulting upstream sha + commit timestamp.
2. **Vendir sync** — invokes `vendir sync` against
   [`vendir.yml`](../../vendir.yml), which copies filtered subsets of the
   cache into `Sources/libcrypto/` and `Sources/libssl/`.
3. **Restore** — runs `git checkout HEAD --` against every path listed in
   [`vendir-preserve.txt`](../../vendir-preserve.txt) (104 files: 100
   configure-generated artifacts + 4 Placeholder stubs that vendir would
   otherwise wipe).

Plus an opt-in fourth phase (`--regenerate`) that runs OpenSSL's Configure
+ make against the cache to *produce* the configure-generated artifacts
fresh, rather than restoring them from HEAD.

## Quickstart

```bash
# Default sync — idempotent against committed state
swift run VendirSync

# Bump upstream version
$EDITOR vendir.yml                                    # change ref:
$EDITOR vendir-upstream.json                          # change ref to match
swift run VendirSync                                  # → drift error
swift run VendirSync --regenerate                     # produces new artifacts
git diff                                              # review
git commit -am "Bump openssl to <new-tag>"

# Run the unit tests (37 tests in 7 suites)
swift test
```

## Common workflows

### Routine sync (no upstream changes)

```bash
swift run VendirSync
```

Expected output:

```
[1/3] PreSync: cache already at openssl-3.6.2, skipping fetch
[2/3] vendir sync
[3/3] restore: 104 preserved path(s) from vendir-preserve.txt
[4/4] drift check: upstream sha matches last regenerate
VendirSync: done
```

Working tree should be clean afterward (`git status` shows nothing
modified). The default sync is idempotent against committed state — that's
how you know it's working correctly.

### Bumping the upstream openssl version

End-to-end procedure for going from `openssl-X.Y.Z` to `openssl-A.B.C`:

```bash
# 1. Edit both pin locations
sed -i.bak 's|openssl-X.Y.Z|openssl-A.B.C|' vendir.yml
sed -i.bak 's|openssl-X.Y.Z|openssl-A.B.C|' vendir-upstream.json
rm vendir.yml.bak vendir-upstream.json.bak

# 2. Run sync — PreSync re-clones the cache at the new ref;
#    drift check fires because lastRegenSha != new sha
swift run VendirSync                  # exits 1 with drift message

# 3. Regenerate configure-generated artifacts at the new upstream
swift run VendirSync --regenerate     # exits 0; updates lastRegenSha

# 4. Verify
swift build && swift test

# 5. Review diff (vendor sources + configure-generated files + lock file)
git diff
git status

# 6. Commit
git commit -am "Bump openssl to A.B.C"
```

If `swift build` fails after step 4 with missing identifiers (e.g.,
`OSSL_CMP_PKISTATUS_*`), the upstream bump changed a `.h.in` template that
our generated headers depend on — `--regenerate` already handled it.
Otherwise, an algorithm-flag mismatch between `Configure.flags` and the
new upstream's expectations may need investigation in
[`Sources/VendirSync/Regenerate.swift`](Regenerate.swift).

### Modifying the algorithm-disable list

When swift-openssl wants to enable or disable an OpenSSL algorithm:

1. Edit `Configure.flags` in
   [`Sources/VendirSyncLib/Configure.swift`](../VendirSyncLib/Configure.swift)
   to add/remove the `no-<alg>` entry.
2. Update the corresponding `excludePaths` in [`vendir.yml`](../../vendir.yml)
   if vendor sources for the algorithm should now be included/excluded.
3. Run `swift run VendirSync --regenerate` to produce updated artifacts.
4. Run `swift build && swift test`.
5. Commit all three changes (Configure.swift + vendir.yml + regenerated
   `Sources/libcrypto/include/openssl/configuration.h`) together.

The Configure flag list, vendir.yml excludePaths, and `OPENSSL_NO_*`
defines in `configuration.h` are **triple-encoded** — they must stay
synchronized.

### Adding a new configure-generated file

If a newer OpenSSL release introduces a new `.h.in` or `.c.in` template
that the build needs:

1. Add its expected post-extraction path to
   [`vendir-preserve.txt`](../../vendir-preserve.txt) (in the appropriate
   grouping section).
2. Run `swift run VendirSync --regenerate`.
3. Verify the new file appears under `Sources/libcrypto/`.

Conversely, if upstream removes a generated file: remove its entry from
`vendir-preserve.txt` before the next regen, otherwise the restore step
will fail trying to checkout a no-longer-tracked path.

## Drift detection

After every default sync, VendirSync compares the upstream sha (current
clone HEAD) against the `lastRegenSha` field in `vendir-upstream.json`:

| State | Behavior | Exit |
|---|---|---|
| `lastRegenSha` unset (first run, bootstrap) | Skips check with informational message. | 0 |
| `sha == lastRegenSha` | Prints "drift check: upstream sha matches last regenerate". | 0 |
| `sha != lastRegenSha` | Prints both shas + "Run `swift run VendirSync --regenerate`". | 1 |

The drift check is the safety net catching the "I bumped vendir.yml's ref
but forgot to regenerate" failure mode. It leverages git's tree hashing —
no parallel hash snapshot file is maintained.

## File reference

| File | Owner | Lifecycle |
|---|---|---|
| [`vendir.yml`](../../vendir.yml) | vendir CLI | Hand-edited on bumps. Read by `vendir sync` directly. |
| [`vendir-upstream.json`](../../vendir-upstream.json) | VendirSync | `url`/`ref` hand-edited on bumps. `sha`, `committedAt`, `committedAtEpoch`, `lastRegenSha` machine-written. |
| [`vendir-preserve.txt`](../../vendir-preserve.txt) | Hand-curated | Adjusted only when upstream's generated set changes (rare). |
| `vendir.lock.yml` | vendir CLI | Auto-generated, gitignored. Information-free under `directory:` source — real provenance lives in `vendir-upstream.json`. |
| `.vendir-cache/openssl/` | PreSync | Gitignored. Single shallow clone reused by all `directory:` sources in vendir.yml. |

## Architecture

Library + thin executable shell:

```
Sources/
├── VendirSyncLib/                ← pure logic, unit-testable
│   ├── UpstreamConfig.swift      ← Codable schema + driftState
│   └── Configure.swift           ← target, flags, path rewrites, manifest parsing
└── VendirSync/                   ← executable shell, process orchestration
    ├── main.swift                ← entry point, helpers, argument parsing
    ├── PreSync.swift             ← git clone/fetch/timestamp capture
    └── Regenerate.swift          ← Configure + make orchestration
```

Pure logic lives in `VendirSyncLib` so it can be exercised by unit tests
without mocking out `Process`. Tests in
[`Tests/VendirSyncLibTests/`](../../Tests/VendirSyncLibTests/) cover:

- `UpstreamConfig` decode/round-trip and all four `driftState` cases.
- `Configure.upstreamPath` for each prefix-rewrite rule.
- `Configure.parsePreserveManifest` against synthetic + the real
  production manifest.
- `Configure.generatedFileMap` produces the expected ~100 entries.
- `Configure.flags` hygiene (no duplicates, `no-*` convention).

## Troubleshooting

### "vendir.yml not found in current working tree"

You're running `swift run VendirSync` from outside the repo. Run it from
the swift-openssl directory or any subdirectory.

### "Configure failed: …" during `--regenerate`

Most often: a flag mismatch with the new upstream's expected option set.
Check the output for `unknown option`. Edit `Configure.flags` in
[`Sources/VendirSyncLib/Configure.swift`](../VendirSyncLib/Configure.swift)
to remove the deprecated flag, then retry.

### Drift check fires but no upstream change happened

`vendir-upstream.json`'s `sha` field was somehow updated without
`lastRegenSha` being refreshed. Run `--regenerate` to align them, or
manually edit `lastRegenSha` to match `sha` if you've verified
configure-generated artifacts are correct as committed.

### `swift build` fails with missing OpenSSL identifiers after a bump

The `.h.in` templates changed in upstream. Run
`swift run VendirSync --regenerate` and rebuild.

### Stale `.vendir-tmp-*/` directories at repo root

`vendir sync` was interrupted before atomic-replace completed. Safe to
delete: `rm -rf .vendir-tmp-*/`. They're already gitignored.

### Default sync wiped my `--regenerate` output

Expected. The default sync's restore step pulls all 104 preserve-list
paths from git HEAD, overwriting un-committed `--regenerate` output. The
intended workflow is: run `--regenerate`, review the diff, commit. Don't
run a default sync between regenerate and commit.

### iOS/tvOS/watchOS/visionOS build failures referencing VendirSync

If you see compile errors in `Sources/VendirSync/main.swift` from
xcodebuild for non-macOS platforms, the conditional-compilation gates in
the `Sources/VendirSync/*.swift` files were broken. Each file must wrap
its body in `#if os(macOS) || os(Linux)`. See `main.swift`'s `#else`
stub for the pattern.

## Related docs

- [`vendir.yml`](../../vendir.yml) — declarative vendoring config (read by vendir).
- [`Vendor/AGENTS.md`](../../Vendor/AGENTS.md) — legacy subtree procedures (planned for retirement once subtree is fully removed).
- [`Sources/AGENTS.md`](../AGENTS.md) — Swift target boundaries.
- [`SWIFT_VENDIR_PLAN.md`](../../SWIFT_VENDIR_PLAN.md) — future extraction into a standalone `swift-vendir` package.
- [Carvel vendir docs](https://carvel.dev/vendir/docs/v0.45.x/) — upstream tool documentation.
