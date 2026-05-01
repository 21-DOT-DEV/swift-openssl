# Migrating from subtree to vendir — Playbook

A phased checklist for replacing the `subtree` CLI with [Carvel's `vendir`](https://carvel.dev/vendir/) as the source-vendoring mechanism for any Swift package in this ecosystem (`swift-openssl`, `swift-event`, `swift-tor`, `swift-secp256k1`, `swift-boost`, `swift-bitcoin`, etc.).

> **Status**: `swift-openssl` is the reference migration (most complex). Other repos should follow Part 2 and use Part 3 as a troubleshooting index.

---

## TL;DR

1. **Inventory** the current `subtree.yaml` extraction blocks and identify files in `Sources/` that are not reproducible from upstream (generated artifacts, placeholders, patches).
2. **Translate** `subtree.yaml` → `vendir.yml`, being careful about vendir's stricter path constraints and different glob semantics.
3. **Capture** the list of non-reproducible files in a plain-text manifest (`scripts/vendir-preserve.txt`).
4. **Build a small Swift wrapper** (`Tools/VendirSync/`) that runs `vendir sync` then restores the preserved files.
5. **Validate** byte-equivalence: snapshot pre-migration `Sources/`, run the wrapper, `diff -r` the result. Fix every diff.
6. **Remove** `subtree.yaml`, `swift-plugin-subtree` dev dep, and (if it exists) the `Vendor/` directory.
7. **Rewrite** CI workflows, update `AGENTS.md`, update `README.md`.

## When to use this playbook

Use this playbook when a repo has:

- a `subtree.yaml` file at its root,
- a `Vendor/<upstream>/` directory containing a full upstream mirror,
- a dev dependency on `swift-plugin-subtree`, and
- one or more `Sources/<target>/` directories populated by running `subtree extract`.

If the repo only depends on `swift-plugin-subtree` for a different reason, or if it doesn't vendor upstream sources at all, this playbook does not apply.

---

## Part 1 — Concepts

### 1.1 Semantic mapping: `subtree.yaml` → `vendir.yml`

| `subtree.yaml` field | `vendir.yml` equivalent | Notes |
|---|---|---|
| `remote:` | `contents[].git.url` | Same meaning. |
| `ref:` (tag or branch) | `contents[].git.ref` | Same meaning. Tags are preferred; combine with `depth: 1`. |
| `extract[].from:` (globs) | `contents[].includePaths` | See §1.4 for glob semantic differences. |
| `extract[].exclude:` (globs) | `contents[].excludePaths` | Applied after `includePaths`. |
| `extract[].to:` (destination) | `directories[].path` + `contents[].path` | Two-level; see §1.3. |
| (implicit: full upstream mirror in `Vendor/`) | — | vendir skips the mirror entirely; it writes filtered files straight into `Sources/`. |
| (implicit: squash commit on `subtree extract`) | `vendir.lock.yml` | vendir records the upstream sha + tag in a lock file; you commit the resulting working tree yourself. |

### 1.2 Execution model

`vendir sync` does this, in order, per top-level `directories[]` entry:

1. For every `contents[].git`, `git clone` into a fresh `.vendir-tmp-<nnn>/incoming/` directory. **No cross-content cache** — two contents with the same URL and ref clone twice.
2. Apply `includePaths` / `excludePaths` filters inside the incoming clone.
3. Move the filtered tree into `.vendir-tmp-<nnn>/staging/<contents-path>/`.
4. Replace the live `directories[].path` with the staging tree (atomic rename).
5. Clean up tmp directories.

Interruption during step 2 or 3 leaves orphaned `.vendir-tmp-*/` dirs in the repo root. They're safe to delete.

### 1.3 Path semantics (the one you'll trip on)

vendir has a two-level path model:

```yaml
directories:
- path: Sources/libcrypto         # <-- the filesystem root vendir will write to
  contents:
  - path: providers               # <-- sub-path under the directory root
    git: { ... }
    includePaths:
    - providers/**/*.c            # <-- upstream-relative path
```

Final filesystem layout: `Sources/libcrypto/providers/providers/**/*.c` — note the **doubled `providers/`**. This is because vendir preserves the upstream-relative path of each included file, rooted under `contents[].path`. The upstream file `providers/common/foo.c` becomes `<directory-path>/<contents-path>/providers/common/foo.c`.

Three ways to control this:

- **Accept the doubling** and reference the doubled path in `Package.swift`'s `headerSearchPath(...)` values. Simplest; no transformation logic.
- **Use `newRootPath:`** to strip a prefix: `newRootPath: providers` turns upstream `providers/common/foo.c` into `common/foo.c`, which then gets placed at `<directory>/<contents>/common/foo.c`.
- **Use `path: .`** for the contents entry, which elides the sub-path. But **only one contents entry per directory can use `path: .`** — vendir rejects configs where multiple contents collide on the same path.

### 1.4 Glob semantics

vendir uses [gitignore-style globs](https://git-scm.com/docs/gitignore#_pattern_format) evaluated by Go's `doublestar` library. Key differences from bash/zsh globbing:

| Pattern | Behavior |
|---|---|
| `*` | Matches any sequence **within a single path segment** (not across `/`). |
| `**` | Matches across path segments. `providers/**/*.c` matches `providers/foo.c` **and** `providers/a/b/c.c`. |
| `?` | Single character. |
| `[abc]` | Character class. |
| `{a,b}` | **Not supported.** Brace expansion does not work in vendir. Expand manually. |
| Extension-specific | `**/*.c` matches only `.c` files. `**/*ml_dsa*` matches `.c`, `.h`, `.inc` equally. |

**Critical**: `excludePaths` can accidentally filter out included headers if a pattern is broader than intended. See Edge Case §3.6.

### 1.5 What vendir manages vs. what you preserve

vendir owns every path under each `directories[].path`. On each sync:

- **Files matching `includePaths` minus `excludePaths`**: written.
- **Everything else under the directory**: deleted (vendir replaces the entire directory atomically).

That means any file you've committed under a `directories[].path` that isn't produced by upstream + filters will be wiped by `vendir sync`. In practice you will always have some of these:

- **Configure-generated artifacts** — e.g., `Sources/libcrypto/include/openssl/asn1.h`, produced by OpenSSL's Perl `Configure` from `asn1.h.in`. Not in upstream git tree.
- **Project-local stubs** — e.g., `Sources/libssl/src/Placeholder.c`, added so SwiftPM sees a non-empty target before the first sync.
- **Patches** — if you apply local modifications on top of upstream (rare in this ecosystem; not covered here).

The playbook's core pattern: **maintain a plain-text manifest of these paths, and restore them after every `vendir sync`**.

---

## Part 2 — The migration recipe (phased checklist)

Each phase lists its commands, deliverables, and a "before moving on" gate. Do not skip gates.

### Phase 0 — Snapshot and branch

```bash
git checkout -b migrate-to-vendir
rsync -a Sources/ /tmp/<repo>-sources-before/
```

The rsync copy is the **pre-migration snapshot** for the Phase 4 byte-diff. Do not regenerate it later — it's your source of truth.

**Gate**: You have a clean git state and a snapshot outside the repo.

### Phase 1 — Inventory

Goal: know exactly what subtree produces and what it doesn't.

```bash
# What does subtree.yaml claim to extract?
cat subtree.yaml

# What's actually in Sources/ that's NOT reproducible from upstream?
# (Run this BEFORE touching subtree — requires the working subtree tooling.)
swift package --build-path .build/subtree \
  --allow-writing-to-package-directory \
  subtree extract --name <subtree-name> --clean

# Anything still present in Sources/ after --clean is non-reproducible.
# Capture it:
find Sources -type f ! -name '.DS_Store' > /tmp/preserve-candidates.txt
```

Review `/tmp/preserve-candidates.txt`. For each file, classify as:

- **Generated artifact** (produced by upstream's build system from a template).
- **Project-local stub** (e.g., `Placeholder.c`).
- **Uninteresting leftover** (build cache, editor file) — exclude from the manifest.

**Gate**: You have a list of every non-upstream file that must survive sync.

### Phase 2 — Author `vendir.yml`

Translate each `subtree.yaml` extraction block into a `vendir.yml` `contents` entry. Reference the mapping table in §1.1 and the path semantics in §1.3.

Starter template (adapt paths and extract blocks):

```yaml
apiVersion: vendir.k14s.io/v1alpha1
kind: Config
minimumRequiredVersion: 0.45.0

directories:

- path: Sources/<target>
  contents:
  - path: .
    git: &upstream
      url: https://github.com/<org>/<repo>
      ref: <tag>
      depth: 1
      skipInitSubmodules: true
    includePaths:
    - <upstream-path>/**/*.c
    - <upstream-path>/**/*.h
    excludePaths:
    - "**/*_test*"
    legalPaths: []
```

Key items to include from the start:

- `depth: 1` — shallow clone of just the pinned tag. Large speed/bandwidth win.
- `skipInitSubmodules: true` — OpenSSL and most upstream repos bundle submodules you don't want.
- `legalPaths: []` — disable vendir's default auto-inclusion of `LICENSE`/`COPYING`/`NOTICE`. If you want these, re-enable selectively.
- YAML anchor `&upstream` on the first `git:` block; alias with `*upstream` on subsequent blocks to keep the URL/ref in one place. Do not define the anchor as a top-level key — vendir's strict schema rejects unknown top-level keys (see Edge Case §3.1).

**Gate**: `vendir sync --dry-run` succeeds (validates the config; does not fetch).

### Phase 3 — Capture the preserved-files manifest

Create `scripts/vendir-preserve.txt`:

```
# Files in Sources/ that vendir does NOT produce and MUST be preserved
# across every `vendir sync`. One path per line, relative to repo root.
# Comments start with #. Blank lines are ignored.

# === Generated public headers (from .h.in templates) ===
Sources/libcrypto/include/openssl/asn1.h
# ... etc

# === Project-local stubs ===
Sources/libcrypto/include/Placeholder.h
Sources/libssl/src/Placeholder.c
```

Commit this file. It's your long-lived contract for what the wrapper restores.

**Gate**: Every file in `/tmp/preserve-candidates.txt` (minus leftover junk) is either in the manifest or explicitly out-of-scope.

### Phase 4 — Author the `Tools/VendirSync/` wrapper

Create a minimal Swift executable that:

1. Runs `vendir sync`.
2. Restores every path in `scripts/vendir-preserve.txt` via `git checkout HEAD -- <path>`.
3. Exits non-zero if either step fails.

Skeleton `Package.swift` addition (add to `products` and `targets`):

```swift
.executableTarget(
    name: "VendirSync",
    path: "Tools/VendirSync"
),
```

Skeleton `Tools/VendirSync/main.swift`:

```swift
import Foundation

// 1. Run `vendir sync`.
let vendir = Process()
vendir.executableURL = URL(fileURLWithPath: "/usr/bin/env")
vendir.arguments = ["vendir", "sync"]
try vendir.run()
vendir.waitUntilExit()
guard vendir.terminationStatus == 0 else {
    FileHandle.standardError.write(Data("vendir sync failed\n".utf8))
    exit(Int32(vendir.terminationStatus))
}

// 2. Restore preserved files.
let manifestURL = URL(fileURLWithPath: "scripts/vendir-preserve.txt")
let manifest = try String(contentsOf: manifestURL, encoding: .utf8)
let paths = manifest
    .split(separator: "\n")
    .map { $0.trimmingCharacters(in: .whitespaces) }
    .filter { !$0.isEmpty && !$0.hasPrefix("#") }

guard !paths.isEmpty else { exit(0) }

let restore = Process()
restore.executableURL = URL(fileURLWithPath: "/usr/bin/env")
restore.arguments = ["git", "checkout", "HEAD", "--"] + paths
try restore.run()
restore.waitUntilExit()
exit(restore.terminationStatus)
```

Invocation: `swift run VendirSync`.

Do not over-engineer the wrapper. It's a two-step orchestrator. Add features (caching, parallelism, byte-diff mode) only when a concrete need appears.

**Gate**: `swift run VendirSync` completes with exit code 0 on a clean checkout.

### Phase 5 — Byte-diff validation

This is the go/no-go gate for the migration.

```bash
# Run the wrapper against the pre-migration snapshot.
swift run VendirSync

# Compare the post-sync Sources/ against the snapshot taken in Phase 0.
diff -r /tmp/<repo>-sources-before/ Sources/ > /tmp/migration.diff
wc -l /tmp/migration.diff
```

**Interpreting the output**:

- **Zero lines** — perfect equivalence. Proceed.
- **Only `Only in /tmp/.../<leftover>:` lines** — the snapshot had files vendir correctly removed (e.g., `.DS_Store`, old subtree-extracted files that should no longer exist). Verify each, then proceed.
- **`Only in Sources/:` lines** — vendir produced files subtree didn't. Likely an over-broad `includePaths`. Tighten the include or add an exclude.
- **`Only in /tmp/.../:` lines for non-preserved files** — vendir missed files subtree included. Likely a missed `includePaths` entry or an over-broad `excludePaths`. See Edge Case §3.6.
- **`differ` lines** — file content mismatch. Usually a path-transformation issue (wrong `newRootPath`) or line-ending difference. Investigate each one.

Iterate on `vendir.yml` and `scripts/vendir-preserve.txt` until the diff is clean. **Do not skip diffs as "probably fine"** — that's how silent drift gets committed.

**Gate**: `diff -r` produces zero interesting lines. Document every "uninteresting" category in the commit message.

### Phase 6 — Remove subtree artifacts

Once Phase 5 is clean:

```bash
git rm subtree.yaml
git rm -r Vendor/
# Edit Package.swift: remove the swift-plugin-subtree dependency.
# Edit subtree.yaml references in .github/workflows/.
```

**Gate**: `swift build` and `swift test` pass on macOS and Linux (`docker build .`).

### Phase 7 — Rewrite CI

The common workflows in this ecosystem are:

- `check-subtree-updates.yml` — scheduled poll for upstream tag changes, opens a PR when one exists.
- `update-subtree.yml` — `workflow_dispatch` that runs the extraction and opens a PR.

Replace both with a single `check-vendir-updates.yml`:

```yaml
# Pseudocode outline — adapt to your org's patterns.
- uses: vmware-tanzu/carvel-setup-action@v2
  with: { only: vendir }
- run: swift run VendirSync
- uses: peter-evans/create-pull-request@v6
  with:
    commit-message: "chore: vendir sync"
    branch: vendir/sync
```

Remove both old workflows.

**Gate**: CI green on a PR that bumps the `ref:` in `vendir.yml`.

### Phase 8 — Documentation sweep

Update each of these:

- `README.md` — replace any mention of `subtree` commands with `swift run VendirSync`.
- `AGENTS.md` (root and scoped) — the "Commands" and "Non-obvious patterns" sections. Remove the subtree extraction/update recipe; add the vendir recipe and the preserved-files rule.
- `Vendor/AGENTS.md` — delete (the directory is gone).
- `.specify/memory/constitution.md` — if it references subtree by name, generalize to "vendored sources".

**Gate**: Grep for `subtree` across the repo returns only historical references (commit logs, CHANGELOG entries).

---

## Part 3 — Edge cases

Each entry: **symptom** → **root cause** → **fix** → **swift-openssl worked example** (when applicable).

### 3.1 Vendir rejects top-level YAML anchor holder key

**Symptom**: `vendir sync` fails with `schema validation error: unknown key '_openssl_git'`.

**Root cause**: vendir's config uses strict schema validation. Unknown top-level keys (even ones you intend as anchor holders) are rejected.

**Fix**: Define the anchor inline on the first use of `git:`, then alias subsequent occurrences:

```yaml
directories:
- path: Sources/libssl/src
  contents:
  - path: .
    git: &openssl
      url: https://github.com/openssl/openssl
      ref: openssl-3.6.2
      depth: 1
      skipInitSubmodules: true
    # ...
- path: Sources/libcrypto
  contents:
  - path: include
    git: *openssl    # alias, no re-declaration
    # ...
```

**swift-openssl example**: The current `vendir.yml` uses this pattern to DRY 5 `git:` blocks into one anchor.

### 3.2 Overlapping `directories[].path`

**Symptom**: `vendir sync` fails with `directories '<a>' and '<b>' overlap`.

**Root cause**: vendir requires every `directories[].path` to be disjoint — no entry's path may be a prefix of another's.

**Fix**: Hoist the common prefix into one directory with multiple `contents`, each using a distinct `path:`.

**swift-openssl example**: Initially `Sources/libcrypto`, `Sources/libcrypto/include`, `Sources/libcrypto/providers`, etc. were all top-level directories and overlapped. Collapsed to a single `- path: Sources/libcrypto` with 4 sub-contents (`include`, `internal_include`, `providers`, `src`).

### 3.3 Multiple contents with `path: '.'`

**Symptom**: `vendir sync` fails with `multiple contents entries at path '.'`.

**Root cause**: Within one `directories[]`, only **one** contents entry may use `path: .`. Multiple contents need distinct sub-paths to avoid writing over each other.

**Fix**: Give each contents entry a unique `path:` value. If you want the files to end up at the same location, use `newRootPath:` on each to strip differing upstream prefixes, or accept doubled path segments (§3.4).

### 3.4 Doubled path prefixes (`providers/providers/...`)

**Symptom**: Files end up at `Sources/libcrypto/providers/providers/common/foo.c` instead of `Sources/libcrypto/providers/common/foo.c`. Header search paths in `Package.swift` are wrong.

**Root cause**: vendir preserves full upstream-relative paths under `contents[].path`. Upstream `providers/common/foo.c` + `contents[].path: providers` → `<directory>/providers/providers/common/foo.c`.

**Fix options**:

1. **Accept the doubling** and update `Package.swift`: `headerSearchPath("providers/providers/common/include")`. Pragmatic and self-documenting.
2. **Use `newRootPath:`**: `newRootPath: providers` strips the upstream prefix. Result: `<directory>/providers/common/foo.c`. Cleaner output, requires matching `newRootPath:` on every related contents entry.
3. **Use `contents[].path: .`**: results in `<directory>/providers/common/foo.c`. But can only be used on one contents entry per directory.

**swift-openssl example**: We chose option 1 (doubled paths) because `Package.swift` already referenced `providers/providers/...` from the subtree era — no downstream changes needed.

### 3.5 Auto-inclusion of `LICENSE`, `COPYING`, `NOTICE`

**Symptom**: After `vendir sync`, `Sources/` contains `LICENSE` files even though your `includePaths` don't mention them.

**Root cause**: vendir auto-includes legal files (anything matching `LICENSE*`, `COPYING*`, `NOTICE*`) unless explicitly told not to.

**Fix**: Add `legalPaths: []` to every `contents` entry:

```yaml
- path: providers
  git: *openssl
  includePaths: [ ... ]
  excludePaths: [ ... ]
  legalPaths: []
```

If you **do** want to vendor the upstream license, use `legalPaths: [LICENSE]` explicitly. Don't rely on the default.

### 3.6 Merged extraction blocks over-exclude headers

**Symptom**: `vendir sync` succeeds and `swift build` fails with missing header errors, even though the exclude patterns look "reasonable." The missing headers match one of your exclude patterns' substring but have a different extension than the sources you meant to filter.

**Root cause**: When two `subtree.yaml` extraction blocks (e.g., "headers, no excludes" + "sources, broad excludes") are merged into one vendir `contents` entry with the union of their includes and the union of their excludes, source-only filters start applying to header files too.

**Fix**: Scope exclude patterns by file extension (`.c`, `.inc`) when the pattern family refers to source files. Example:

```yaml
# WRONG — filters both ml_dsa_codecs.h (wanted) and ml_dsa_sig.c (unwanted):
- "**/ml_dsa_*"

# RIGHT — filters only sources:
- "**/ml_dsa_*.c"
- "**/ml_dsa_*.inc"
```

**Prevention**: When merging two blocks into one, audit every exclude pattern against the header set. For each pattern, run:

```bash
find <upstream> -path '*/include/*' -name '<pattern-core>*' -exec echo "AT-RISK: {}" \;
```

**swift-openssl example**: The merger of subtree's block 4 (provider headers, zero excludes) and block 5 (provider sources, 50+ broad excludes) into one vendir contents silently dropped `ml_dsa_codecs.h`, `ml_kem_codecs.h`, and `mlx_kem.h` because patterns like `**/ml_dsa_*` matched the codec headers. Byte-diff caught all three. Fix: scope those specific patterns to `.c`/`.inc`.

### 3.7 Configure-generated files (not in upstream)

**Symptom**: Build fails with `'openssl/asn1t.h' file not found` after `vendir sync`, even though everything else looks correct.

**Root cause**: The upstream project's build system generates source files from `.h.in` / `.c.in` templates (common in OpenSSL 3.6+, autotools projects). These files are **not in upstream git** — they're produced by running `./Configure` + `make build_all_generated`. You commit them under `Sources/` as artifacts. vendir wipes them on every sync because they live under a path it manages.

**Fix**: Add every generated artifact path to `scripts/vendir-preserve.txt`. The wrapper restores them from `git HEAD` after each sync. When upstream bumps a version that changes any `.h.in` or `.c.in` template, regenerate the artifacts once (via a one-off `regenerate-configure.sh`) and commit the updated copies.

**swift-openssl example**: 100 Configure-generated files under `Sources/libcrypto/**`. The manifest lives at `scripts/configure-generated-files.txt` (to be renamed `scripts/vendir-preserve.txt`).

### 3.8 Project-local stubs wiped by sync

**Symptom**: `Placeholder.h` or `Placeholder.c` disappears after `vendir sync`. SwiftPM complains about empty targets on a fresh clone.

**Root cause**: Same as §3.7 — files committed under a vendir-managed path that aren't produced by filters.

**Fix**: Add them to the same preserve manifest:

```
Sources/libcrypto/include/Placeholder.h
Sources/libcrypto/src/Placeholder.c
Sources/libssl/src/Placeholder.c
```

**Alternative**: Move the stubs outside the vendir-managed tree (e.g., `Sources/libcrypto/Stubs/Placeholder.c`) and keep the target path set in `Package.swift`. Cleanest separation; no preserve step.

### 3.9 Redundant per-contents clones

**Symptom**: `vendir sync` takes a long time and appears to clone the same repo multiple times.

**Root cause**: vendir clones once **per `contents[].git`**, even when URL+ref are identical. There is no cross-content cache.

**Fixes**:

- **Minimum**: add `depth: 1` to the shared git source. A shallow clone of a pinned tag is small and fast.
- **Optional (future evolution)**: maintain a shared bare clone outside vendir and use vendir's `directory:` source type to point at it. See §4.3. Costs lock-file provenance — trade-off, not always worth it.

**swift-openssl example**: 5 clones for one OpenSSL repo. With `depth: 1`, sync completes in ~30s. Without `depth: 1`, the sync is slow enough to appear hung.

### 3.10 Stale `.vendir-tmp-*` directories

**Symptom**: `.vendir-tmp-226887257/`, `.vendir-tmp-2276066684/`, etc. accumulate at the repo root.

**Root cause**: `vendir sync` was interrupted (Ctrl-C, OOM, crash) before cleanup.

**Fix**: Safe to delete manually: `rm -rf .vendir-tmp-*`. Add the glob to `.gitignore`:

```
# Vendir staging directories (cleaned up on successful sync)
.vendir-tmp-*/
```

### 3.11 `vendir sync` appears to hang

**Symptom**: `vendir sync` prints the "Fetching" line and produces no output for several minutes.

**Root cause**: A full (non-shallow) clone of a large upstream repo. OpenSSL's history is ~800 MB+; fetching all of it over a slow network looks indistinguishable from a hang.

**Fix**: Always use `depth: 1` when your `ref:` is a tag. Tags are stable references, so shallow fetch is safe.

### 3.12 `skipInitSubmodules` and submodule gitlinks

**Symptom**: Unwanted submodule pointers appear in the sync output, or CI fails with "submodule not initialized."

**Root cause**: Upstream repos often contain their own submodules (testing frameworks, documentation generators). vendir by default runs `git submodule update --init`, pulling in content you don't want.

**Fix**: Add `skipInitSubmodules: true` to every `git:` block:

```yaml
git: &upstream
  url: ...
  ref: ...
  depth: 1
  skipInitSubmodules: true
```

This parallels the `--strip-gitlinks` concept in the old `subtree` CLI (which stripped mode-160000 index entries post-extraction to placate SPI). vendir handles it at clone time instead.

### 3.13 Lock file semantics

**Symptom**: Unsure whether to commit `vendir.lock.yml`.

**Fix**: **Commit it.** It pins the exact upstream commit sha for every `contents[].git`, giving you a reproducible sync regardless of whether upstream force-pushes a tag. Treat it like `Package.resolved`.

The lock file is the vendir equivalent of subtree's squash commit metadata: it records upstream provenance. Without it, your `Sources/` tree becomes un-auditable.

### 3.14 Selective sync (`--directory` flag)

**Symptom**: `vendir sync --directory Sources/libcrypto/include` fails with `did not match any`.

**Root cause**: The `--directory` flag requires an **exact** match against one of the `directories[].path` values in `vendir.yml`. Subpaths of those values don't work.

**Fix**: Use the top-level path: `vendir sync --directory Sources/libcrypto`. This re-syncs every `contents` entry under that directory.

For finer-grained control, temporarily comment out unrelated `contents` entries during development. There is no per-contents selective sync.

### 3.15 (Untested) gitlab remotes

`swift-tor` vendors from `gitlab.torproject.org`. vendir's git source should support any git-clonable URL, but this migration path hasn't been exercised yet. Expect potential issues with:

- HTTPS vs SSH URL selection in CI (personal tokens vs deploy keys).
- Rate-limited fetches on slow gitlab mirrors.

### 3.16 (Untested) multi-upstream configs

`swift-secp256k1` vendors from three upstreams (`secp256k1`, `secp256k1-zkp`, `swift-crypto`). The anchor DRY pattern in §3.1 assumes one upstream. With multiple, you'd define multiple anchors (`&secp256k1`, `&zkp`, `&crypto`) or forgo DRY and repeat the git blocks.

### 3.17 (Untested) overlays/patches

If a repo applies local patches on top of upstream (none currently in this ecosystem), `vendir` supports [overlay](https://carvel.dev/vendir/docs/latest/overlays/) processing via `ytt`-based patches. Not covered in this playbook.

---

## Part 4 — Tooling reference

### 4.1 `Tools/VendirSync/` design

**Responsibilities**:

1. Run `vendir sync` (inheriting stdout/stderr).
2. After success, restore every path in `scripts/vendir-preserve.txt` from `git HEAD`.
3. Exit with the failing subprocess's exit code if either step fails.

**Non-responsibilities** (by design):

- Byte-diff validation. That's a one-time migration gate, not an ongoing sync concern.
- Upstream version bumping. That's `sed -i 's/openssl-3.6.2/openssl-3.6.3/' vendir.yml` or a CI PR bot.
- Regenerating `.h.in` / `.c.in` artifacts. That's a separate `scripts/regenerate-configure.sh`, run only when templates change.

**Dependencies**: `Foundation` only. No external SwiftPM dependencies. `Process` suffices for the subprocess orchestration.

### 4.2 Preserve-list manifest format

Path: `scripts/vendir-preserve.txt`.

```
# Comments start with #. Blank lines ignored.
# Paths are relative to repo root. One per line.
# Order doesn't matter.

# === Grouping comments are optional but recommended ===
Sources/libcrypto/include/openssl/asn1.h
Sources/libcrypto/include/openssl/asn1t.h

# === Project-local stubs ===
Sources/libcrypto/include/Placeholder.h
```

Globs are **not** supported by the wrapper. If a subdir needs wholesale preservation, list every file. This is intentional — globs hide drift when upstream adds a matching file you didn't expect.

### 4.3 Future evolution: shared bare-clone cache

The #1 remaining inefficiency is the per-contents clone (§3.9). Mitigation path:

1. Pre-sync step: `git clone --bare --depth 1 <url> .vendir-cache/<repo>` (or `git fetch` if already present).
2. Change every `git:` block in `vendir.yml` to a `directory:` block pointing at `.vendir-cache/<repo>`.
3. Add `.vendir-cache/` to `.gitignore`.

**Cost**: `vendir.lock.yml` loses upstream provenance — it records the local path, not the upstream sha. Mitigate by having the pre-sync step emit a sidecar file recording the upstream sha. Not a drop-in equivalent.

**Decision**: Defer unless `vendir sync` wall time becomes a developer-loop pain point.

### 4.4 Future evolution: SwiftPM plugin

If the `Tools/VendirSync/` executable gets copy-pasted across 5+ repos and starts drifting, extract it into `swift-plugin-vendir` — a SwiftPM plugin paralleling the existing `swift-plugin-subtree`. The plugin would:

- Ship the sync logic once.
- Expose `swift package vendir-sync` as a command.
- Use the conditional-dev-dep pattern (exclude from tagged releases via `Context.gitInformation?.currentTag`).

**Decision**: Defer until concrete drift appears. YAGNI until it isn't.

---

## Part 5 — Repo-specific appendix template

Each repo that migrates should append its own section to this file (or copy this playbook and fill in their section). Template:

```markdown
## Appendix: <repo-name>

**Migrated on**: <date>
**Upstream**: <url> @ <tag>
**Sync wrapper**: Tools/VendirSync/ (commit <sha>)
**Preserve manifest**: scripts/vendir-preserve.txt (<N> entries)

### Notable edge cases encountered

- [§3.X] <one-line summary of how this edge case manifested here>

### Byte-diff status

- Final diff: <N> lines, all accounted for.
- Categories: <e.g., "removed: old .DS_Store files; differs: none">

### Regeneration recipe (if applicable)

- scripts/regenerate-configure.sh ...
- Trigger: <when to run>
```

---

## Part 6 — Ongoing operations

### 6.1 Bumping upstream version

```bash
# Edit vendir.yml: change the `ref:` in the shared anchor.
sed -i '' 's/openssl-3.6.2/openssl-3.6.3/' vendir.yml

# Sync and restore preserved files.
swift run VendirSync

# Check whether any .h.in or .c.in templates changed.
#   If yes, run the project's regenerate-configure recipe and commit.
#   If no, preserved files from HEAD are still valid.

# Verify.
swift build && swift test
```

Commit `vendir.yml`, `vendir.lock.yml`, and the updated `Sources/` in one atomic commit with a structured message:

```
chore(vendir): bump openssl to 3.6.3

vendir.lock.yml: fe686e1 -> 7a2b3c4
```

### 6.2 Scope changes (adding/removing files)

Edit `includePaths` / `excludePaths` in `vendir.yml`. Run `swift run VendirSync`. Diff against pre-change `Sources/` tree to verify only the intended files changed:

```bash
rsync -a Sources/ /tmp/before/
# edit vendir.yml
swift run VendirSync
diff -r /tmp/before/ Sources/
```

### 6.3 Investigating unexpected drift

If a sync introduces unexpected file changes:

1. `diff -r /tmp/<snapshot>/ Sources/` — confirm what changed.
2. Check `vendir.lock.yml` — did the upstream sha advance (e.g., moving tag)? If so, that's the real change.
3. Check `vendir.yml` — did anyone edit an `includePaths` / `excludePaths` entry since the last sync?
4. Re-run with a pinned tag and a snapshot restore to isolate.

Treat silent drift as a bug. The preserve manifest, lock file, and diff discipline are your defenses.

---

## References

- [Vendir documentation](https://carvel.dev/vendir/docs/latest/)
- [Vendir GitHub](https://github.com/carvel-dev/vendir)
- [Vendir config reference](https://carvel.dev/vendir/docs/latest/vendir-spec/)
- [The old subtree CLI](https://github.com/21-DOT-DEV/swift-plugin-subtree) (being deprecated by this migration)
- [swift-openssl `vendir.yml`](../vendir.yml) — the reference config
- [swift-openssl `scripts/configure-generated-files.txt`](../scripts/configure-generated-files.txt) — the reference preserve manifest
