// Codable schema for `scripts/vendir-upstream.json` — the single source of
// truth for the upstream pin (`url`, `ref`) and PreSync's bookkeeping (`sha`,
// timestamps, `lastRegenSha`).
//
// Lives in VendirSyncLib so VendirSync's executable shell, plus tests, can
// share the schema. Keep this struct in sync with manual edits to the JSON
// — adding/removing fields here without updating the JSON (or vice versa)
// will surface as a decode error.

import Foundation

public struct UpstreamConfig: Codable, Equatable, Sendable {
    public var url: String
    public var ref: String
    public var sha: String?
    public var fetchedAt: String?
    /// ISO 8601 timestamp of the upstream commit's committer date.
    /// Drives `SOURCE_DATE_EPOCH` for deterministic `buildinf.h` regen.
    public var committedAt: String?
    /// Same value as `committedAt`, but as Unix epoch seconds — the form
    /// `SOURCE_DATE_EPOCH` consumes directly.
    public var committedAtEpoch: Int?
    /// Upstream commit sha at the last successful `--regenerate`. Drift
    /// check compares this against `sha`; mismatch prompts the maintainer
    /// to run `--regenerate`. Leverages git's tree hashing — no parallel
    /// hash snapshot needed.
    public var lastRegenSha: String?

    public init(
        url: String,
        ref: String,
        sha: String? = nil,
        fetchedAt: String? = nil,
        committedAt: String? = nil,
        committedAtEpoch: Int? = nil,
        lastRegenSha: String? = nil
    ) {
        self.url = url
        self.ref = ref
        self.sha = sha
        self.fetchedAt = fetchedAt
        self.committedAt = committedAt
        self.committedAtEpoch = committedAtEpoch
        self.lastRegenSha = lastRegenSha
    }
}

extension UpstreamConfig {
    /// Result of comparing `sha` against `lastRegenSha`. Drives the
    /// default-mode drift check in VendirSync.
    public enum DriftState: Equatable, Sendable {
        /// Either `sha` or `lastRegenSha` is nil — bootstrap state.
        /// Default mode skips the check; first `--regenerate` populates them.
        case noBaseline
        /// Current upstream sha matches the sha at last `--regenerate`.
        case match
        /// Upstream sha has advanced past the last regenerate.
        /// Maintainer should run `--regenerate`.
        case drifted(currentSha: String, lastRegenSha: String)
    }

    /// Compute drift state from the config's `sha` and `lastRegenSha`.
    /// See `DriftState` for the three cases.
    public var driftState: DriftState {
        guard let sha, let lastRegenSha else { return .noBaseline }
        if sha == lastRegenSha { return .match }
        return .drifted(currentSha: sha, lastRegenSha: lastRegenSha)
    }
}
