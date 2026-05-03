import Foundation
import Testing

@testable import VendirSyncLib

@Suite("UpstreamConfig")
struct UpstreamConfigTests {
    @Test("decodes the schema written by PreSync")
    func decodesPreSyncOutput() throws {
        let json = """
            {
              "committedAt" : "2026-04-07T12:17:57Z",
              "committedAtEpoch" : 1775564277,
              "fetchedAt" : "2026-05-01T00:00:00Z",
              "lastRegenSha" : "fe686e15d84334b284f883118ed92f64b409b3aa",
              "ref" : "openssl-3.6.2",
              "sha" : "fe686e15d84334b284f883118ed92f64b409b3aa",
              "url" : "https://github.com/openssl/openssl"
            }
            """
        let config = try JSONDecoder().decode(UpstreamConfig.self, from: Data(json.utf8))

        #expect(config.url == "https://github.com/openssl/openssl")
        #expect(config.ref == "openssl-3.6.2")
        #expect(config.sha == "fe686e15d84334b284f883118ed92f64b409b3aa")
        #expect(config.fetchedAt == "2026-05-01T00:00:00Z")
        #expect(config.committedAt == "2026-04-07T12:17:57Z")
        #expect(config.committedAtEpoch == 1775564277)
        #expect(config.lastRegenSha == "fe686e15d84334b284f883118ed92f64b409b3aa")
    }

    @Test("decodes a minimal config with only required fields")
    func decodesMinimal() throws {
        let json = """
            { "url": "https://example.com/repo", "ref": "v1.0" }
            """
        let config = try JSONDecoder().decode(UpstreamConfig.self, from: Data(json.utf8))

        #expect(config.url == "https://example.com/repo")
        #expect(config.ref == "v1.0")
        #expect(config.sha == nil)
        #expect(config.fetchedAt == nil)
        #expect(config.committedAt == nil)
        #expect(config.committedAtEpoch == nil)
        #expect(config.lastRegenSha == nil)
    }

    @Test("encode/decode round-trip preserves all fields")
    func roundTripsAllFields() throws {
        let original = UpstreamConfig(
            url: "https://github.com/openssl/openssl",
            ref: "openssl-3.6.2",
            sha: "abc123",
            fetchedAt: "2026-05-01T00:00:00Z",
            committedAt: "2026-04-07T12:17:57Z",
            committedAtEpoch: 1775564277,
            lastRegenSha: "abc123"
        )
        let encoded = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(UpstreamConfig.self, from: encoded)
        #expect(decoded == original)
    }

    @Test("driftState is .noBaseline when sha is missing")
    func driftStateNoBaselineWhenShaMissing() {
        let config = UpstreamConfig(
            url: "u", ref: "r", sha: nil,
            lastRegenSha: "deadbeef"
        )
        #expect(config.driftState == .noBaseline)
    }

    @Test("driftState is .noBaseline when lastRegenSha is missing")
    func driftStateNoBaselineWhenLastRegenMissing() {
        let config = UpstreamConfig(
            url: "u", ref: "r", sha: "deadbeef",
            lastRegenSha: nil
        )
        #expect(config.driftState == .noBaseline)
    }

    @Test("driftState is .match when both shas are equal")
    func driftStateMatch() {
        let config = UpstreamConfig(
            url: "u", ref: "r", sha: "abc123",
            lastRegenSha: "abc123"
        )
        #expect(config.driftState == .match)
    }

    @Test("driftState is .drifted when shas differ")
    func driftStateDrifted() {
        let config = UpstreamConfig(
            url: "u", ref: "r", sha: "newsha",
            lastRegenSha: "oldsha"
        )
        #expect(config.driftState == .drifted(currentSha: "newsha", lastRegenSha: "oldsha"))
    }
}
