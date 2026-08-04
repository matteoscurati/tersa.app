// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import XCTest

/// Deterministic tests for the closed, fixed-purpose Keychain isolation canary.
///
/// These tests exercise only pure derivation, parsing, classification, query
/// construction, and evidence mapping. They never call live `SecItem*` and never
/// inspect the host process's real signing entitlements. Fixtures carry no
/// credentials, tokens, or Keychain data; the team prefix is a synthetic
/// placeholder that is never emitted by the probe, and the canary account is a
/// fixed fixture string rather than the runner's per-run UUID.
final class KeychainIsolationProbeTests: XCTestCase {

    // A synthetic, non-real 10-character team prefix. The probe never prints it.
    private let teamPrefix = "TEAM000000"

    private var mainGroup: String { "\(teamPrefix).app.tersa.shared" }
    private var tokenGroup: String { "\(teamPrefix).app.tersa.token" }

    // A fixed, non-emitted account fixture standing in for the runner's per-run
    // random UUID account.
    private let account = "fixture-account"

    // MARK: Opt-in argument contract

    func testExactArgumentAccepted() {
        XCTAssertTrue(
            KeychainIsolationProbe.isProbeRequest(
                ["/usr/bin/tersa", "--tersa-keychain-isolation-probe-v2"]
            )
        )
    }

    func testMissingArgumentRejected() {
        // Only the executable path: not a probe request.
        XCTAssertFalse(KeychainIsolationProbe.isProbeRequest(["/usr/bin/tersa"]))
        // No arguments at all is also not a probe request.
        XCTAssertFalse(KeychainIsolationProbe.isProbeRequest([]))
    }

    func testWrongArgumentRejected() {
        // The stale v1 argument must be rejected so a stale harness cannot
        // silently accept the changed v2 semantics.
        XCTAssertFalse(
            KeychainIsolationProbe.isProbeRequest(
                ["/usr/bin/tersa", "--tersa-keychain-isolation-probe-v1"]
            )
        )
        XCTAssertFalse(
            KeychainIsolationProbe.isProbeRequest(
                ["/usr/bin/tersa", "--help"]
            )
        )
        // A prefix of the argument is not the argument.
        XCTAssertFalse(
            KeychainIsolationProbe.isProbeRequest(
                ["/usr/bin/tersa", "--tersa-keychain-isolation-probe"]
            )
        )
    }

    func testExtraArgumentRejected() {
        XCTAssertFalse(
            KeychainIsolationProbe.isProbeRequest(
                [
                    "/usr/bin/tersa",
                    "--tersa-keychain-isolation-probe-v2",
                    "extra",
                ]
            )
        )
        XCTAssertFalse(
            KeychainIsolationProbe.isProbeRequest(
                [
                    "/usr/bin/tersa",
                    "--tersa-keychain-isolation-probe-v2",
                    "--tersa-keychain-isolation-probe-v2",
                ]
            )
        )
    }

    // MARK: Forbidden-group derivation

    func testMainAppDerivesTokenGroupFromOneValidRootGroup() {
        XCTAssertEqual(
            KeychainIsolationProbe.resolve(
                groups: [mainGroup],
                principal: .mainApp
            ),
            tokenGroup
        )
    }

    func testTokenBrokerDerivesRootGroupFromOneValidTokenGroup() {
        XCTAssertEqual(
            KeychainIsolationProbe.resolve(
                groups: [tokenGroup],
                principal: .tokenBroker
            ),
            mainGroup
        )
    }

    func testDerivationRetainsTeamPrefixExactly() {
        // The forbidden group must reuse the same team prefix verbatim, only
        // swapping the suffix.
        let resolved = KeychainIsolationProbe.resolve(
            groups: ["ABCDE12345.app.tersa.shared"],
            principal: .mainApp
        )
        XCTAssertEqual(resolved, "ABCDE12345.app.tersa.token")
    }

    func testMainAppRejectsTokenSuffixAndViceVersa() {
        // A principal never resolves its own opposite group as input.
        XCTAssertNil(
            KeychainIsolationProbe.resolve(groups: [tokenGroup], principal: .mainApp)
        )
        XCTAssertNil(
            KeychainIsolationProbe.resolve(groups: [mainGroup], principal: .tokenBroker)
        )
    }

    // MARK: Fail-closed configuration cases

    func testEmptyTeamPrefixFailsClosed() {
        // Group is exactly the suffix with no team prefix.
        XCTAssertNil(
            KeychainIsolationProbe.resolve(
                groups: [".app.tersa.shared"],
                principal: .mainApp
            )
        )
        XCTAssertNil(
            KeychainIsolationProbe.resolve(
                groups: [".app.tersa.token"],
                principal: .tokenBroker
            )
        )
    }

    func testWrongSuffixFailsClosed() {
        XCTAssertNil(
            KeychainIsolationProbe.resolve(
                groups: ["\(teamPrefix).app.tersa.other"],
                principal: .mainApp
            )
        )
        // Missing the leading dot before the suffix is not the exact suffix.
        XCTAssertNil(
            KeychainIsolationProbe.resolve(
                groups: ["\(teamPrefix)app.tersa.shared"],
                principal: .mainApp
            )
        )
        // A suffix appearing only as a substring (dotted-suffix attack) must not
        // match: the group must END with the exact suffix.
        XCTAssertNil(
            KeychainIsolationProbe.resolve(
                groups: ["\(teamPrefix).app.tersa.shared.evil"],
                principal: .mainApp
            )
        )
    }

    func testAbsentAndEmptyGroupsFailClosed() {
        XCTAssertNil(
            KeychainIsolationProbe.resolve(groups: nil, principal: .mainApp)
        )
        XCTAssertNil(
            KeychainIsolationProbe.resolve(groups: [], principal: .mainApp)
        )
        // An empty group string is not the suffix.
        XCTAssertNil(
            KeychainIsolationProbe.resolve(groups: [""], principal: .mainApp)
        )
    }

    func testDualGroupsFailClosed() {
        // A dual-group process must never resolve, even if both are valid.
        XCTAssertNil(
            KeychainIsolationProbe.resolve(
                groups: [mainGroup, tokenGroup],
                principal: .mainApp
            )
        )
        XCTAssertNil(
            KeychainIsolationProbe.resolve(
                groups: [mainGroup, tokenGroup],
                principal: .tokenBroker
            )
        )
        // Two copies of the same valid group is still multiple groups.
        XCTAssertNil(
            KeychainIsolationProbe.resolve(
                groups: [mainGroup, mainGroup],
                principal: .mainApp
            )
        )
    }

    // MARK: Entitlement value parsing

    func testParsedGroupsAcceptsArrayOfStrings() {
        let value = [mainGroup] as CFTypeRef
        XCTAssertEqual(
            KeychainIsolationProbe.parsedGroups(from: value),
            [mainGroup]
        )
    }

    func testParsedGroupsAcceptsMultipleAndOrder() {
        let value = [mainGroup, tokenGroup] as CFTypeRef
        XCTAssertEqual(
            KeychainIsolationProbe.parsedGroups(from: value),
            [mainGroup, tokenGroup]
        )
    }

    func testParsedGroupsRejectsAbsentNonArrayAndNonStringElement() {
        XCTAssertNil(KeychainIsolationProbe.parsedGroups(from: nil))
        // A bare string instead of an array is malformed.
        XCTAssertNil(KeychainIsolationProbe.parsedGroups(from: mainGroup as CFTypeRef))
        // Any non-string element makes the whole value malformed.
        let mixed = [mainGroup, 42] as CFTypeRef
        XCTAssertNil(KeychainIsolationProbe.parsedGroups(from: mixed))
        // A number is not an array.
        XCTAssertNil(KeychainIsolationProbe.parsedGroups(from: 42 as CFTypeRef))
    }

    // MARK: Add status classification

    func testOnlyMissingEntitlementPasses() {
        XCTAssertEqual(
            KeychainIsolationProbe.classifyAdd(status: errSecMissingEntitlement),
            .missingEntitlement
        )
        XCTAssertEqual(
            KeychainIsolationProbe.exitCode(for: .missingEntitlement),
            0
        )
    }

    func testAddSuccessMeansBarrierBroken() {
        // A successful add is the barrier-broken outcome that triggers cleanup;
        // it is never a pass.
        XCTAssertEqual(
            KeychainIsolationProbe.classifyAdd(status: errSecSuccess),
            .unexpectedlyAuthorized
        )
        XCTAssertNotEqual(
            KeychainIsolationProbe.exitCode(for: .unexpectedlyAuthorized),
            0
        )
    }

    func testArbitraryAddStatusFailsAsUnexpected() {
        // Both negative and positive unknown statuses fail as unexpected.
        XCTAssertEqual(
            KeychainIsolationProbe.classifyAdd(status: -1),
            .unexpectedStatus
        )
        XCTAssertEqual(
            KeychainIsolationProbe.classifyAdd(status: errSecParam),
            .unexpectedStatus
        )
        XCTAssertEqual(
            KeychainIsolationProbe.classifyAdd(status: errSecAuthFailed),
            .unexpectedStatus
        )
        XCTAssertNotEqual(
            KeychainIsolationProbe.exitCode(for: .unexpectedStatus),
            0
        )
        XCTAssertNotEqual(
            KeychainIsolationProbe.exitCode(for: .unexpectedStatus),
            KeychainIsolationProbe.exitCode(for: .unexpectedlyAuthorized)
        )
    }

    // MARK: Cleanup classification after a broken barrier

    func testCleanupSuccessOrNotFoundLeavesNoResidue() {
        XCTAssertEqual(
            KeychainIsolationProbe.cleanupOutcome(deleteStatus: errSecSuccess),
            .unexpectedlyAuthorized
        )
        // Item-not-found means the canary was already gone: no residue, still a
        // closed failure.
        XCTAssertEqual(
            KeychainIsolationProbe.cleanupOutcome(deleteStatus: errSecItemNotFound),
            .unexpectedlyAuthorized
        )
    }

    func testCleanupFailureFailsClosed() {
        XCTAssertEqual(
            KeychainIsolationProbe.cleanupOutcome(deleteStatus: errSecParam),
            .cleanupFailed
        )
        XCTAssertEqual(
            KeychainIsolationProbe.cleanupOutcome(deleteStatus: -1),
            .cleanupFailed
        )
        XCTAssertNotEqual(
            KeychainIsolationProbe.exitCode(for: .cleanupFailed),
            0
        )
        XCTAssertNotEqual(
            KeychainIsolationProbe.exitCode(for: .cleanupFailed),
            KeychainIsolationProbe.exitCode(for: .unexpectedlyAuthorized)
        )
    }

    func testExitCodesAreStableAndDistinct() {
        XCTAssertEqual(KeychainIsolationProbe.exitCode(for: .missingEntitlement), 0)
        XCTAssertEqual(KeychainIsolationProbe.exitCode(for: .configurationInvalid), 2)
        XCTAssertEqual(KeychainIsolationProbe.exitCode(for: .unexpectedlyAuthorized), 3)
        XCTAssertEqual(KeychainIsolationProbe.exitCode(for: .unexpectedStatus), 4)
        XCTAssertEqual(KeychainIsolationProbe.exitCode(for: .cleanupFailed), 5)
        // The pass outcome is the unique zero code.
        let codes: [KeychainIsolationProbe.Outcome] = [
            .missingEntitlement,
            .unexpectedlyAuthorized,
            .cleanupFailed,
            .unexpectedStatus,
            .configurationInvalid,
        ]
        let unique = Set(codes.map { KeychainIsolationProbe.exitCode(for: $0) })
        XCTAssertEqual(unique.count, codes.count, "exit codes must be distinct")
    }

    // MARK: Query construction

    func testAddQueryContainsRequiredCanaryAttributes() {
        let query = KeychainIsolationProbe.addQuery(for: tokenGroup, account: account)
        XCTAssertEqual(query[kSecClass] as? String, kSecClassGenericPassword as String)
        XCTAssertEqual(query[kSecAttrService] as? String, KeychainIsolationProbe.service)
        XCTAssertEqual(query[kSecAttrAccount] as? String, account)
        XCTAssertEqual(query[kSecAttrAccessGroup] as? String, tokenGroup)
        XCTAssertEqual(query[kSecUseDataProtectionKeychain] as? Bool, true)
        XCTAssertEqual(query[kSecValueData] as? Data, KeychainIsolationProbe.canaryValue)
        XCTAssertEqual(
            query[kSecAttrAccessible] as? String,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String
        )
    }

    func testAddQueryRequestsNoReadOrReturnSurface() {
        let query = KeychainIsolationProbe.addQuery(for: tokenGroup, account: account)
        // The canary add never reads or returns data/attributes.
        XCTAssertNil(query[kSecMatchLimit])
        XCTAssertNil(query[kSecReturnData])
        XCTAssertNil(query[kSecReturnAttributes])
        XCTAssertNil(query[kSecReturnPersistentRef])
        XCTAssertNil(query[kSecReturnRef])
    }

    func testCanaryValueIsASingleFixedZeroByte() {
        // Non-secret, one byte, zero value: no credential or user data.
        XCTAssertEqual(KeychainIsolationProbe.canaryValue, Data([0]))
        XCTAssertEqual(KeychainIsolationProbe.canaryValue.count, 1)
    }

    func testDeleteQueryIdentifiesTheExactCanaryWithoutValueData() {
        let query = KeychainIsolationProbe.deleteQuery(for: tokenGroup, account: account)
        XCTAssertEqual(query[kSecClass] as? String, kSecClassGenericPassword as String)
        XCTAssertEqual(query[kSecAttrService] as? String, KeychainIsolationProbe.service)
        XCTAssertEqual(query[kSecAttrAccount] as? String, account)
        XCTAssertEqual(query[kSecAttrAccessGroup] as? String, tokenGroup)
        XCTAssertEqual(query[kSecUseDataProtectionKeychain] as? Bool, true)
        // Cleanup carries no value data and no read/return surface.
        XCTAssertNil(query[kSecValueData])
        XCTAssertNil(query[kSecAttrAccessible])
        XCTAssertNil(query[kSecMatchLimit])
        XCTAssertNil(query[kSecReturnData])
        XCTAssertNil(query[kSecReturnAttributes])
    }

    func testQueriesBindTheDerivedForbiddenGroupAndAccount() {
        // Round-trip: derive the forbidden group, then confirm both queries
        // embed that exact string and the supplied account.
        let forbidden = KeychainIsolationProbe.resolve(
            groups: [mainGroup],
            principal: .mainApp
        )
        XCTAssertEqual(forbidden, tokenGroup)
        let add = KeychainIsolationProbe.addQuery(for: forbidden ?? "", account: account)
        let delete = KeychainIsolationProbe.deleteQuery(for: forbidden ?? "", account: account)
        XCTAssertEqual(add[kSecAttrAccessGroup] as? String, tokenGroup)
        XCTAssertEqual(delete[kSecAttrAccessGroup] as? String, tokenGroup)
        XCTAssertEqual(add[kSecAttrAccount] as? String, account)
        XCTAssertEqual(delete[kSecAttrAccount] as? String, account)
    }

    // MARK: Evidence labels and JSON shape

    func testStablePrincipalAndOutcomeLabels() {
        XCTAssertEqual(KeychainIsolationProbe.Principal.mainApp.rawValue, "main-app")
        XCTAssertEqual(
            KeychainIsolationProbe.Principal.tokenBroker.rawValue,
            "token-broker"
        )
        XCTAssertEqual(
            KeychainIsolationProbe.Outcome.missingEntitlement.rawValue,
            "missing-entitlement"
        )
        XCTAssertEqual(
            KeychainIsolationProbe.Outcome.unexpectedlyAuthorized.rawValue,
            "unexpectedly-authorized"
        )
        XCTAssertEqual(
            KeychainIsolationProbe.Outcome.cleanupFailed.rawValue,
            "cleanup-failed"
        )
        XCTAssertEqual(
            KeychainIsolationProbe.Outcome.unexpectedStatus.rawValue,
            "unexpected-status"
        )
        XCTAssertEqual(
            KeychainIsolationProbe.Outcome.configurationInvalid.rawValue,
            "configuration-invalid"
        )
        XCTAssertEqual(KeychainIsolationProbe.schemaVersion, 2)
    }

    func testEvidenceLineIsSingleLineCompactJSON() {
        let line = KeychainIsolationProbe.evidenceLine(
            principal: .mainApp,
            outcome: .missingEntitlement
        )
        XCTAssertFalse(line.contains("\n"), "evidence must be a single line")
        XCTAssertFalse(line.contains(" "), "evidence must be compact (no spaces)")

        // Must parse as well-formed JSON with the expected closed fields.
        guard let data = line.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            return XCTFail("evidence line must be valid JSON: \(line)")
        }
        XCTAssertEqual(object["schema_version"] as? Int, 2)
        XCTAssertEqual(object["principal"] as? String, "main-app")
        XCTAssertEqual(object["result"] as? String, "missing-entitlement")
        XCTAssertNil(object["os_status"], "os_status must not appear on a known status")
    }

    func testEvidenceLineIncludesOSStatusOnlyForUnexpectedAndCleanupFailed() {
        // Known/closed statuses never carry os_status.
        XCTAssertFalse(
            KeychainIsolationProbe.evidenceLine(
                principal: .tokenBroker,
                outcome: .missingEntitlement
            ).contains("os_status")
        )
        XCTAssertFalse(
            KeychainIsolationProbe.evidenceLine(
                principal: .tokenBroker,
                outcome: .unexpectedlyAuthorized
            ).contains("os_status")
        )
        XCTAssertFalse(
            KeychainIsolationProbe.evidenceLine(
                principal: .tokenBroker,
                outcome: .configurationInvalid
            ).contains("os_status")
        )
        // An unexpected add status carries the numeric OSStatus.
        let unexpected = KeychainIsolationProbe.evidenceLine(
            principal: .tokenBroker,
            outcome: .unexpectedStatus,
            osStatus: -50
        )
        XCTAssertTrue(unexpected.contains("\"os_status\":-50"))
        // A cleanup failure carries the redacted numeric delete status.
        let cleanup = KeychainIsolationProbe.evidenceLine(
            principal: .tokenBroker,
            outcome: .cleanupFailed,
            osStatus: -25300
        )
        XCTAssertTrue(cleanup.contains("\"os_status\":-25300"))
        for line in [unexpected, cleanup] {
            guard let data = line.data(using: .utf8),
                  let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
            else {
                return XCTFail("evidence line must be valid JSON: \(line)")
            }
            XCTAssertEqual(object["schema_version"] as? Int, 2)
        }
        XCTAssertEqual(
            (try? JSONSerialization.jsonObject(
                with: unexpected.data(using: .utf8) ?? Data()
            ) as? [String: Any])?["os_status"] as? Int,
            -50
        )
        XCTAssertEqual(
            (try? JSONSerialization.jsonObject(
                with: cleanup.data(using: .utf8) ?? Data()
            ) as? [String: Any])?["os_status"] as? Int,
            -25300
        )
        // A cleanup-failed outcome must not carry os_status when none is given.
        XCTAssertFalse(
            KeychainIsolationProbe.evidenceLine(
                principal: .tokenBroker,
                outcome: .cleanupFailed
            ).contains("os_status")
        )
    }

    func testEvidenceLineNeverLeaksSecretMaterial() {
        // The line must never embed any derived group, team prefix, service,
        // account, or arbitrary text — only the closed labels and schema.
        for outcome: KeychainIsolationProbe.Outcome in [
            .missingEntitlement,
            .unexpectedlyAuthorized,
            .cleanupFailed,
            .unexpectedStatus,
            .configurationInvalid,
        ] {
            let line = KeychainIsolationProbe.evidenceLine(
                principal: .mainApp,
                outcome: outcome,
                osStatus: outcome == .unexpectedStatus || outcome == .cleanupFailed ? -7 : nil
            )
            XCTAssertFalse(line.contains(teamPrefix), "team prefix must not leak: \(line)")
            XCTAssertFalse(line.contains("app.tersa"), "group/service must not leak: \(line)")
            XCTAssertFalse(
                line.contains(KeychainIsolationProbe.service),
                "service must not leak: \(line)"
            )
            XCTAssertFalse(line.contains(account), "account must not leak: \(line)")
            XCTAssertFalse(line.contains("error"), "no free-form error text: \(line)")
        }
    }
}
