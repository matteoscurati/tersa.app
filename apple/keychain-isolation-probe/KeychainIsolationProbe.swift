// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import Foundation
import Security

/// A fixed-purpose, negative-mutation "wrong-Keychain-group" isolation canary.
///
/// This file compiles unchanged into three targets — TersaMac,
/// TersaMacTokenBroker, and TersaMacTests — so Point 6 can run the canary inside
/// the actual signed executables. When the host process is launched with exactly
/// one argument (`--tersa-keychain-isolation-probe-v2`) it reads its own signed
/// `keychain-access-groups` entitlement, derives the single Keychain access group
/// the principal is *forbidden* from (the other principal's group), and attempts
/// exactly one `SecItemAdd` of a non-secret, one-byte, zero-value
/// generic-password canary into that group, using the Data Protection Keychain.
/// The only passing outcome is `errSecMissingEntitlement`: the kernel refused to
/// let the process create an item in a group it is not entitled to, which proves
/// the main app and the token broker remain Keychain-isolated.
///
/// Why a mutation and not a read. Apple documents that adding an item to a group
/// the app does not belong to returns `errSecMissingEntitlement`, but searching
/// an unauthorized group with `SecItemCopyMatching` returns `errSecItemNotFound`.
/// A read-only probe can therefore never observe the missing-entitlement barrier,
/// so it cannot serve as isolation evidence. The canary instead mutates: only the
/// add path distinguishes "denied for lack of entitlement" from "allowed". The v1
/// read-only probe is superseded; the opt-in argument and evidence schema were
/// bumped together so a stale v1 harness cannot silently accept the changed
/// semantics.
///
/// Hard guarantees, enforced by design:
/// - Exactly one mutation surface. There is exactly one `SecItemAdd` (the canary)
///   and exactly one `SecItemDelete`, used only to clean up a canary whose add
///   unexpectedly succeeded. There is no `SecItemCopyMatching`, `SecItemUpdate`,
///   or any other `SecItem` capability, and the add passes `nil` so it returns no
///   item data.
/// - No caller-supplied input. The forbidden group is derived solely from the
///   process's own signed entitlement; a suffix is never accepted from a caller.
/// - No credential or user data. The canary carries a single fixed zero byte and
///   a per-run random UUID account that is never emitted; service is a fixed v2
///   public name. No token, refresh token, or user secret is touched.
/// - Fail-closed cleanup. If the add succeeds the barrier is broken: the probe
///   immediately attempts exactly one `SecItemDelete` for that exact canary
///   (without value data) and emits a closed `unexpectedly-authorized` failure.
///   If cleanup itself fails, the probe still fails closed as `cleanup-failed`
///   carrying only the redacted numeric delete status; a non-secret one-byte
///   residue may then remain in the forbidden group until it is removed.
/// - No entitlement weakening and no live-evidence leak. The committed
///   entitlements are untouched, and the JSON line leaks no entitlement value,
///   group, team ID, service/account, Keychain data, token, or free-form error
///   text.
/// - No production behavior change without the exact opt-in argument.
enum KeychainIsolationProbe {

    // MARK: Opt-in contract

    /// The single accepted launch argument. Probe execution occurs only when
    /// `CommandLine.arguments` is exactly `[executablePath, argument]`.
    static let argument = "--tersa-keychain-isolation-probe-v2"

    /// Machine-readable evidence schema version. Bumped to 2 with the switch
    /// from the read-only query (v1) to the negative-mutation canary, so a
    /// stale v1 harness cannot silently accept the changed semantics.
    static let schemaVersion = 2

    // MARK: Principals (closed)

    /// The two fixed principals. The raw values are the stable public evidence
    /// labels emitted in the JSON `principal` field.
    enum Principal: String {
        /// The TersaMac application process.
        case mainApp = "main-app"
        /// The embedded TersaMacTokenBroker XPC process.
        case tokenBroker = "token-broker"

        /// The exact suffix this principal's single signed group must end with.
        var allowedSuffix: String {
            switch self {
            case .mainApp: return ".app.tersa.shared"
            case .tokenBroker: return ".app.tersa.token"
            }
        }

        /// The suffix of the other principal's group. The forbidden group is
        /// produced by replacing the allowed suffix on the same team prefix.
        var forbiddenSuffix: String {
            switch self {
            case .mainApp: return ".app.tersa.token"
            case .tokenBroker: return ".app.tersa.shared"
            }
        }
    }

    // MARK: Outcome (closed result labels)

    /// The closed set of result labels emitted as the JSON `result` field.
    enum Outcome: String {
        /// `errSecMissingEntitlement`: the canary add was correctly refused for
        /// the forbidden group. The only passing outcome.
        case missingEntitlement = "missing-entitlement"
        /// `errSecSuccess` on the add: the isolation barrier is broken. After
        /// cleanup the probe fails with this closed label.
        case unexpectedlyAuthorized = "unexpectedly-authorized"
        /// The cleanup `SecItemDelete` after a broken barrier returned a status
        /// other than success or item-not-found; a non-secret one-byte residue
        /// may remain in the forbidden group until it is removed.
        case cleanupFailed = "cleanup-failed"
        /// Any add `OSStatus` other than missing-entitlement or success.
        case unexpectedStatus = "unexpected-status"
        /// The signed entitlement did not resolve to exactly one valid group
        /// for this principal. No Keychain mutation is attempted.
        case configurationInvalid = "configuration-invalid"
    }

    // MARK: Non-secret canary identity

    /// Constant, non-secret service for the canary. Unique to this probe
    /// version; it scopes the single canary item against the forbidden group.
    static let service = "app.tersa.keychain-isolation-probe.v2"

    /// The fixed, non-secret canary value: a single zero byte. The canary never
    /// carries a credential, token, or any user data.
    static let canaryValue = Data([0])

    /// The `keychain-access-groups` entitlement key string for
    /// `SecTaskCopyValueForEntitlement`. The literal is the canonical,
    /// version-stable entitlement key; stored as a Sendable `String` and cast to
    /// `CFString` at the call site.
    private static let keychainAccessGroupsEntitlement = "keychain-access-groups"
}

// MARK: - Opt-in detection (pure)

extension KeychainIsolationProbe {

    /// True only when `arguments` is exactly the executable path followed by the
    /// single probe argument. Missing, extra, or different arguments are not a
    /// probe request.
    static func isProbeRequest(_ arguments: [String]) -> Bool {
        arguments.count == 2 && arguments[1] == argument
    }
}

// MARK: - Entitlement parsing (pure)

extension KeychainIsolationProbe {

    /// Parses the raw `keychain-access-groups` entitlement value into its group
    /// strings. Returns `nil` for an absent or malformed value: anything that is
    /// not an array, or any array element that is not a string. Pure — no
    /// Security framework calls — so it is unit-testable without signing.
    static func parsedGroups(from value: CFTypeRef?) -> [String]? {
        guard let value else { return nil }
        guard let array = value as? [Any] else { return nil }
        var groups: [String] = []
        for element in array {
            guard let string = element as? String else { return nil }
            groups.append(string)
        }
        return groups
    }
}

// MARK: - Forbidden-group derivation (pure)

extension KeychainIsolationProbe {

    /// Derives the forbidden Keychain group for `principal` from its signed
    /// entitlement groups.
    ///
    /// Resolution succeeds only when there is exactly one group, it ends with
    /// the principal's exact allowed suffix, and the retained team prefix is
    /// non-empty. The forbidden group keeps that team prefix and substitutes the
    /// other principal's suffix. A dual-group process can never resolve. Returns
    /// `nil` (fail closed) for absent, malformed, zero/multiple, empty-prefix,
    /// or wrong-suffix input. Never accepts a caller-supplied group or suffix.
    /// Pure — no Security framework calls.
    static func resolve(groups: [String]?, principal: Principal) -> String? {
        guard let groups, groups.count == 1 else { return nil }
        let group = groups[0]
        let allowedSuffix = principal.allowedSuffix
        guard group.hasSuffix(allowedSuffix) else { return nil }
        let teamPrefix = group.dropLast(allowedSuffix.count)
        guard !teamPrefix.isEmpty else { return nil }
        return String(teamPrefix) + principal.forbiddenSuffix
    }
}

// MARK: - Query construction (pure)

extension KeychainIsolationProbe {

    /// Builds the single fixed `SecItemAdd` dictionary for the canary in the
    /// derived forbidden group. The canary value is the fixed one-byte
    /// `canaryValue`; the account is the per-run random UUID supplied by the
    /// runner (never a constant, never emitted). Accessibility is device-only,
    /// matching the restrictive setting the Keychain adapters use. Pure — no
    /// Security framework calls.
    static func addQuery(for forbiddenGroup: String, account: String) -> [CFString: Any] {
        [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecAttrAccessGroup: forbiddenGroup as CFString,
            kSecUseDataProtectionKeychain: true,
            kSecValueData: canaryValue,
            kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
    }

    /// Builds the single fixed `SecItemDelete` dictionary used to clean up a
    /// canary whose add unexpectedly succeeded. It carries no value data and
    /// requests no return; it identifies the exact canary by class, service,
    /// per-run account, and forbidden group. Pure — no Security framework calls.
    static func deleteQuery(for forbiddenGroup: String, account: String) -> [CFString: Any] {
        [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecAttrAccessGroup: forbiddenGroup as CFString,
            kSecUseDataProtectionKeychain: true
        ]
    }
}

// MARK: - Status classification (pure)

extension KeychainIsolationProbe {

    /// Classifies the canary `SecItemAdd` status. `errSecMissingEntitlement` is
    /// the only passing status; `errSecSuccess` means the isolation barrier is
    /// broken and the probe must clean up the canary; every other status fails
    /// closed as an unexpected status. Pure.
    static func classifyAdd(status: OSStatus) -> Outcome {
        switch status {
        case errSecMissingEntitlement: return .missingEntitlement
        case errSecSuccess: return .unexpectedlyAuthorized
        default: return .unexpectedStatus
        }
    }

    /// Resolves the final outcome after the barrier was broken and the probe ran
    /// its single cleanup `SecItemDelete`. `errSecSuccess` or `errSecItemNotFound`
    /// mean the canary left no residue, so the outcome stays the closed
    /// `unexpectedly-authorized` failure; any other delete status means cleanup
    /// could not be confirmed and the probe fails closed as `cleanup-failed`.
    /// Pure.
    static func cleanupOutcome(deleteStatus: OSStatus) -> Outcome {
        switch deleteStatus {
        case errSecSuccess, errSecItemNotFound: return .unexpectedlyAuthorized
        default: return .cleanupFailed
        }
    }

    /// Stable, distinct exit code for an outcome. `0` only for the expected
    /// missing-entitlement outcome; nonzero for every failure. Pure.
    static func exitCode(for outcome: Outcome) -> Int32 {
        switch outcome {
        case .missingEntitlement: return 0
        case .configurationInvalid: return 2
        case .unexpectedlyAuthorized: return 3
        case .unexpectedStatus: return 4
        case .cleanupFailed: return 5
        }
    }
}

// MARK: - Evidence emission (pure)

extension KeychainIsolationProbe {

    /// Emits the single compact, machine-readable JSON evidence line.
    ///
    /// Contains only the schema version, the stable principal label, and the
    /// closed result label, plus — only for an unexpected status or a
    /// cleanup-failed outcome — the redacted numeric `OSStatus`. It never embeds
    /// entitlement values, groups, team IDs, service/account, Keychain data,
    /// tokens, or free-form error text. The emitted values are closed enums of
    /// `[a-z-]` and integers, so no JSON escaping is required. Pure.
    static func evidenceLine(
        principal: Principal,
        outcome: Outcome,
        osStatus: OSStatus? = nil
    ) -> String {
        // Built by explicit concatenation, not string interpolation, so the
        // emitted JSON bytes are fully static and contain no evaluated segments.
        var pairs = [
            "\"schema_version\":" + String(schemaVersion),
            "\"principal\":\"" + principal.rawValue + "\"",
            "\"result\":\"" + outcome.rawValue + "\""
        ]
        if let osStatus,
           outcome == .unexpectedStatus || outcome == .cleanupFailed {
            pairs.append("\"os_status\":" + String(osStatus))
        }
        return "{" + pairs.joined(separator: ",") + "}"
    }
}

// MARK: - Live execution (entrypoint only)

extension KeychainIsolationProbe {

    /// Runs the canary as `principal` and exits the process.
    ///
    /// Reads the current process's signed `keychain-access-groups` entitlement,
    /// attempts exactly one `SecItemAdd` of a non-secret canary into the derived
    /// forbidden group, cleans up only if the add unexpectedly succeeds, emits
    /// exactly one JSON line on stdout, and exits with the outcome's stable code.
    /// Never returns.
    static func runAsPrincipal(_ principal: Principal) -> Never {
        let value = copyKeychainAccessGroupsValue()
        let groups = parsedGroups(from: value)

        guard let forbiddenGroup = resolve(groups: groups, principal: principal) else {
            emitAndExit(principal: principal, outcome: .configurationInvalid)
        }

        let account = randomAccount()
        let addStatus = addCanary(query: addQuery(for: forbiddenGroup, account: account))
        switch classifyAdd(status: addStatus) {
        case .missingEntitlement:
            emitAndExit(principal: principal, outcome: .missingEntitlement)
        case .unexpectedlyAuthorized:
            // Barrier broken: clean up the exact canary, then fail closed.
            let deleteStatus = deleteCanary(query: deleteQuery(for: forbiddenGroup, account: account))
            let outcome = cleanupOutcome(deleteStatus: deleteStatus)
            let osStatus = outcome == .cleanupFailed ? deleteStatus : nil
            emitAndExit(principal: principal, outcome: outcome, osStatus: osStatus)
        case .unexpectedStatus:
            emitAndExit(principal: principal, outcome: .unexpectedStatus, osStatus: addStatus)
        case .configurationInvalid, .cleanupFailed:
            // classifyAdd never returns these; fail closed if it ever did.
            emitAndExit(principal: principal, outcome: .unexpectedStatus, osStatus: addStatus)
        }
    }

    /// A per-run random UUID account for the canary, so successive runs never
    /// collide on a stale item or residue. Never emitted in evidence.
    private static func randomAccount() -> String {
        UUID().uuidString
    }

    /// Copies the current process's signed `keychain-access-groups` entitlement
    /// value via `SecTask`, or `nil` if it cannot be read.
    private static func copyKeychainAccessGroupsValue() -> CFTypeRef? {
        guard let task = SecTaskCreateFromSelf(nil) else {
            return nil
        }
        return SecTaskCopyValueForEntitlement(
            task,
            keychainAccessGroupsEntitlement as CFString,
            nil
        )
    }

    /// Attempts the single canary `SecItemAdd`. The result pointer is `nil`, so
    /// no item data is returned.
    private static func addCanary(query: [CFString: Any]) -> OSStatus {
        SecItemAdd(query as CFDictionary, nil)
    }

    /// Attempts the single cleanup `SecItemDelete` for an exact canary whose add
    /// unexpectedly succeeded.
    private static func deleteCanary(query: [CFString: Any]) -> OSStatus {
        SecItemDelete(query as CFDictionary)
    }

    /// Prints exactly one JSON line on stdout and exits with the outcome code.
    private static func emitAndExit(
        principal: Principal,
        outcome: Outcome,
        osStatus: OSStatus? = nil
    ) -> Never {
        print(evidenceLine(principal: principal, outcome: outcome, osStatus: osStatus))
        exit(exitCode(for: outcome))
    }
}
