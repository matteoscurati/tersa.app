// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import Foundation
import Security

/// A fixed-purpose, read-only "wrong-Keychain-group" isolation probe.
///
/// This file compiles unchanged into three targets — TersaMac,
/// TersaMacTokenBroker, and TersaMacTests — so Point 6 can run the probe inside
/// the actual signed executables. When the host process is launched with
/// exactly one argument (`--tersa-keychain-isolation-probe-v1`) it reads its own
/// signed `keychain-access-groups` entitlement, derives the single Keychain
/// access group the principal is *forbidden* from (the other principal's
/// group), and issues exactly one query-only `SecItemCopyMatching` against that
/// group. The only passing outcome is `errSecMissingEntitlement`: the kernel
/// denied access to a group the process is not entitled to, which proves the
/// main app and the token broker remain Keychain-isolated.
///
/// Hard guarantees, enforced by design:
/// - No mutation. There is no `SecItemAdd`, `SecItemUpdate`, or
///   `SecItemDelete` anywhere in this file, and the single query requests no
///   item data and no attributes.
/// - No caller-supplied input. The forbidden group is derived solely from the
///   process's own signed entitlement; a suffix is never accepted from a caller.
/// - No entitlement weakening and no live evidence. The committed entitlements
///   are untouched; nothing is written, and the JSON line leaks no entitlement
///   value, group, team ID, service/account, Keychain data, token, or free-form
///   error text.
/// - No production behavior change without the exact opt-in argument.
enum KeychainIsolationProbe {

    // MARK: Opt-in contract

    /// The single accepted launch argument. Probe execution occurs only when
    /// `CommandLine.arguments` is exactly `[executablePath, argument]`.
    static let argument = "--tersa-keychain-isolation-probe-v1"

    /// Machine-readable evidence schema version. Bumped only if the JSON
    /// surface changes.
    static let schemaVersion = 1

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
        /// `errSecMissingEntitlement`: the process was correctly denied access
        /// to the forbidden group. The only passing outcome.
        case missingEntitlement = "missing-entitlement"
        /// `errSecItemNotFound`: the access-group gate did not deny the query,
        /// so isolation could not be confirmed.
        case itemNotFound = "item-not-found"
        /// Any `OSStatus` other than the two known ones.
        case unexpectedStatus = "unexpected-status"
        /// The signed entitlement did not resolve to exactly one valid group
        /// for this principal. No Keychain query is issued.
        case configurationInvalid = "configuration-invalid"
    }

    // MARK: Non-secret probe item identity

    /// Constant, non-secret service for the query. No item with this service is
    /// ever created; it scopes a read against the forbidden group only. Unique
    /// to this probe version.
    static let service = "app.tersa.keychain-isolation-probe.v1"

    /// Constant, non-secret account paired with `service`.
    static let account = "tersa-keychain-isolation-probe.v1"

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

    /// Builds the single fixed, query-only `SecItemCopyMatching` dictionary for
    /// the derived forbidden group.
    ///
    /// The query requests no item data (`kSecReturnData` absent) and no
    /// attributes (`kSecReturnAttributes` absent); it exists only to observe
    /// whether the access-group gate denies the read. Pure — no Security
    /// framework calls.
    static func query(for forbiddenGroup: String) -> [CFString: Any] {
        [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecAttrAccessGroup: forbiddenGroup as CFString,
            kSecUseDataProtectionKeychain: true,
            kSecMatchLimit: kSecMatchLimitOne
        ]
    }
}

// MARK: - Status classification (pure)

extension KeychainIsolationProbe {

    /// Classifies an `OSStatus` from the query. Only `errSecMissingEntitlement`
    /// passes; `errSecItemNotFound` and every other status fail. Pure.
    static func classify(status: OSStatus) -> Outcome {
        switch status {
        case errSecMissingEntitlement: return .missingEntitlement
        case errSecItemNotFound: return .itemNotFound
        default: return .unexpectedStatus
        }
    }

    /// Stable, distinct exit code for an outcome. `0` only for the expected
    /// missing-entitlement outcome; nonzero for every failure. Pure.
    static func exitCode(for outcome: Outcome) -> Int32 {
        switch outcome {
        case .missingEntitlement: return 0
        case .configurationInvalid: return 2
        case .itemNotFound: return 3
        case .unexpectedStatus: return 4
        }
    }
}

// MARK: - Evidence emission (pure)

extension KeychainIsolationProbe {

    /// Emits the single compact, machine-readable JSON evidence line.
    ///
    /// Contains only the schema version, the stable principal label, and the
    /// closed result label, plus — only for an unexpected status — the numeric
    /// `OSStatus`. It never embeds entitlement values, groups, team IDs,
    /// service/account, Keychain data, tokens, or free-form error text. The
    /// emitted values are closed enums of `[a-z-]` and integers, so no JSON
    /// escaping is required. Pure.
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
        if outcome == .unexpectedStatus, let osStatus {
            pairs.append("\"os_status\":" + String(osStatus))
        }
        return "{" + pairs.joined(separator: ",") + "}"
    }
}

// MARK: - Live execution (entrypoint only)

extension KeychainIsolationProbe {

    /// Runs the probe as `principal` and exits the process.
    ///
    /// Reads the current process's signed `keychain-access-groups` entitlement,
    /// builds one query-only `SecItemCopyMatching` against the derived forbidden
    /// group, emits exactly one JSON line on stdout, and exits with the
    /// outcome's stable code. Never returns.
    static func runAsPrincipal(_ principal: Principal) -> Never {
        let value = copyKeychainAccessGroupsValue()
        let groups = parsedGroups(from: value)

        guard let forbiddenGroup = resolve(groups: groups, principal: principal) else {
            emitAndExit(principal: principal, outcome: .configurationInvalid)
        }

        let status = copyMatching(query: query(for: forbiddenGroup))
        let outcome = classify(status: status)
        let osStatus = outcome == .unexpectedStatus ? status : nil
        emitAndExit(principal: principal, outcome: outcome, osStatus: osStatus)
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

    /// Issues the single query-only `SecItemCopyMatching` and returns its
    /// status. The query requests no data and no attributes, so any returned
    /// object is intentionally discarded.
    private static func copyMatching(query: [CFString: Any]) -> OSStatus {
        var result: CFTypeRef?
        return SecItemCopyMatching(query as CFDictionary, &result)
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
