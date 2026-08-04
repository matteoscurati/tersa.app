// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import Foundation
import XCTest

final class MailboxLifecyclePresentationTests: XCTestCase {
    private let date = Date(timeIntervalSince1970: 1_800_000_000)

    func testFreshAndOfflineCopyUsesOnlyAggregateFreshness() {
        let formatter: (Date) -> String = { _ in "the recorded time" }

        XCTAssertEqual(
            MailboxFreshnessState.fresh(lastSuccessfulSync: date).message(formatDate: formatter),
            "Last updated the recorded time."
        )
        XCTAssertEqual(
            MailboxFreshnessState.offline(lastSuccessfulSync: date).message(formatDate: formatter),
            "Offline. Showing cached mail last updated the recorded time."
        )
    }

    func testNeverSyncedOfflineStateMakesTheMissingTimestampExplicit() {
        let state = MailboxFreshnessState.offline(lastSuccessfulSync: nil)

        XCTAssertEqual(
            state.message(),
            "Offline. Showing cached mail; no successful sync time is available."
        )
        XCTAssertEqual(state.accessibilityLabel, "Offline cached mailbox")
    }

    func testUnknownStateRendersNoFreshnessClaim() {
        XCTAssertFalse(MailboxFreshnessState.unknown.isVisible)
        XCTAssertEqual(MailboxFreshnessState.unknown.message(), "")
    }

    func testRelaunchProjectsEveryDurableRecoveryState() {
        XCTAssertEqual(
            MailboxLifecycleSnapshot(
                disconnectRecovery: .incompleteTeardown,
                lastSuccessfulSync: nil
            ).recoveryPresentation,
            .disconnectIncomplete
        )
        XCTAssertEqual(
            MailboxLifecycleSnapshot(
                disconnectRecovery: .revokeUnconfirmed,
                lastSuccessfulSync: date
            ).recoveryPresentation,
            .revokeUnconfirmed
        )
        XCTAssertEqual(
            MailboxLifecycleSnapshot(
                disconnectRecovery: nil,
                lastSuccessfulSync: date
            ).recoveryPresentation,
            .none
        )
    }

    func testSuccessfulRetryReplacesOfflinePresentationWithFreshMetadata() {
        let staleSnapshot = MailboxLifecycleSnapshot(
            disconnectRecovery: nil,
            lastSuccessfulSync: date
        )
        let refreshedDate = date.addingTimeInterval(60)
        let refreshedSnapshot = MailboxLifecycleSnapshot(
            disconnectRecovery: nil,
            lastSuccessfulSync: refreshedDate
        )

        XCTAssertEqual(
            MailboxFreshnessState.afterSync(snapshot: staleSnapshot, offline: true),
            .offline(lastSuccessfulSync: date)
        )
        XCTAssertEqual(
            MailboxFreshnessState.afterSync(snapshot: refreshedSnapshot, offline: false),
            .fresh(lastSuccessfulSync: refreshedDate)
        )
    }

    func testLifecycleReadFailureIsAnExplicitLaunchFailure() {
        XCTAssertEqual(MailboxLifecycleReadResult.failure.launchProjection, .unavailable)
    }

    func testLaunchRestoreFenceRejectsUserIntentAndAccountChanges() {
        var fence = MailboxLifecycleRestoreFence()
        let primary = Data("primary-gmail".utf8)
        let other = Data("other-gmail".utf8)
        let first = fence.begin(accountIdentifier: primary)

        XCTAssertFalse(fence.finish(first, currentAccountIdentifier: other))
        fence.invalidate()
        XCTAssertFalse(fence.finish(first, currentAccountIdentifier: primary))

        let retry = fence.begin(accountIdentifier: primary)
        XCTAssertTrue(fence.finish(retry, currentAccountIdentifier: primary))
        XCTAssertFalse(fence.finish(retry, currentAccountIdentifier: primary))
    }

    func testRefreshAdmissionCoalescesUntilTheActiveRefreshFinishes() throws {
        var presentation = MailboxRefreshPresentation()
        let account = Data("primary-gmail".utf8)
        let first = try XCTUnwrap(presentation.begin(accountIdentifier: account))

        XCTAssertNil(presentation.begin(accountIdentifier: account))
        XCTAssertTrue(presentation.isRefreshing)
        XCTAssertTrue(presentation.finish(first, succeeded: false))
        XCTAssertFalse(presentation.isRefreshing)
        XCTAssertEqual(presentation.reloadGeneration, 0)
    }

    func testSuccessfulRefreshAdvancesReloadGenerationExactlyOnce() throws {
        var presentation = MailboxRefreshPresentation()
        let account = Data("primary-gmail".utf8)
        let token = try XCTUnwrap(presentation.begin(accountIdentifier: account))

        XCTAssertTrue(presentation.finish(token, succeeded: true))
        XCTAssertEqual(presentation.reloadGeneration, 1)
        XCTAssertFalse(presentation.finish(token, succeeded: true))
        XCTAssertEqual(presentation.reloadGeneration, 1)
    }

    func testDisconnectInvalidationRejectsStaleRefreshCallback() throws {
        var presentation = MailboxRefreshPresentation()
        let account = Data("primary-gmail".utf8)
        let token = try XCTUnwrap(presentation.begin(accountIdentifier: account))

        presentation.invalidate()

        XCTAssertFalse(presentation.finish(token, succeeded: true))
        XCTAssertFalse(presentation.isRefreshing)
        XCTAssertEqual(presentation.reloadGeneration, 0)
    }

    func testRefreshReconnectNoticeRequiresAnExplicitFollowUpAction() {
        XCTAssertTrue(MailboxRefreshNotice.reconnectRequired.requiresExplicitReconnect)
        XCTAssertFalse(MailboxRefreshNotice.offline.requiresExplicitReconnect)
        XCTAssertFalse(MailboxRefreshNotice.unavailable.requiresExplicitReconnect)
    }

    func testAutomaticRefreshReconnectAndPermissionNeverAdmitOAuth() {
        XCTAssertEqual(
            MailboxRefreshPolicy.route(
                origin: .automaticRefresh,
                event: .brokerReconnect
            ),
            .presentRefreshReconnect
        )
        XCTAssertEqual(
            MailboxRefreshPolicy.route(
                origin: .automaticRefresh,
                event: .brokerPermissionRequired
            ),
            .presentRefreshReconnect
        )
    }

    func testOnlyOrdinaryOrExplicitConnectionRoutesCanAdmitOAuth() {
        XCTAssertEqual(
            MailboxRefreshPolicy.route(
                origin: .ordinaryConnection,
                event: .missingStoredCredential
            ),
            .authorizeFromConnectionLadder
        )
        XCTAssertEqual(
            MailboxRefreshPolicy.route(
                origin: .explicitReconnect,
                event: .missingStoredCredential
            ),
            .startExplicitReconnectLadder
        )
    }

    func testRefreshFailurePolicyKeepsTheInboxOnCachedOfflineOrUnavailableMail() {
        XCTAssertEqual(MailboxRefreshPresentationPolicy.notice(for: .transport), .offline)
        XCTAssertEqual(MailboxRefreshPresentationPolicy.notice(for: .syncFailure), .offline)
        XCTAssertEqual(MailboxRefreshPresentationPolicy.notice(for: .unavailable), .unavailable)
    }

    func testRefreshTimeoutOrdersBrokerClientReleaseBeforeFinishAndFence() {
        XCTAssertEqual(
            MailboxRefreshPolicy.timeoutActions,
            [.cancelOwnedBrokerClient, .finishAndFence(.transport)]
        )
        XCTAssertEqual(
            MailboxRefreshPresentationPolicy.notice(for: .transport),
            .offline
        )
    }

    func testRefreshFailureNoticesDoNotAdvanceTheInboxReloadGeneration() throws {
        let account = Data("primary-gmail".utf8)
        for notice in [MailboxRefreshNotice.offline, .reconnectRequired, .unavailable] {
            var presentation = MailboxRefreshPresentation()
            let token = try XCTUnwrap(presentation.begin(accountIdentifier: account))

            XCTAssertTrue(presentation.finish(token, succeeded: false))
            presentation.present(notice)
            XCTAssertFalse(presentation.isRefreshing)
            XCTAssertEqual(presentation.reloadGeneration, 0)
            XCTAssertEqual(presentation.notice, notice)
        }
    }

    func testTimedOutRefreshFencesLateSuccessWithoutReloading() throws {
        var presentation = MailboxRefreshPresentation()
        let token = try XCTUnwrap(presentation.begin(accountIdentifier: Data("primary-gmail".utf8)))

        XCTAssertTrue(presentation.finish(token, succeeded: false))
        presentation.present(.offline)

        XCTAssertFalse(presentation.finish(token, succeeded: true))
        XCTAssertFalse(presentation.isRefreshing)
        XCTAssertEqual(presentation.reloadGeneration, 0)
        XCTAssertEqual(presentation.notice, .offline)
    }
}
