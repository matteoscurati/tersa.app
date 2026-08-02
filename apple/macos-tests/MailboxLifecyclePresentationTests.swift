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
}
