// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import XCTest

@MainActor
final class ConnectionOperationDeadlineTests: XCTestCase {
    private final class TestClock {
        var now: UInt64

        init(now: UInt64) {
            self.now = now
        }
    }

    func testDeadlineIsMonotonicAndFencesLateCallback() {
        let clock = TestClock(now: 100)
        let deadlines = ConnectionOperationDeadline(now: { clock.now })
        let token = deadlines.start(kind: .connectAndSync, timeout: 1)

        clock.now = 1_000_000_099
        XCTAssertFalse(deadlines.timeOut(token, keepAlive: false))
        XCTAssertTrue(deadlines.accepts(token))

        clock.now = 1_000_000_100
        XCTAssertTrue(deadlines.timeOut(token, keepAlive: false))
        XCTAssertFalse(deadlines.accepts(token))
        XCTAssertFalse(deadlines.finish(token))
    }

    func testRetryFencesLateCallbackFromPreviousAttempt() {
        let clock = TestClock(now: 0)
        let deadlines = ConnectionOperationDeadline(now: { clock.now })
        let first = deadlines.start(kind: .authorization, timeout: 10)
        let retry = deadlines.start(kind: .authorization, timeout: 10)

        XCTAssertFalse(deadlines.accepts(first))
        XCTAssertTrue(deadlines.accepts(retry))
        XCTAssertFalse(deadlines.finish(first))
        XCTAssertTrue(deadlines.finish(retry))
    }

    func testDisconnectTimeoutKeepsLateSuccessAuthorized() {
        let clock = TestClock(now: 0)
        let deadlines = ConnectionOperationDeadline(now: { clock.now })
        let token = deadlines.start(kind: .disconnect, timeout: 1)

        clock.now = 1_000_000_000
        XCTAssertTrue(deadlines.timeOut(token, keepAlive: true))
        XCTAssertTrue(deadlines.accepts(token))
        XCTAssertTrue(deadlines.disconnectIsActive)
        XCTAssertTrue(deadlines.finish(token))
        XCTAssertFalse(deadlines.accepts(token))
        XCTAssertFalse(deadlines.disconnectIsActive)
    }

    func testConnectTimeoutKeepsLateSuccessAuthoritativeAndBlocksRetryBegin() {
        let clock = TestClock(now: 0)
        let deadlines = ConnectionOperationDeadline(now: { clock.now })
        let token = deadlines.start(kind: .connectAndSync, timeout: 1)

        clock.now = 1_000_000_000
        XCTAssertTrue(deadlines.timeOut(token, keepAlive: true))
        XCTAssertTrue(deadlines.accepts(token))
        XCTAssertTrue(deadlines.connectIsActive)
        XCTAssertTrue(deadlines.hasActiveOperation)
        XCTAssertTrue(deadlines.finish(token))
        XCTAssertFalse(deadlines.connectIsActive)
        XCTAssertFalse(deadlines.hasActiveOperation)
    }

    func testKeepWaitingRenewsTheSameGenerationAndCanTimeOutAgain() throws {
        let clock = TestClock(now: 0)
        let deadlines = ConnectionOperationDeadline(now: { clock.now })
        let token = deadlines.start(kind: .disconnect, timeout: 1)
        clock.now = 1_000_000_000
        XCTAssertTrue(deadlines.timeOut(token, keepAlive: true))

        let renewed = try XCTUnwrap(deadlines.renewTimedOut(kind: .disconnect, timeout: 2))
        XCTAssertEqual(renewed, token)
        clock.now = 2_999_999_999
        XCTAssertFalse(deadlines.timeOut(token, keepAlive: true))
        clock.now = 3_000_000_000
        XCTAssertTrue(deadlines.timeOut(token, keepAlive: true))
        XCTAssertTrue(deadlines.accepts(token))
    }
}
