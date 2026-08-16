// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import XCTest

final class BrokerGrantActivationHandoffTests: XCTestCase {
    @MainActor
    func testInactiveAppRequestsActivationThenAdoptsOnNextTurn() throws {
        let handoff = BrokerGrantActivationHandoff()
        let environment = FakeBrokerGrantActivationEnvironment(isApplicationActive: false)

        XCTAssertTrue(environment.begin(handoff))
        XCTAssertEqual(environment.events, [.requestedActivation, .scheduledNextTurn])
        XCTAssertTrue(handoff.isPending)
        XCTAssertEqual(environment.adoptionCount, 0)

        try XCTUnwrap(environment.nextTurnCallbacks.first)()

        XCTAssertEqual(environment.adoptionCount, 1)
        XCTAssertFalse(handoff.isPending)
    }

    @MainActor
    func testNextTurnCallbackAdoptsExactlyOnceWhenInvokedTwice() throws {
        let handoff = BrokerGrantActivationHandoff()
        let environment = FakeBrokerGrantActivationEnvironment(isApplicationActive: false)

        XCTAssertTrue(environment.begin(handoff))
        let callback = try XCTUnwrap(environment.nextTurnCallbacks.first)
        callback()
        callback()

        XCTAssertEqual(environment.adoptionCount, 1)
        XCTAssertFalse(handoff.isPending)
    }

    @MainActor
    func testAlreadyActiveAppAdoptsWithoutActivationOrScheduling() {
        let handoff = BrokerGrantActivationHandoff()
        let environment = FakeBrokerGrantActivationEnvironment(isApplicationActive: true)

        XCTAssertTrue(environment.begin(handoff))

        XCTAssertEqual(environment.adoptionCount, 1)
        XCTAssertTrue(environment.events.isEmpty)
        XCTAssertTrue(environment.nextTurnCallbacks.isEmpty)
        XCTAssertFalse(handoff.isPending)
    }

    @MainActor
    func testSecondBeginIsRejectedWhileFirstHandoffIsPending() {
        let handoff = BrokerGrantActivationHandoff()
        let first = FakeBrokerGrantActivationEnvironment(isApplicationActive: false)
        let second = FakeBrokerGrantActivationEnvironment(isApplicationActive: true)

        XCTAssertTrue(first.begin(handoff))
        XCTAssertFalse(second.begin(handoff))

        XCTAssertTrue(handoff.isPending)
        XCTAssertEqual(first.adoptionCount, 0)
        XCTAssertEqual(second.adoptionCount, 0)

        let firstCallback = first.nextTurnCallbacks.first
        XCTAssertNotNil(firstCallback)
        firstCallback?()

        XCTAssertEqual(first.adoptionCount, 1)
        XCTAssertEqual(second.adoptionCount, 0)
        XCTAssertFalse(handoff.isPending)
    }

    @MainActor
    func testBeginIsRejectedWhileClaimedActionIsRunning() {
        let handoff = BrokerGrantActivationHandoff()
        var nestedBeginResult: Bool?

        let started = handoff.beginApplicationActivation(
            isApplicationActive: { true },
            requestActivation: { XCTFail("active app must not request activation") },
            scheduleNextMainQueueTurn: { _ in XCTFail("active app must not schedule") },
            adopt: {
                nestedBeginResult = handoff.beginApplicationActivation(
                    isApplicationActive: { true },
                    requestActivation: {},
                    scheduleNextMainQueueTurn: { _ in },
                    adopt: {}
                )
            }
        )

        XCTAssertTrue(started)
        XCTAssertEqual(nestedBeginResult, false)
        XCTAssertFalse(handoff.isPending)
    }

    @MainActor
    func testStaleCallbackCannotClaimRearmedHandoff() throws {
        let handoff = BrokerGrantActivationHandoff()
        let first = FakeBrokerGrantActivationEnvironment(isApplicationActive: false)
        let second = FakeBrokerGrantActivationEnvironment(isApplicationActive: false)

        XCTAssertTrue(first.begin(handoff))
        let staleCallback = try XCTUnwrap(first.nextTurnCallbacks.first)
        staleCallback()
        XCTAssertEqual(first.adoptionCount, 1)

        XCTAssertTrue(second.begin(handoff))
        staleCallback()
        XCTAssertTrue(handoff.isPending)
        XCTAssertEqual(first.adoptionCount, 1)
        XCTAssertEqual(second.adoptionCount, 0)

        try XCTUnwrap(second.nextTurnCallbacks.first)()
        XCTAssertEqual(second.adoptionCount, 1)
        XCTAssertFalse(handoff.isPending)
    }
}

@MainActor
private final class FakeBrokerGrantActivationEnvironment {
    enum Event: Equatable {
        case requestedActivation
        case scheduledNextTurn
    }

    let isApplicationActive: Bool
    private(set) var events: [Event] = []
    private(set) var adoptionCount = 0
    private(set) var nextTurnCallbacks: [@MainActor () -> Void] = []

    init(isApplicationActive: Bool) {
        self.isApplicationActive = isApplicationActive
    }

    func begin(_ handoff: BrokerGrantActivationHandoff) -> Bool {
        handoff.beginApplicationActivation(
            isApplicationActive: { self.isApplicationActive },
            requestActivation: { self.events.append(.requestedActivation) },
            scheduleNextMainQueueTurn: {
                self.events.append(.scheduledNextTurn)
                self.nextTurnCallbacks.append($0)
            },
            adopt: {
                self.adoptionCount += 1
            }
        )
    }
}
