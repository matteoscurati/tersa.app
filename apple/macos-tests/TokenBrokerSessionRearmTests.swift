// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import XCTest

/// Deterministic re-arm and stale-callback gating tests for the broker-backed
/// authorization session attempt lifecycle.
///
/// No live XPC, network, listener, or Keychain. The session instance is
/// app-lifetime, so a terminal outcome (cancel, success, timeout, failure)
/// must be followable by a new `start`, and every asynchronous callback from
/// the prior attempt must be rejected by the generation gate. These tests pin
/// the exact production lifecycle value type the session stores and the gate
/// every callback passes through before mutating session state.
final class TokenBrokerSessionRearmTests: XCTestCase {
    func testInitialLifecyclePermitsFirstStart() {
        let lifecycle = TokenBrokerSessionAttemptLifecycle()
        XCTAssertTrue(lifecycle.canStart)
        XCTAssertTrue(lifecycle.isFinished)
        XCTAssertEqual(lifecycle.generation, 0)
    }

    func testActiveAttemptRejectsSecondStartUntilTerminal() {
        var lifecycle = TokenBrokerSessionAttemptLifecycle()
        let generation = lifecycle.beginAttempt()
        XCTAssertTrue(lifecycle.isCurrent(generation))
        // While the attempt is live a second start must stay rejected.
        XCTAssertFalse(lifecycle.canStart)
        lifecycle.finishAttempt()
        // After the terminal outcome the same instance may start again.
        XCTAssertTrue(lifecycle.canStart)
        XCTAssertTrue(lifecycle.isFinished)
    }

    func testEveryTerminalOutcomeKindAllowsRearmWithFreshGeneration() {
        // Cancel, success, timeout, and failure all terminate via the same
        // finish path; each cycle must leave the lifecycle startable again
        // with a strictly increasing generation.
        var lifecycle = TokenBrokerSessionAttemptLifecycle()
        var previousGeneration = lifecycle.generation
        for cycle in 0..<4 {
            XCTAssertTrue(lifecycle.canStart, "cycle \(cycle) must be startable")
            let generation = lifecycle.beginAttempt()
            XCTAssertGreaterThan(
                generation,
                previousGeneration,
                "cycle \(cycle) must arm a fresh generation"
            )
            XCTAssertTrue(lifecycle.isCurrent(generation))
            XCTAssertFalse(lifecycle.canStart, "cycle \(cycle) is active; no second start")
            lifecycle.finishAttempt()
            XCTAssertFalse(lifecycle.isCurrent(generation))
            previousGeneration = generation
        }
        XCTAssertTrue(lifecycle.canStart)
    }

    func testStaleGenerationCannotGateIntoRearmedAttempt() {
        var lifecycle = TokenBrokerSessionAttemptLifecycle()
        let staleGeneration = lifecycle.beginAttempt()
        lifecycle.finishAttempt()
        let liveGeneration = lifecycle.beginAttempt()

        XCTAssertNotEqual(staleGeneration, liveGeneration)
        // Delayed callback/timer/listener event captured by the prior attempt.
        XCTAssertFalse(lifecycle.isCurrent(staleGeneration))
        XCTAssertTrue(lifecycle.isCurrent(liveGeneration))
    }

    func testStaleCallbackCompositionCannotFinishOrClaimLiveAttempt() {
        // Mirrors the production gate order: every asynchronous entry point
        // checks isCurrent before finish or the forwarded-callback latch.
        var lifecycle = TokenBrokerSessionAttemptLifecycle()
        let staleGeneration = lifecycle.beginAttempt()
        lifecycle.finishAttempt()
        let liveGeneration = lifecycle.beginAttempt()

        // A stale finish path must be rejected by the gate before it can
        // terminate the live attempt.
        var staleFinishRan = false
        if lifecycle.isCurrent(staleGeneration) {
            lifecycle.finishAttempt()
            staleFinishRan = true
        }
        XCTAssertFalse(staleFinishRan)
        XCTAssertTrue(lifecycle.isCurrent(liveGeneration))
        XCTAssertFalse(lifecycle.canStart)

        // The live attempt's callback latch remains claimable exactly once;
        // nothing the stale attempt did consumed it.
        var hasForwardedCallback = false
        XCTAssertTrue(
            TokenBrokerAuthorizationSession.claimForwardedCallback(
                isFinished: lifecycle.isFinished,
                hasForwardedCallback: &hasForwardedCallback
            )
        )
        XCTAssertFalse(
            TokenBrokerAuthorizationSession.claimForwardedCallback(
                isFinished: lifecycle.isFinished,
                hasForwardedCallback: &hasForwardedCallback
            )
        )

        // The live attempt still completes exactly once and is re-usable.
        lifecycle.finishAttempt()
        XCTAssertFalse(lifecycle.isCurrent(liveGeneration))
        XCTAssertTrue(lifecycle.canStart)
    }

    func testFinishAttemptIsExactlyOnceAndDoesNotRearm() {
        var lifecycle = TokenBrokerSessionAttemptLifecycle()
        let generation = lifecycle.beginAttempt()
        lifecycle.finishAttempt()
        XCTAssertTrue(lifecycle.isFinished)
        XCTAssertTrue(lifecycle.canStart)
        // A duplicate terminal signal (late timeout after failure, etc.) is a
        // no-op and must not advance the generation or reopen anything.
        let generationAfterFinish = lifecycle.generation
        lifecycle.finishAttempt()
        XCTAssertEqual(lifecycle.generation, generationAfterFinish)
        XCTAssertTrue(lifecycle.isFinished)
        XCTAssertFalse(lifecycle.isCurrent(generation))
    }

    func testInFlightCallbacksOfFinishedAttemptAreStaleImmediately() {
        // Between finish and the next start there is no re-arm yet: callbacks
        // from the just-finished attempt must already be rejected so they
        // cannot double-complete the session.
        var lifecycle = TokenBrokerSessionAttemptLifecycle()
        let generation = lifecycle.beginAttempt()
        XCTAssertTrue(lifecycle.isCurrent(generation))
        lifecycle.finishAttempt()
        XCTAssertFalse(lifecycle.isCurrent(generation))
    }

    func testRearmAfterFinishWithinSameCycleKeepsExactlyOnceCompletion() {
        // Sequence one full cancel cycle and one full success-shaped cycle:
        // each attempt finishes exactly once, and the next attempt only arms
        // after the previous terminal outcome.
        var lifecycle = TokenBrokerSessionAttemptLifecycle()
        var completedAttempts = 0
        for _ in 0..<2 {
            XCTAssertTrue(lifecycle.canStart)
            let generation = lifecycle.beginAttempt()
            if lifecycle.isCurrent(generation) {
                lifecycle.finishAttempt()
                completedAttempts += 1
            }
            // Exactly-once: a second finish for the same attempt adds nothing.
            if lifecycle.isCurrent(generation) {
                lifecycle.finishAttempt()
                completedAttempts += 1
            }
        }
        XCTAssertEqual(completedAttempts, 2)
        XCTAssertTrue(lifecycle.canStart)
    }
}
