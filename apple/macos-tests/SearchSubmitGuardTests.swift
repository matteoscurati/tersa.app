// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import XCTest

final class SearchSubmitGuardTests: XCTestCase {
    func testSubmitAllowedWhenNoSearchIsInFlight() {
        XCTAssertEqual(SearchSubmitGuard.decision(searching: false), .submitField)
    }

    func testResubmitRejectedWhileSearchIsInFlight() {
        XCTAssertEqual(SearchSubmitGuard.decision(searching: true), .rejectInFlight)
    }

    func testInProgressStatusIsFixedCopyThatNeverCarriesQueryText() {
        let status = SearchSubmitGuard.inProgressStatus

        XCTAssertEqual(status, "Search already in progress.")
        // A sample of query-shaped content must never appear in the status.
        for sample in ["invoice", "alice@example.com", "Q3 budget"] {
            XCTAssertFalse(status.contains(sample))
        }
    }
}

final class SearchFieldValidatorTests: XCTestCase {
    func testValidFieldSubmitsTheTrimmedQuery() {
        XCTAssertEqual(
            SearchFieldValidator.decision(forFieldText: "  invoice  "),
            .validatedQuery("invoice")
        )
    }

    func testEmptyFieldIsRejectedWithFixedCopy() {
        XCTAssertEqual(SearchFieldValidator.decision(forFieldText: ""), .emptyField)
        XCTAssertEqual(SearchFieldValidator.decision(forFieldText: "   \n"), .emptyField)
        XCTAssertEqual(
            SearchFieldValidator.emptyFieldMessage,
            "Enter search text, then press Return."
        )
    }

    func testFieldExactlyAtTheByteLimitSubmits() {
        let atLimit = String(repeating: "a", count: SearchFieldValidator.maximumQueryByteCount)
        XCTAssertEqual(SearchFieldValidator.decision(forFieldText: atLimit), .validatedQuery(atLimit))
    }

    func testOverLimitFieldIsRejectedWithFixedCopy() {
        let overLimit = String(repeating: "a", count: SearchFieldValidator.maximumQueryByteCount + 1)
        XCTAssertEqual(
            SearchFieldValidator.decision(forFieldText: overLimit),
            .invalid(SearchFieldValidator.tooLongMessage)
        )
        XCTAssertEqual(
            SearchFieldValidator.tooLongMessage,
            "Search text is limited to 256 bytes. Shorten it and try again."
        )
    }

    func testControlCharactersAreRejectedWithFixedCopy() {
        XCTAssertEqual(
            SearchFieldValidator.decision(forFieldText: "invoice\u{07}"),
            .invalid(SearchFieldValidator.controlCharacterMessage)
        )
        XCTAssertEqual(
            SearchFieldValidator.controlCharacterMessage,
            "Search text cannot contain control characters."
        )
    }

    /// Try again routes through this same decision with the current field
    /// text: an unchanged field retries the failed query, an edited field
    /// submits the user's current text — the field is never rewritten to an
    /// earlier query.
    func testRetryDecisionUsesTheCurrentFieldText() {
        XCTAssertEqual(
            SearchFieldValidator.decision(forFieldText: "invoice"),
            .validatedQuery("invoice")
        )
        XCTAssertEqual(
            SearchFieldValidator.decision(forFieldText: "invoice q3"),
            .validatedQuery("invoice q3")
        )
    }

    func testValidationMessagesAreFixedCopyThatNeverCarryQueryText() {
        for message in [
            SearchFieldValidator.emptyFieldMessage,
            SearchFieldValidator.tooLongMessage,
            SearchFieldValidator.controlCharacterMessage,
        ] {
            for sample in ["invoice", "alice@example.com", "Q3 budget"] {
                XCTAssertFalse(message.contains(sample))
            }
        }
    }
}
