// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import XCTest

final class SearchCompletionGuardTests: XCTestCase {
    func testUnchangedFieldDisplaysTheResult() {
        XCTAssertEqual(
            SearchCompletionGuard.decision(completedQuery: "invoice", currentFieldText: "invoice"),
            .displayResult
        )
    }

    func testEditedFieldDiscardsTheStaleResult() {
        XCTAssertEqual(
            SearchCompletionGuard.decision(completedQuery: "invoice", currentFieldText: "invoice q3"),
            .discardStale
        )
        XCTAssertEqual(
            SearchCompletionGuard.decision(completedQuery: "invoice", currentFieldText: ""),
            .discardStale
        )
    }

    func testFieldTrimmingMatchesTheSubmitTrimming() {
        // Submit trims the field before searching, so a field that differs
        // only by surrounding whitespace still shows the completed query.
        XCTAssertEqual(
            SearchCompletionGuard.decision(completedQuery: "invoice", currentFieldText: "  invoice  "),
            .displayResult
        )
    }

    func testStaleEditStatusIsFixedCopyThatNeverCarriesQueryText() {
        let status = SearchCompletionGuard.staleEditStatus

        XCTAssertEqual(status, "Search text changed. Press Return to search again.")
        // A sample of query-shaped content must never appear in the status.
        for sample in ["invoice", "alice@example.com", "Q3 budget"] {
            XCTAssertFalse(status.contains(sample))
        }
    }
}
