// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import Foundation
import XCTest

final class DisconnectIntentStoreTests: XCTestCase {
    func testPendingIntentSurvivesAStoreRecreationAndClearsExplicitly() throws {
        let suiteName = "app.tersa.tests.disconnect-intent." + UUID().uuidString
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suiteName))
        defer { defaults.removePersistentDomain(forName: suiteName) }

        let writer = DisconnectIntentStore(defaults: defaults)
        XCTAssertTrue(writer.markPending(accountIdentifier: "primary-gmail"))

        let relaunched = DisconnectIntentStore(defaults: defaults)
        XCTAssertEqual(relaunched.pendingAccountIdentifier(), "primary-gmail")
        XCTAssertTrue(relaunched.clearPending())
        XCTAssertNil(relaunched.pendingAccountIdentifier())
    }

    func testEmptyAccountIdentifierCannotCreateAnIntent() throws {
        let suiteName = "app.tersa.tests.disconnect-intent." + UUID().uuidString
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suiteName))
        defer { defaults.removePersistentDomain(forName: suiteName) }

        let store = DisconnectIntentStore(defaults: defaults)
        XCTAssertFalse(store.markPending(accountIdentifier: ""))
        XCTAssertNil(store.pendingAccountIdentifier())
    }
}
