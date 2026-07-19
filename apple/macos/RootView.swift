// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import SwiftUI

/// Root of the app window: the account-connection flow until connected, then
/// the empty-state inbox. Also announces every connection-state transition to
/// VoiceOver.
@MainActor
struct RootView: View {
    @StateObject private var viewModel = AccountConnectionViewModel()

    var body: some View {
        Group {
            if viewModel.state == .connected {
                InboxEmptyStateView()
            } else {
                AccountConnectionView(viewModel: viewModel)
            }
        }
        .frame(minWidth: 480, minHeight: 360)
        .onChange(of: viewModel.state) { _, newState in
            announceConnectionState(newState)
        }
    }

    private func announceConnectionState(_ state: ConnectionState) {
        AccessibilityNotification.Announcement(state.announcement).post()
    }
}
