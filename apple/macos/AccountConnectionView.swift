// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import SwiftUI

/// Account-connection scaffold: identifier form, progress, failure with
/// retry, and the empty-state inbox once connected. All controls are plain
/// keyboard-reachable AppKit-backed SwiftUI controls; nothing is
/// gesture-only.
@MainActor
struct AccountConnectionView: View {
    @ObservedObject var viewModel: AccountConnectionViewModel

    var body: some View {
        VStack(spacing: 20) {
            switch viewModel.state {
            case .notConnected, .connecting:
                connectionContent(isConnecting: viewModel.state == .connecting)
            case .connected:
                InboxEmptyStateView()
            case .failed(let failure):
                failureContent(failure)
            }
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .accessibilityLabel("Account connection")
        .accessibilityValue(viewModel.state.accessibilityValue)
    }

    private func connectionContent(isConnecting: Bool) -> some View {
        VStack(spacing: 20) {
            Image(systemName: "person.crop.circle.badge.plus")
                .font(.system(size: 48))
                .foregroundStyle(Color.accentColor)
                .accessibilityHidden(true)
            Text("Connect your account")
                .font(.title2)
            Text("Enter an account identifier to connect this Mac.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            if isConnecting {
                ProgressView()
                    .accessibilityLabel("Connection progress")
                    .accessibilityValue("In progress")
            }
            TextField("Account identifier", text: $viewModel.accountIdentifier)
                .textFieldStyle(.roundedBorder)
                .frame(maxWidth: 320)
                .disabled(isConnecting)
                .accessibilityLabel("Account identifier")
                .onSubmit(handleConnectTapped)
            Button("Connect", action: handleConnectTapped)
                .keyboardShortcut(.defaultAction)
                .disabled(isConnecting || viewModel.isConnectDisabled)
                .accessibilityLabel("Connect account")
        }
    }

    private func failureContent(_ failure: ConnectionFailure) -> some View {
        VStack(spacing: 20) {
            Image(systemName: "exclamationmark.triangle")
                .font(.system(size: 48))
                .foregroundStyle(.orange)
                .accessibilityHidden(true)
            Text("Connection failed")
                .font(.title2)
            Text(failure.message)
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button("Try again", action: handleRetryTapped)
                .keyboardShortcut(.defaultAction)
                .accessibilityLabel("Try again")
        }
    }

    private func handleConnectTapped() {
        viewModel.connect()
    }

    private func handleRetryTapped() {
        viewModel.retry()
    }
}
