// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import SwiftUI

/// Account-connection surface: identifier form, browser sign-in progress with
/// cancel, disconnect progress, failure with retry, and the dismissible
/// disconnect notice banner. All controls are plain keyboard-reachable
/// AppKit-backed SwiftUI controls; nothing is gesture-only.
@MainActor
struct AccountConnectionView: View {
    @ObservedObject var viewModel: AccountConnectionViewModel

    var body: some View {
        VStack(spacing: 20) {
            if let disconnectNotice = viewModel.disconnectNotice {
                disconnectNoticeBanner(disconnectNotice)
            } else if let confirmation = viewModel.disconnectConfirmation {
                disconnectConfirmationBanner(confirmation)
            }
            switch viewModel.state {
            case .notConnected, .connecting:
                connectionContent(isConnecting: viewModel.state == .connecting)
            case .authorizing:
                authorizingContent
            case .disconnecting:
                disconnectingContent
            case .failed(let failure):
                failureContent(failure)
            case .connected:
                // RootView swaps to the inbox on `.connected`; this view is only
                // shown while not connected, so this branch is never rendered.
                EmptyView()
            }
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Account connection")
        .accessibilityValue(viewModel.state.accessibilityValue)
        .onChange(of: viewModel.disconnectNotice) { _, newNotice in
            announce(newNotice)
        }
        .onChange(of: viewModel.disconnectConfirmation) { _, newConfirmation in
            announce(newConfirmation)
        }
    }

    private func connectionContent(isConnecting: Bool) -> some View {
        VStack(spacing: 20) {
            Image(systemName: "person.crop.circle.badge.plus")
                .font(.system(size: 48))
                .foregroundStyle(Color.accentColor)
                .accessibilityHidden(true)
            Text("Connect your account")
                .font(.title2)
            Text("Enter a local account name, such as primary-gmail, to connect this Mac.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            if isConnecting {
                ProgressView()
                    .accessibilityLabel("Connection progress")
                    .accessibilityValue("In progress")
            }
            TextField("Local account name", text: $viewModel.accountIdentifier)
                .textFieldStyle(.roundedBorder)
                .frame(maxWidth: 320)
                .disabled(isConnecting)
                .accessibilityLabel("Local account name")
                .onSubmit(handleConnectTapped)
            Button("Connect", action: handleConnectTapped)
                .keyboardShortcut(.defaultAction)
                .disabled(isConnecting || viewModel.isConnectDisabled)
                .accessibilityLabel("Connect account")
        }
    }

    private var authorizingContent: some View {
        VStack(spacing: 20) {
            Image(systemName: "safari")
                .font(.system(size: 48))
                .foregroundStyle(Color.accentColor)
                .accessibilityHidden(true)
            Text("Finish sign-in in your browser")
                .font(.title2)
            Text("Tersa opened a sign-in page in your browser. Tersa finishes connecting automatically once you've signed in.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            ProgressView()
                .accessibilityLabel("Sign-in progress")
                .accessibilityValue("Waiting for browser sign-in")
            Button("Cancel", action: viewModel.cancelAuthorization)
                .keyboardShortcut(.cancelAction)
                .accessibilityLabel("Cancel sign-in")
        }
    }

    private var disconnectingContent: some View {
        VStack(spacing: 20) {
            Image(systemName: "person.crop.circle.badge.minus")
                .font(.system(size: 48))
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            Text("Disconnecting account")
                .font(.title2)
            Text("Revoking Tersa's access and removing mail stored on this Mac.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            ProgressView()
                .accessibilityLabel("Disconnect progress")
                .accessibilityValue("In progress")
        }
    }

    private func failureContent(_ failure: ConnectionFailure) -> some View {
        VStack(spacing: 20) {
            Image(systemName: "exclamationmark.triangle")
                .font(.system(size: 48))
                .foregroundStyle(.orange)
                .accessibilityHidden(true)
            Text(failure.title)
                .font(.title2)
            Text(failure.message)
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button(retryLabel(failure)) {
                viewModel.retryAfterFailure(failure)
            }
            .keyboardShortcut(.defaultAction)
            .accessibilityLabel(retryLabel(failure))
        }
    }

    /// The retry button names the operation it retries, so "Try again" under
    /// "Disconnect failed" can't read as "retry connecting".
    private func retryLabel(_ failure: ConnectionFailure) -> String {
        switch failure {
        case .signInExpired, .signInFailed, .signInUnavailable, .permissionRequired:
            return "Sign in again"
        case .disconnectIncomplete:
            return "Disconnect again"
        case .disconnectTimedOut:
            return "Keep waiting"
        case .connectionTimedOut:
            return "Keep waiting"
        default:
            return "Try again"
        }
    }

    /// The M2 WARNING banner: the revoke could not be confirmed, so it carries
    /// a link the user can act on (Google's connections page) — a remedy the
    /// user can't reach isn't a remedy — plus a non-chromatic severity glyph so
    /// the warning reads without relying on the orange tint.
    private func disconnectNoticeBanner(_ notice: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 8) {
                Text(notice)
                    .font(.callout)
                    .multilineTextAlignment(.leading)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityLabel("Revoke not confirmed")
                    .accessibilityValue(notice)
                Link("Open Google Account settings",
                     destination: AccountConnectionViewModel.googleConnectionsURL)
                    .accessibilityLabel("Open Google Account settings to remove Tersa")
            }
            Spacer(minLength: 8)
            Button("Dismiss", action: viewModel.dismissDisconnectNotice)
                .accessibilityLabel("Dismiss revoke warning")
        }
        .padding(12)
        .frame(maxWidth: 420)
        .background(Color.orange.opacity(0.15), in: RoundedRectangle(cornerRadius: 8))
    }

    /// The neutral clean-disconnect confirmation: distinct style from the M2
    /// warning (no orange, no link), so its mere presence never reads as
    /// "revoke unconfirmed".
    private func disconnectConfirmationBanner(_ confirmation: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Image(systemName: "checkmark.circle.fill")
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            Text(confirmation)
                .font(.callout)
                .multilineTextAlignment(.leading)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityLabel("Disconnected")
                .accessibilityValue(confirmation)
            Spacer(minLength: 8)
            Button("Dismiss", action: viewModel.dismissDisconnectNotice)
                .accessibilityLabel("Dismiss confirmation")
        }
        .padding(12)
        .frame(maxWidth: 420)
        .background(Color.secondary.opacity(0.12), in: RoundedRectangle(cornerRadius: 8))
    }

    private func handleConnectTapped() {
        viewModel.connect()
    }

    private func announce(_ message: String?) {
        guard let message else {
            return
        }
        AccessibilityNotification.Announcement(message).post()
    }
}
