// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import SwiftUI
import WebKit

/// One thread over the 2b read C ABI, opened from the inbox or search results.
/// Exercised only once the store holds data; the loading, empty, and failure
/// states mirror the inbox.
@MainActor
struct ThreadView: View {
    let accountIdentifier: Data
    let threadIdentifier: Data

    @Environment(\.dismiss) private var dismiss
    @State private var worker = MailboxReadWorker()
    @State private var outcome: MailboxReadOutcome?

    var body: some View {
        VStack(spacing: 0) {
            threadHeader
            Divider()
            content
        }
            .navigationTitle("Thread")
            .onAppear(perform: loadThread)
            .onChange(of: outcome) { _, newOutcome in
                announceOutcome(newOutcome)
            }
    }

    private var threadHeader: some View {
        HStack {
            Button(action: dismiss.callAsFunction) {
                Label("Back", systemImage: "chevron.left")
            }
            .keyboardShortcut("[", modifiers: .command)
            .accessibilityLabel("Back")
            Spacer()
        }
        .overlay {
            Text("Thread")
                .font(.headline)
                .accessibilityAddTraits(.isHeader)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
    }

    @ViewBuilder
    private var content: some View {
        switch outcome {
        case .none:
            loadingContent
        case .some(.empty):
            threadEmpty
        case .some(.content(let rows)):
            threadList(rows)
        case .some(.failure(let failure)):
            threadFailure(failure)
        }
    }

    private var loadingContent: some View {
        ProgressView()
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .accessibilityLabel("Loading thread")
            .accessibilityValue("In progress")
    }

    private var threadEmpty: some View {
        VStack(spacing: 16) {
            Image(systemName: "tray")
                .font(.system(size: 48))
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            Text("No messages in this thread")
                .font(.title2)
                .accessibilityAddTraits(.isHeader)
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("No messages in this thread")
    }

    private func threadList(_ rows: [MessageRow]) -> some View {
        GeometryReader { proxy in
            List(rows) { row in
                ThreadMessageDetailView(
                    row: row,
                    // Leave room for list chrome + message headers; body grows with the window.
                    availableBodyHeight: max(240, proxy.size.height - 140)
                )
                .listRowInsets(EdgeInsets(top: 8, leading: 12, bottom: 8, trailing: 12))
            }
            .listStyle(.plain)
            .frame(width: proxy.size.width, height: proxy.size.height)
        }
        .accessibilityLabel("Thread")
        .accessibilityValue(String(rows.count) + (rows.count == 1 ? " message" : " messages"))
    }

    private func threadFailure(_ failure: MailboxReadFailure) -> some View {
        VStack(spacing: 16) {
            Image(systemName: "exclamationmark.triangle")
                .font(.system(size: 48))
                .foregroundStyle(.orange)
                .accessibilityHidden(true)
            Text("The thread could not be loaded")
                .font(.title2)
                .accessibilityAddTraits(.isHeader)
            Text(failure.message)
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button("Try again", action: handleThreadReloadTapped)
                .keyboardShortcut(.defaultAction)
                .accessibilityLabel("Try again")
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func loadThread() {
        worker.enqueueRead(
            accountIdentifier: accountIdentifier,
            threadIdentifier: threadIdentifier
        ) { result in
            self.outcome = result
        }
    }

    private func reloadThread() {
        outcome = nil
        loadThread()
    }

    private func handleThreadReloadTapped() {
        reloadThread()
    }

    private func announceOutcome(_ newOutcome: MailboxReadOutcome?) {
        guard let newOutcome else {
            return
        }
        AccessibilityNotification.Announcement(newOutcome.announcement).post()
    }
}

/// Expanded message card: sender, subject, date, and offline body with plain/HTML toggle.
@MainActor
private struct ThreadMessageDetailView: View {
    enum BodyMode: String, CaseIterable, Identifiable {
        case plain = "Plain text"
        case html = "HTML"

        var id: String { rawValue }
    }

    let row: MessageRow
    /// Height budget for the body region; tracks the parent GeometryReader on resize.
    let availableBodyHeight: CGFloat
    @State private var bodyMode: BodyMode = .plain

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                if row.unread {
                    Circle()
                        .fill(Color.accentColor)
                        .frame(width: 8, height: 8)
                        .accessibilityHidden(true)
                }
                Text(row.from)
                    .font(.headline)
                    .lineLimit(2)
                Spacer(minLength: 8)
                Text(row.receivedDate, format: .dateTime.month(.abbreviated).day().hour().minute())
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Text(row.subject)
                .font(.title3)
                .fontWeight(.semibold)
            if row.hasHtmlBody {
                Picker("Body format", selection: $bodyMode) {
                    ForEach(availableModes) { mode in
                        Text(mode.rawValue).tag(mode)
                    }
                }
                .pickerStyle(.segmented)
                .frame(maxWidth: 280)
                .accessibilityLabel("Body format")
            }
            Divider()
            bodyContent
        }
        .padding(.vertical, 10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .onAppear {
            // Prefer plain when both exist; fall back to HTML-only messages.
            if !row.hasPlainBody, row.hasHtmlBody {
                bodyMode = .html
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel(accessibilityLabel)
    }

    private var availableModes: [BodyMode] {
        var modes: [BodyMode] = []
        if row.hasPlainBody {
            modes.append(.plain)
        }
        if row.hasHtmlBody {
            modes.append(.html)
        }
        if modes.isEmpty {
            modes.append(.plain)
        }
        return modes
    }

    @ViewBuilder
    private var bodyContent: some View {
        switch bodyMode {
        case .plain:
            Text(row.displayBody.isEmpty ? "No message body is available offline." : row.displayBody)
                .font(.body)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .foregroundStyle(row.displayBody.isEmpty ? .secondary : .primary)
        case .html:
            if let html = row.bodyHtml, !html.isEmpty {
                SandboxedMailHTMLView(html: html)
                    .frame(maxWidth: .infinity)
                    .frame(height: availableBodyHeight)
                    .clipShape(RoundedRectangle(cornerRadius: 8))
                    .overlay(
                        RoundedRectangle(cornerRadius: 8)
                            .stroke(Color.secondary.opacity(0.25))
                    )
                    .accessibilityLabel("HTML message body")
            } else {
                Text("No HTML body is available offline.")
                    .font(.body)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var accessibilityLabel: String {
        let unreadText = row.unread ? "Unread, " : ""
        let dateText = row.receivedDate.formatted(
            .dateTime.month(.abbreviated).day().hour().minute()
        )
        let body: String
        switch bodyMode {
        case .plain:
            body = row.displayBody.isEmpty ? "No message body is available offline" : row.displayBody
        case .html:
            body = row.hasHtmlBody ? "HTML message body" : "No HTML body is available offline"
        }
        return unreadText + row.from + ", " + row.subject + ", " + dateText + ", " + body
    }
}

/// Renders offline HTML mail in a fail-closed WKWebView: no JavaScript, no
/// navigation away from the document, and content-rule blocking of remote loads.
@MainActor
private struct SandboxedMailHTMLView: NSViewRepresentable {
    let html: String

    func makeNSView(context: Context) -> WKWebView {
        let preferences = WKWebpagePreferences()
        preferences.allowsContentJavaScript = false

        let configuration = WKWebViewConfiguration()
        configuration.defaultWebpagePreferences = preferences
        configuration.preferences.isElementFullscreenEnabled = false
        configuration.websiteDataStore = .nonPersistent()

        let webView = WKWebView(frame: .zero, configuration: configuration)
        webView.navigationDelegate = context.coordinator
        webView.autoresizingMask = [.width, .height]
        webView.setValue(false, forKey: "drawsBackground")
        context.coordinator.installContentBlocker(on: webView)
        context.coordinator.load(html: html, in: webView)
        return webView
    }

    func updateNSView(_ webView: WKWebView, context: Context) {
        context.coordinator.load(html: html, in: webView)
    }

    func makeCoordinator() -> Coordinator {
        Coordinator()
    }

    @MainActor
    final class Coordinator: NSObject, WKNavigationDelegate {
        private var lastHTML: String?
        private var contentRuleList: WKContentRuleList?

        func installContentBlocker(on webView: WKWebView) {
            // Block all subresource/network fetches; the document itself is loaded
            // from a string with a nil base URL.
            let rules = """
            [{
              "trigger": { "url-filter": ".*" },
              "action": { "type": "block" }
            }]
            """
            WKContentRuleListStore.default().compileContentRuleList(
                forIdentifier: "tersa.mail.html.offline.block-all",
                encodedContentRuleList: rules
            ) { [weak self, weak webView] list, _ in
                guard let list, let webView else { return }
                self?.contentRuleList = list
                webView.configuration.userContentController.add(list)
            }
        }

        func load(html: String, in webView: WKWebView) {
            let wrapped = Self.wrapForFlexibleWidth(html)
            guard lastHTML != wrapped else { return }
            lastHTML = wrapped
            // nil baseURL prevents relative network resolution from a local origin.
            webView.loadHTMLString(wrapped, baseURL: nil)
        }

        /// Injects a viewport + fluid layout so HTML reflows when the host view resizes.
        private static func wrapForFlexibleWidth(_ html: String) -> String {
            let headInjection = """
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
            html, body {
              margin: 0;
              padding: 8px;
              max-width: 100%;
              overflow-x: auto;
              overflow-wrap: anywhere;
              word-break: break-word;
              box-sizing: border-box;
              font-family: -apple-system, system-ui, sans-serif;
            }
            img, table, video, iframe {
              max-width: 100% !important;
              height: auto !important;
            }
            * { box-sizing: border-box; }
            </style>
            """
            if let headRange = html.range(of: "<head", options: .caseInsensitive),
               let headClose = html[headRange.lowerBound...].range(of: ">")
            {
                var result = html
                result.insert(contentsOf: headInjection, at: headClose.upperBound)
                return result
            }
            if let htmlRange = html.range(of: "<html", options: .caseInsensitive),
               let htmlClose = html[htmlRange.lowerBound...].range(of: ">")
            {
                var result = html
                result.insert(
                    contentsOf: "<head>" + headInjection + "</head>",
                    at: htmlClose.upperBound
                )
                return result
            }
            return "<!DOCTYPE html><html><head>"
                + headInjection
                + "</head><body>"
                + html
                + "</body></html>"
        }

        func webView(
            _ webView: WKWebView,
            decidePolicyFor navigationAction: WKNavigationAction,
            decisionHandler: @escaping (WKNavigationActionPolicy) -> Void
        ) {
            // Allow only the initial string document load. Cancel link clicks and
            // any navigation to a remote/local URL.
            if navigationAction.navigationType == .other {
                decisionHandler(.allow)
                return
            }
            decisionHandler(.cancel)
        }

        func webView(
            _ webView: WKWebView,
            decidePolicyFor navigationResponse: WKNavigationResponse,
            decisionHandler: @escaping (WKNavigationResponsePolicy) -> Void
        ) {
            // The offline HTML document itself is allowed; subresources are
            // blocked by content rules and cancelled here as belt-and-suspenders.
            if navigationResponse.isForMainFrame {
                decisionHandler(.allow)
            } else {
                decisionHandler(.cancel)
            }
        }
    }
}
