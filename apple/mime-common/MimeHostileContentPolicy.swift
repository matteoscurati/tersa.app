// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import CryptoKit
import Foundation
import WebKit
#if os(macOS)
import AppKit
#endif

@MainActor
final class MimeHostileContentPolicy: NSObject, WKNavigationDelegate, WKUIDelegate {
    struct Evidence: Encodable {
        let contentRuleListAttached: Bool
        let dataStoreIsNonPersistent: Bool
        let failureCount: Int
        let failureCode: Int
        let initialNavigationAllowed: Bool
        let javaScriptDisabled: Bool
        let navigationActionsDenied: Int
        let navigationResponsesDenied: Int
        let newWindowsDenied: Int
        let pageJavaScriptDidNotExecute: Bool
        let probeCompleted: Bool
        let rawControlHash: String
        let rawControlLoaded: Bool
        let sanitizedDocumentHash: String
        let sanitizedDocumentLoaded: Bool
        let sanitizedResourceFound: Bool
        let websiteDataRecordCount: Int
        let label: String = "NOT A DEVICE-GATE RESULT"
    }

    private enum CaseKind {
        case sanitized
        case rawControl
    }

    private struct NavigationWaiter {
        let identifier: UUID
        let continuation: CheckedContinuation<Void, Never>
    }

    private static let rawControlTemplate = """
    <!doctype html><html><head><meta charset=\"utf-8\"><title>RAW_CONTROL</title><meta http-equiv=\"refresh\" content=\"0;url=__CANARY__/navigation\"><link rel=\"stylesheet\" href=\"__CANARY__/style.css\"><script src=\"__CANARY__/script.js\"></script></head><body onload=\"document.title='JAVASCRIPT_EXECUTED';fetch('__CANARY__/inline-js');window.open('__CANARY__/new-window');location='__CANARY__/inline-navigation'\"><img src=\"__CANARY__/image.png\"><form action=\"__CANARY__/form\" method=\"post\" target=\"_blank\"><button type=\"submit\">Submit</button></form><script>document.forms[0].submit();</script></body></html>
    """

    private let dataStore: WKWebsiteDataStore
    private let canaryBaseURL: URL?
    private var contentRuleListAttached = false
    private var currentCase: CaseKind?
    private var initialNavigationPending = false
    private var initialNavigationWasAllowed = false
    private var initialNavigationResponsePending = false
    private var navigationDenialWaiter: CheckedContinuation<Void, Never>?
    private var navigationWaiter: NavigationWaiter?
    private var sanitizedDocumentLoaded = false
    private var rawControlLoaded = false
    private var rawControlHash = ""
    private var navigationActionsDenied = 0
    private var navigationResponsesDenied = 0
    private var newWindowsDenied = 0
    private var pageJavaScriptDidNotExecute = false
    private var failureCount = 0
    private var failureCode = 0

    init(environment: [String: String] = ProcessInfo.processInfo.environment) {
        dataStore = .nonPersistent()
        canaryBaseURL = Self.canaryBaseURL(environment: environment)
        super.init()
    }

    func run() async -> Evidence {
        guard let canaryBaseURL, let documentBaseURL = URL(string: "about:blank") else {
            failureCount += 1
            return await makeEvidence(probeCompleted: false)
        }

        let configuration: WKWebViewConfiguration
        do {
            configuration = try await makeConfiguration()
        } catch {
            failureCount += 1
            return await makeEvidence(probeCompleted: false)
        }

        let webView = WKWebView(frame: .zero, configuration: configuration)
        webView.navigationDelegate = self
        webView.uiDelegate = self
#if os(macOS)
        let hostWindow = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 640, height: 480),
            styleMask: [.borderless],
            backing: .buffered,
            defer: false
        )
        hostWindow.contentView = webView
        hostWindow.orderOut(nil)
#endif

        let sanitizedDocument = loadSanitizedDocument()
        if let sanitizedDocument {
            await load(sanitizedDocument, into: webView, baseURL: documentBaseURL, kind: .sanitized)
        } else {
            failureCount += 1
        }
        let rawControl = Self.rawControl(canaryBaseURL: canaryBaseURL)
        rawControlHash = Self.sha256(rawControl)
        await load(rawControl, into: webView, baseURL: documentBaseURL, kind: .rawControl)
        pageJavaScriptDidNotExecute = webView.title != "JAVASCRIPT_EXECUTED"
        await exerciseNavigationDenial(in: webView)
#if os(macOS)
        hostWindow.contentView = nil
#endif

        return await makeEvidence(probeCompleted: sanitizedDocument != nil)
    }

    func webView(
        _ webView: WKWebView,
        decidePolicyFor navigationAction: WKNavigationAction,
        decisionHandler: @escaping @MainActor (WKNavigationActionPolicy) -> Void
    ) {
        if initialNavigationPending, navigationAction.targetFrame?.isMainFrame == true {
            initialNavigationPending = false
            initialNavigationWasAllowed = true
            initialNavigationResponsePending = true
            decisionHandler(.allow)
            return
        }

        navigationActionsDenied += 1
        finishNavigationDenialWaiter()
        decisionHandler(.cancel)
    }

    func webView(
        _ webView: WKWebView,
        decidePolicyFor navigationResponse: WKNavigationResponse,
        decisionHandler: @escaping @MainActor (WKNavigationResponsePolicy) -> Void
    ) {
        if initialNavigationResponsePending {
            initialNavigationResponsePending = false
            decisionHandler(.allow)
            return
        }

        navigationResponsesDenied += 1
        decisionHandler(.cancel)
    }

    func webView(
        _ webView: WKWebView,
        createWebViewWith configuration: WKWebViewConfiguration,
        for navigationAction: WKNavigationAction,
        windowFeatures: WKWindowFeatures
    ) -> WKWebView? {
        newWindowsDenied += 1
        return nil
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        switch currentCase {
        case .sanitized:
            sanitizedDocumentLoaded = true
        case .rawControl:
            rawControlLoaded = true
        case nil:
            failureCount += 1
        }
        finishNavigationWaiter()
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        failureCount += 1
        failureCode = (error as NSError).code
        finishNavigationWaiter()
    }

    func webView(
        _ webView: WKWebView,
        didFailProvisionalNavigation navigation: WKNavigation!,
        withError error: Error
    ) {
        failureCount += 1
        failureCode = (error as NSError).code
        finishNavigationWaiter()
    }

    func webViewWebContentProcessDidTerminate(_ webView: WKWebView) {
        failureCount += 1
        failureCode = -1
        finishNavigationWaiter()
    }

    private func makeConfiguration() async throws -> WKWebViewConfiguration {
        let ruleList = try await compileRuleList()
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = dataStore
        let preferences = WKWebpagePreferences()
        preferences.allowsContentJavaScript = false
        configuration.defaultWebpagePreferences = preferences
        configuration.userContentController.add(ruleList)
        contentRuleListAttached = true
        return configuration
    }

    private func compileRuleList() async throws -> WKContentRuleList {
        let rules = """
        [{"trigger":{"url-filter":"^https?://"},"action":{"type":"block"}}]
        """
        return try await withCheckedThrowingContinuation { continuation in
            WKContentRuleListStore.default().compileContentRuleList(
                forIdentifier: "tersa.mime.hostile-content.block-all.v1",
                encodedContentRuleList: rules
            ) { ruleList, error in
                if let ruleList {
                    continuation.resume(returning: ruleList)
                } else if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(throwing: MimePolicyError.ruleListUnavailable)
                }
            }
        }
    }

    private func load(_ document: String, into webView: WKWebView, baseURL: URL, kind: CaseKind) async {
        currentCase = kind
        initialNavigationPending = true
        initialNavigationResponsePending = false
        let identifier = UUID()
        await withCheckedContinuation { continuation in
            navigationWaiter = NavigationWaiter(
                identifier: identifier,
                continuation: continuation
            )
            webView.loadHTMLString(document, baseURL: baseURL)
            Task { @MainActor in
                try? await Task.sleep(for: .seconds(10))
                guard navigationWaiter?.identifier == identifier else {
                    return
                }
                failureCount += 1
                failureCode = -2
                webView.stopLoading()
                finishNavigationWaiter()
            }
        }
    }

    private func finishNavigationWaiter() {
        guard let waiter = navigationWaiter else {
            return
        }
        navigationWaiter = nil
        waiter.continuation.resume()
    }

    private func exerciseNavigationDenial(in webView: WKWebView) async {
        guard let deniedURL = URL(string: "about:blank#tersa-denied-navigation") else {
            failureCount += 1
            failureCode = -3
            return
        }
        await withCheckedContinuation { continuation in
            navigationDenialWaiter = continuation
            webView.load(URLRequest(url: deniedURL))
            Task { @MainActor in
                try? await Task.sleep(for: .seconds(5))
                guard navigationDenialWaiter != nil else {
                    return
                }
                failureCount += 1
                failureCode = -3
                finishNavigationDenialWaiter()
            }
        }
    }

    private func finishNavigationDenialWaiter() {
        guard let waiter = navigationDenialWaiter else {
            return
        }
        navigationDenialWaiter = nil
        waiter.resume()
    }

    private func loadSanitizedDocument() -> String? {
        guard let resourceURL = Bundle.main.url(forResource: "sanitized", withExtension: "html"),
              let document = try? String(contentsOf: resourceURL, encoding: .utf8)
        else {
            return nil
        }
        return document
    }

    private func makeEvidence(probeCompleted: Bool) async -> Evidence {
        let sanitizedDocument = loadSanitizedDocument() ?? ""
        let recordCount = await websiteDataRecordCount()
        return Evidence(
            contentRuleListAttached: contentRuleListAttached,
            dataStoreIsNonPersistent: true,
            failureCount: failureCount,
            failureCode: failureCode,
            initialNavigationAllowed: initialNavigationWasAllowed,
            javaScriptDisabled: true,
            navigationActionsDenied: navigationActionsDenied,
            navigationResponsesDenied: navigationResponsesDenied,
            newWindowsDenied: newWindowsDenied,
            pageJavaScriptDidNotExecute: pageJavaScriptDidNotExecute,
            probeCompleted: probeCompleted,
            rawControlHash: rawControlHash,
            rawControlLoaded: rawControlLoaded,
            sanitizedDocumentHash: Self.sha256(sanitizedDocument),
            sanitizedDocumentLoaded: sanitizedDocumentLoaded,
            sanitizedResourceFound: !sanitizedDocument.isEmpty,
            websiteDataRecordCount: recordCount
        )
    }

    private func websiteDataRecordCount() async -> Int {
        await withCheckedContinuation { continuation in
            dataStore.fetchDataRecords(ofTypes: WKWebsiteDataStore.allWebsiteDataTypes()) { records in
                continuation.resume(returning: records.count)
            }
        }
    }

    private static func canaryBaseURL(environment: [String: String]) -> URL? {
        guard let portText = environment["TERSA_MIME_CANARY_PORT"],
              let port = UInt16(portText),
              port > 0
        else {
            return nil
        }
        return URL(string: "http://127.0.0.1:\(port)/")
    }

    private static func rawControl(canaryBaseURL: URL) -> String {
        let base = canaryBaseURL.absoluteString.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        return rawControlTemplate.replacingOccurrences(of: "__CANARY__", with: base)
    }

    private static func sha256(_ value: String) -> String {
        SHA256.hash(data: Data(value.utf8)).map { String(format: "%02x", $0) }.joined()
    }
}

private enum MimePolicyError: Error {
    case ruleListUnavailable
}
