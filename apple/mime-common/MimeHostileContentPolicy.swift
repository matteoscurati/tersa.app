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
        let runMode: String
        let sanitizedDocumentHash: String
        let sanitizedDocumentLoaded: Bool
        let sanitizedResourceFound: Bool
        let transportControlLoaded: Bool
        let websiteDataRecordCount: Int
        let label: String = "NOT A DEVICE-GATE RESULT"
    }

    private enum CaseKind {
        case sanitized
        case rawControl
        case transportControl
        case newWindowControl
    }

    private enum ResponsePolicy {
        case allow
        case denyTransportControl
    }

    private enum RunMode: String {
        case protected
        case transportControl = "transport-control"

        init(environment: [String: String]) {
            if environment["TERSA_MIME_RUN_MODE"] == Self.transportControl.rawValue {
                self = .transportControl
            } else {
                self = .protected
            }
        }
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
    private let runMode: RunMode
    private var contentRuleListAttached = false
    private var currentCase: CaseKind?
    private var expectedInitialNavigationURL: URL?
    private var expectedInitialResponsePolicy: ResponsePolicy?
    private var expectedTransportCancellation = false
    private var initialNavigationWasAllowed = false
    private var javaScriptWasDisabled = false
    private var navigationDenialWaiter: CheckedContinuation<Void, Never>?
    private var navigationWaiter: NavigationWaiter?
    private var newWindowWaiter: CheckedContinuation<Void, Never>?
    private var sanitizedDocumentLoaded = false
    private var rawControlLoaded = false
    private var transportControlLoaded = false
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
        runMode = RunMode(environment: environment)
        super.init()
    }

    func run() async -> Evidence {
        guard let canaryBaseURL else {
            recordFailure(code: -10)
            return await makeEvidence(probeCompleted: false)
        }
        switch runMode {
        case .transportControl:
            return await runTransportControl(canaryBaseURL: canaryBaseURL)
        case .protected:
            return await runProtectedProbe(canaryBaseURL: canaryBaseURL)
        }
    }

    func webView(
        _ webView: WKWebView,
        decidePolicyFor navigationAction: WKNavigationAction,
        decisionHandler: @escaping @MainActor (WKNavigationActionPolicy) -> Void
    ) {
        if let expectedURL = expectedInitialNavigationURL,
           navigationAction.targetFrame?.isMainFrame == true
        {
            expectedInitialNavigationURL = nil
            if navigationAction.request.url == expectedURL {
                initialNavigationWasAllowed = true
                decisionHandler(.allow)
            } else {
                recordFailure(code: -11)
                finishNavigationWaiter()
                decisionHandler(.cancel)
            }
            return
        }

        if newWindowWaiter != nil, navigationAction.targetFrame == nil {
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
        guard let responsePolicy = expectedInitialResponsePolicy else {
            navigationResponsesDenied += 1
            decisionHandler(.cancel)
            return
        }
        expectedInitialResponsePolicy = nil
        switch responsePolicy {
        case .allow:
            decisionHandler(.allow)
        case .denyTransportControl:
            guard navigationResponse.response.url == canaryBaseURL?.appendingPathComponent("transport-control") else {
                recordFailure(code: -12)
                finishNavigationWaiter()
                decisionHandler(.cancel)
                return
            }
            navigationResponsesDenied += 1
            transportControlLoaded = true
            expectedTransportCancellation = true
            finishNavigationWaiter()
            decisionHandler(.cancel)
        }
    }

    func webView(
        _ webView: WKWebView,
        createWebViewWith configuration: WKWebViewConfiguration,
        for navigationAction: WKNavigationAction,
        windowFeatures: WKWindowFeatures
    ) -> WKWebView? {
        newWindowsDenied += 1
        finishNewWindowWaiter()
        return nil
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        switch currentCase {
        case .sanitized:
            sanitizedDocumentLoaded = true
        case .rawControl:
            rawControlLoaded = true
        case .newWindowControl:
            break
        case .transportControl:
            recordFailure(code: -13)
        case nil:
            recordFailure(code: -14)
        }
        finishNavigationWaiter()
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        handleNavigationFailure(error)
    }

    func webView(
        _ webView: WKWebView,
        didFailProvisionalNavigation navigation: WKNavigation!,
        withError error: Error
    ) {
        handleNavigationFailure(error)
    }

    func webViewWebContentProcessDidTerminate(_ webView: WKWebView) {
        recordFailure(code: -1)
        finishNavigationWaiter()
        finishNavigationDenialWaiter()
        finishNewWindowWaiter()
    }

    private func runTransportControl(canaryBaseURL: URL) async -> Evidence {
        let configuration = makeBaseConfiguration(javaScriptAllowed: false)
        javaScriptWasDisabled = !configuration.defaultWebpagePreferences.allowsContentJavaScript
        let webView = WKWebView(frame: .zero, configuration: configuration)
        webView.navigationDelegate = self
        let hostWindow = host(webView)
        let controlURL = canaryBaseURL.appendingPathComponent("transport-control")
        await load(
            URLRequest(url: controlURL),
            into: webView,
            expectedURL: controlURL,
            kind: .transportControl,
            responsePolicy: .denyTransportControl
        )
        try? await Task.sleep(for: .milliseconds(100))
        release(hostWindow)
        return await makeEvidence(probeCompleted: transportControlLoaded)
    }

    private func runProtectedProbe(canaryBaseURL: URL) async -> Evidence {
        guard let documentBaseURL = URL(string: "about:blank") else {
            recordFailure(code: -15)
            return await makeEvidence(probeCompleted: false)
        }
        let configuration: WKWebViewConfiguration
        do {
            configuration = try await makeProtectedConfiguration()
        } catch {
            recordFailure(code: -16)
            return await makeEvidence(probeCompleted: false)
        }

        let webView = WKWebView(frame: .zero, configuration: configuration)
        webView.navigationDelegate = self
        webView.uiDelegate = self
        let hostWindow = host(webView)

        let sanitizedDocument = loadSanitizedDocument()
        if let sanitizedDocument {
            await load(
                sanitizedDocument,
                into: webView,
                baseURL: documentBaseURL,
                kind: .sanitized
            )
        } else {
            recordFailure(code: -17)
        }
        let rawControl = Self.rawControl(canaryBaseURL: canaryBaseURL)
        rawControlHash = Self.sha256(rawControl)
        await load(rawControl, into: webView, baseURL: documentBaseURL, kind: .rawControl)
        pageJavaScriptDidNotExecute = webView.title != "JAVASCRIPT_EXECUTED"
        await exerciseNavigationDenial(in: webView)
        await exerciseNewWindowDenial()
        release(hostWindow)

        let completed = sanitizedDocument != nil
            && sanitizedDocumentLoaded
            && rawControlLoaded
            && navigationActionsDenied > 0
            && newWindowsDenied > 0
        return await makeEvidence(probeCompleted: completed)
    }

    private func makeBaseConfiguration(javaScriptAllowed: Bool) -> WKWebViewConfiguration {
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = dataStore
        let preferences = WKWebpagePreferences()
        preferences.allowsContentJavaScript = javaScriptAllowed
        configuration.defaultWebpagePreferences = preferences
        return configuration
    }

    private func makeProtectedConfiguration() async throws -> WKWebViewConfiguration {
        let ruleList = try await compileRuleList()
        let configuration = makeBaseConfiguration(javaScriptAllowed: false)
        configuration.userContentController.add(ruleList)
        contentRuleListAttached = true
        javaScriptWasDisabled = !configuration.defaultWebpagePreferences.allowsContentJavaScript
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

    private func load(
        _ document: String,
        into webView: WKWebView,
        baseURL: URL,
        kind: CaseKind
    ) async {
        await beginNavigation(kind: kind, expectedURL: baseURL, responsePolicy: .allow) {
            webView.loadHTMLString(document, baseURL: baseURL)
        }
    }

    private func load(
        _ request: URLRequest,
        into webView: WKWebView,
        expectedURL: URL,
        kind: CaseKind,
        responsePolicy: ResponsePolicy
    ) async {
        await beginNavigation(kind: kind, expectedURL: expectedURL, responsePolicy: responsePolicy) {
            webView.load(request)
        }
    }

    private func beginNavigation(
        kind: CaseKind,
        expectedURL: URL,
        responsePolicy: ResponsePolicy,
        start: () -> Void
    ) async {
        currentCase = kind
        expectedInitialNavigationURL = expectedURL
        expectedInitialResponsePolicy = responsePolicy
        let identifier = UUID()
        await withCheckedContinuation { continuation in
            navigationWaiter = NavigationWaiter(identifier: identifier, continuation: continuation)
            start()
            Task { @MainActor in
                try? await Task.sleep(for: .seconds(10))
                guard navigationWaiter?.identifier == identifier else {
                    return
                }
                recordFailure(code: -2)
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
            recordFailure(code: -3)
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
                recordFailure(code: -3)
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

    private func exerciseNewWindowDenial() async {
        let configuration = makeBaseConfiguration(javaScriptAllowed: true)
        let webView = WKWebView(frame: .zero, configuration: configuration)
        webView.navigationDelegate = self
        webView.uiDelegate = self
        let hostWindow = host(webView)
        currentCase = .newWindowControl
        await withCheckedContinuation { continuation in
            newWindowWaiter = continuation
            Task { @MainActor in
                do {
                    _ = try await webView.evaluateJavaScript(
                        "window.open('about:blank#tersa-new-window', '_blank')"
                    )
                } catch {
                    recordFailure(code: -4)
                    finishNewWindowWaiter()
                }
                try? await Task.sleep(for: .seconds(5))
                guard newWindowWaiter != nil else {
                    return
                }
                recordFailure(code: -4)
                finishNewWindowWaiter()
            }
        }
        release(hostWindow)
    }

    private func finishNewWindowWaiter() {
        guard let waiter = newWindowWaiter else {
            return
        }
        newWindowWaiter = nil
        waiter.resume()
    }

    private func handleNavigationFailure(_ error: Error) {
        if expectedTransportCancellation {
            expectedTransportCancellation = false
            finishNavigationWaiter()
            return
        }
        recordFailure(code: (error as NSError).code)
        finishNavigationWaiter()
        finishNavigationDenialWaiter()
        finishNewWindowWaiter()
    }

    private func recordFailure(code: Int) {
        failureCount += 1
        failureCode = code
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
            dataStoreIsNonPersistent: !dataStore.isPersistent,
            failureCount: failureCount,
            failureCode: failureCode,
            initialNavigationAllowed: initialNavigationWasAllowed,
            javaScriptDisabled: javaScriptWasDisabled,
            navigationActionsDenied: navigationActionsDenied,
            navigationResponsesDenied: navigationResponsesDenied,
            newWindowsDenied: newWindowsDenied,
            pageJavaScriptDidNotExecute: pageJavaScriptDidNotExecute,
            probeCompleted: probeCompleted,
            rawControlHash: rawControlHash,
            rawControlLoaded: rawControlLoaded,
            runMode: runMode.rawValue,
            sanitizedDocumentHash: Self.sha256(sanitizedDocument),
            sanitizedDocumentLoaded: sanitizedDocumentLoaded,
            sanitizedResourceFound: !sanitizedDocument.isEmpty,
            transportControlLoaded: transportControlLoaded,
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

    private func host(_ webView: WKWebView) -> AnyObject? {
#if os(macOS)
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 640, height: 480),
            styleMask: [.borderless],
            backing: .buffered,
            defer: false
        )
        window.contentView = webView
        window.orderOut(nil)
        return window
#else
        return nil
#endif
    }

    private func release(_ host: AnyObject?) {
#if os(macOS)
        (host as? NSWindow)?.contentView = nil
#endif
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
