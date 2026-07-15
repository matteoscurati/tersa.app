// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import AppKit
import Foundation

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        Task { @MainActor in
            let evidence = await MimeHostileContentPolicy().run()
            try? await Task.sleep(for: .seconds(2))
            emit(evidence)
            NSApp.terminate(nil)
        }
    }

    private func emit(_ evidence: MimeHostileContentPolicy.Evidence) {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = (try? encoder.encode(evidence)) ?? Self.encodingFailureEvidence
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.write(Data([0x0A]))
    }

    private static let encodingFailureEvidence = Data(
        "{\"contentRuleListAttached\":false,\"dataStoreIsNonPersistent\":false,\"failureCode\":-1,\"failureCount\":1,\"initialNavigationAllowed\":false,\"javaScriptDisabled\":false,\"label\":\"NOT A DEVICE-GATE RESULT\",\"navigationActionsDenied\":0,\"navigationResponsesDenied\":0,\"newWindowsDenied\":0,\"pageJavaScriptDidNotExecute\":false,\"probeCompleted\":false,\"rawControlHash\":\"\",\"rawControlLoaded\":false,\"runMode\":\"encoding-failure\",\"sanitizedDocumentHash\":\"\",\"sanitizedDocumentLoaded\":false,\"sanitizedResourceFound\":false,\"transportControlLoaded\":false,\"websiteDataRecordCount\":0}".utf8
    )
}

@main
@MainActor
private enum MimeDiagnosticMain {
    private static let delegate = AppDelegate()

    static func main() {
        let application = NSApplication.shared
        application.delegate = delegate
        application.run()
    }
}
