// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import Foundation

enum ProductBootstrapStatus: Int32 {
    case ready = 0
    case invalidAccountIdentifier = 1
    case invalidExecutionContext = 2
    case busyOrUnavailable = 3
    case rootMissingWithExistingProfile = 4
    case unavailable = 5
}

/// Serializes the one-shot product bootstrap away from the AppKit main thread.
final class BootstrapWorker: @unchecked Sendable {
    private let queue = DispatchQueue(label: "app.tersa.macos.bootstrap", qos: .utility)
    private let state = NSLock()
    private var running = false
    private var pending: (() -> Void)?

    /// Queues one operation. A second queued request is rejected immediately.
    func submit(accountIdentifier: Data, completion: @escaping @MainActor (ProductBootstrapStatus) -> Void) {
        let operation = { [queue] in
            queue.async {
                let status = accountIdentifier.withUnsafeBytes { bytes in
                    tersa_macos_bootstrap_default_account(
                        bytes.bindMemory(to: UInt8.self).baseAddress,
                        bytes.count
                    )
                }
                let closedStatus = ProductBootstrapStatus(rawValue: status) ?? .unavailable
                DispatchQueue.main.async { completion(closedStatus) }
                self.finish()
            }
        }
        state.lock()
        defer { state.unlock() }
        if !running {
            running = true
            operation()
        } else if pending == nil {
            pending = operation
        } else {
            DispatchQueue.main.async { completion(.busyOrUnavailable) }
        }
    }

    private func finish() {
        state.lock()
        let next = pending
        pending = nil
        if next == nil { running = false }
        state.unlock()
        next?()
    }
}
