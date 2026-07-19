// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import Foundation

/// Serializes mailbox reads away from the AppKit main thread. The read
/// composition rejects main-thread calls, so every C ABI invocation happens
/// on the private utility queue below.
final class MailboxReadWorker: @unchecked Sendable {
    private static let initialOutputCapacity = 65_536

    private let queue = DispatchQueue(label: "app.tersa.macos.mailbox-read", qos: .utility)
    private let state = NSLock()
    private var running = false
    private var pending: (() -> Void)?

    /// Queues one inbox read. A second queued request is rejected immediately.
    func enqueueRead(
        accountIdentifier: Data,
        completion: @escaping @MainActor (MailboxReadOutcome) -> Void
    ) {
        enqueueOperation(accountIdentifier: accountIdentifier, threadIdentifier: nil, completion: completion)
    }

    /// Queues one thread read. A second queued request is rejected immediately.
    func enqueueRead(
        accountIdentifier: Data,
        threadIdentifier: Data,
        completion: @escaping @MainActor (MailboxReadOutcome) -> Void
    ) {
        enqueueOperation(
            accountIdentifier: accountIdentifier,
            threadIdentifier: threadIdentifier,
            completion: completion
        )
    }

    private func enqueueOperation(
        accountIdentifier: Data,
        threadIdentifier: Data?,
        completion: @escaping @MainActor (MailboxReadOutcome) -> Void
    ) {
        let operation = { [queue] in
            queue.async {
                let outcome = self.performRead(
                    accountIdentifier: accountIdentifier,
                    threadIdentifier: threadIdentifier
                )
                DispatchQueue.main.async { completion(outcome) }
                self.finishRead()
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
            DispatchQueue.main.async { completion(.failure(.unavailable)) }
        }
    }

    private func finishRead() {
        state.lock()
        let next = pending
        pending = nil
        if next == nil { running = false }
        state.unlock()
        next?()
    }

    /// Runs one bounded read on the worker queue. On `bufferTooSmall` the
    /// bridge reports the exact required size in `outputLength`; the buffer
    /// is reallocated once and the read retried exactly once. A second
    /// `bufferTooSmall` is treated as `unavailable`. Buffers may hold mail
    /// bytes and are zeroed before release.
    private func performRead(accountIdentifier: Data, threadIdentifier: Data?) -> MailboxReadOutcome {
        var output = [UInt8](repeating: 0, count: Self.initialOutputCapacity)
        defer {
            output.withUnsafeMutableBufferPointer { buffer in
                buffer.initialize(repeating: 0)
            }
        }
        var outputLength = 0
        var status = readOnce(
            accountIdentifier: accountIdentifier,
            threadIdentifier: threadIdentifier,
            output: &output,
            outputLength: &outputLength
        )
        if status == MailboxReadStatus.bufferTooSmall.rawValue {
            output.withUnsafeMutableBufferPointer { buffer in
                buffer.initialize(repeating: 0)
            }
            output = [UInt8](repeating: 0, count: outputLength)
            outputLength = 0
            status = readOnce(
                accountIdentifier: accountIdentifier,
                threadIdentifier: threadIdentifier,
                output: &output,
                outputLength: &outputLength
            )
            if status == MailboxReadStatus.bufferTooSmall.rawValue {
                status = MailboxReadStatus.unavailable.rawValue
            }
        }
        guard status == MailboxReadStatus.ok.rawValue else {
            return .failure(MailboxReadFailure.fromStatus(status))
        }
        let validLength = min(outputLength, output.count)
        // The transient payload copy is wiped after decoding. The decoded
        // on-screen fields (from/subject) necessarily reside in view state and
        // cannot be zeroed, so this is best-effort defense on the C-boundary copy.
        var payload = Data(output[0..<validLength])
        defer {
            if !payload.isEmpty {
                payload.resetBytes(in: 0..<payload.count)
            }
        }
        if threadIdentifier == nil {
            return MailboxDocumentDecoder.decodeInbox(payload)
        }
        return MailboxDocumentDecoder.decodeThread(payload)
    }

    /// Invokes the C ABI read symbol once. A `limit` of zero lets the Rust
    /// composition substitute its bounded default.
    private func readOnce(
        accountIdentifier: Data,
        threadIdentifier: Data?,
        output: inout [UInt8],
        outputLength: inout Int
    ) -> Int32 {
        accountIdentifier.withUnsafeBytes { accountBytes in
            output.withUnsafeMutableBufferPointer { buffer in
                if let threadIdentifier {
                    return threadIdentifier.withUnsafeBytes { threadBytes in
                        tersa_macos_mailbox_read_thread(
                            accountBytes.bindMemory(to: UInt8.self).baseAddress,
                            accountBytes.count,
                            threadBytes.bindMemory(to: UInt8.self).baseAddress,
                            threadBytes.count,
                            0,
                            buffer.baseAddress,
                            buffer.count,
                            &outputLength
                        )
                    }
                }
                return tersa_macos_mailbox_read_inbox(
                    accountBytes.bindMemory(to: UInt8.self).baseAddress,
                    accountBytes.count,
                    0,
                    buffer.baseAddress,
                    buffer.count,
                    &outputLength
                )
            }
        }
    }
}
