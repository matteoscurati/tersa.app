// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import Foundation

/// Process-owned mutable UTF-8 buffer for the complete-authorization FFI path.
///
/// Uniquely references storage for the duration of `body`, then zeros the same
/// allocation on every exit path (`return` or `throw`). Production runs the
/// complete FFI call inside `body` with no second plaintext copy; tests invoke
/// this exact helper to prove the wipe. Immutable XPC `String` values are not
/// zeroizable — only this process-owned byte buffer is wiped.
enum TokenBrokerOwnedCallbackUTF8 {
    /// Invokes `body` with uniquely referenced mutable storage, zeros that
    /// allocation via `defer` after `body` returns or throws, then optionally
    /// lets the caller observe the wiped buffer (same base address when storage
    /// is stable).
    ///
    /// The FFI path must read via `UnsafePointer` of `buffer.baseAddress` so
    /// the wipe targets the allocation the call observed. Storage is already
    /// initialized `[UInt8]`, so the wipe uses the initialized-memory overwrite
    /// operation rather than re-initialization.
    @discardableResult
    static func withMutableBufferWipedAfter<R>(
        _ plaintext: [UInt8],
        body: (UnsafeMutableBufferPointer<UInt8>) throws -> R,
        afterWipe: ((UnsafeMutableBufferPointer<UInt8>) -> Void)? = nil
    ) rethrows -> R {
        var storage = plaintext
        return try storage.withUnsafeMutableBufferPointer { buffer in
            defer {
                // Initialized `[UInt8]` storage: overwrite in place so both
                // success and throw leave the same allocation zeroed.
                buffer.update(repeating: 0)
                afterWipe?(buffer)
            }
            return try body(buffer)
        }
    }
}
