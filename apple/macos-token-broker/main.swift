// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import Foundation

// Fail-closed entry point for the embedded macOS token-broker XPC service.
// The process exports only TersaMacTokenBrokerProtocolV1 through the reviewed
// listener delegate. It does not perform OAuth, Keychain, network, or Rust FFI
// work; those remain outside this skeleton.
let tokenBrokerListenerDelegate = TokenBrokerListenerDelegate()
let tokenBrokerListener = NSXPCListener.service()
tokenBrokerListener.delegate = tokenBrokerListenerDelegate
tokenBrokerListener.resume()
RunLoop.current.run()
