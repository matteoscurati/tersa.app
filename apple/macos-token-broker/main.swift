// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import Foundation

// Operational entry point for the embedded macOS token-broker XPC service.
// The process exports only TersaMacTokenBrokerProtocolV1 through the reviewed
// listener delegate and binds the dedicated Rust broker composition. OAuth
// code exchange, refresh, persistence, revoke, and local delete run only here.

// Exact opt-in Keychain isolation probe: read-only, no listener, exits before
// any normal broker behavior. Without this single argument the broker launches
// exactly as before.
if KeychainIsolationProbe.isProbeRequest(CommandLine.arguments) {
    KeychainIsolationProbe.runAsPrincipal(.tokenBroker)
}

let tokenBrokerListenerDelegate = TokenBrokerListenerDelegate()
let tokenBrokerListener = NSXPCListener.service()
tokenBrokerListener.delegate = tokenBrokerListenerDelegate
tokenBrokerListener.resume()
RunLoop.current.run()
