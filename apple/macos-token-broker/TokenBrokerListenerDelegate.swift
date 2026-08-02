// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import Foundation

/// NSXPC listener delegate for the embedded token broker.
///
/// Connections are accepted only after a code-signing requirement is applied
/// with `setCodeSigningRequirement(_:)`. Process identifiers are never used
/// for authentication. The exported interface is exactly
/// `TersaMacTokenBrokerProtocolV1`.
final class TokenBrokerListenerDelegate: NSObject, NSXPCListenerDelegate {
    /// Designated requirement for the embedding TersaMac product.
    ///
    /// The requirement pins the peer to the reviewed main-app bundle identifier
    /// under an Apple generic anchor. Unsigned local builds fail closed until
    /// release signing is configured; team-specific leaf binding is a later
    /// provisioning step and is not claimed by this skeleton.
    static let embeddingAppCodeSigningRequirement =
        "identifier \"app.tersa.mac\" and anchor apple generic"

    func listener(
        _ listener: NSXPCListener,
        shouldAcceptNewConnection newConnection: NSXPCConnection
    ) -> Bool {
        _ = listener

        let exportedInterface = NSXPCInterface(with: TersaMacTokenBrokerProtocolV1.self)
        newConnection.exportedInterface = exportedInterface
        newConnection.exportedObject = TokenBrokerService()
        newConnection.setCodeSigningRequirement(Self.embeddingAppCodeSigningRequirement)
        newConnection.invalidationHandler = {
            // Fail closed: an invalidated peer simply drops. No fallback path.
        }
        newConnection.interruptionHandler = {
            // Fail closed: interruptions do not open an in-process token path.
        }
        newConnection.resume()
        return true
    }
}
