// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import CoreGraphics
import Foundation

guard CommandLine.arguments.count == 2,
      let processIdentifier = Int32(CommandLine.arguments[1]) else {
    fatalError("Expected one process identifier")
}

let options: CGWindowListOption = [.optionOnScreenOnly, .excludeDesktopElements]
let windows = CGWindowListCopyWindowInfo(options, kCGNullWindowID) as? [[CFString: Any]] ?? []
for window in windows {
    let owner = (window[kCGWindowOwnerPID] as? NSNumber)?.int32Value
    let layer = (window[kCGWindowLayer] as? NSNumber)?.intValue
    let number = (window[kCGWindowNumber] as? NSNumber)?.intValue
    if owner == processIdentifier && layer == 0, let number {
        print(number)
        break
    }
}
