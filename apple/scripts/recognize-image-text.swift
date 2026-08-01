// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import AppKit
import Vision

guard CommandLine.arguments.count == 2 else {
  fatalError("Usage: recognize-image-text IMAGE_PATH")
}

let path = CommandLine.arguments[1]
guard let image = NSImage(contentsOfFile: path) else {
  fatalError("Cannot load screenshot at \(path)")
}
var proposedRect = NSRect(origin: .zero, size: image.size)
guard
  let cgImage = image.cgImage(
    forProposedRect: &proposedRect,
    context: nil,
    hints: nil
  )
else {
  fatalError("Cannot create a CGImage for \(path)")
}

let request = VNRecognizeTextRequest()
request.recognitionLevel = .accurate
request.usesLanguageCorrection = false
try VNImageRequestHandler(cgImage: cgImage).perform([request])
for observation in request.results ?? [] {
  if let candidate = observation.topCandidates(1).first {
    print(candidate.string)
  }
}
