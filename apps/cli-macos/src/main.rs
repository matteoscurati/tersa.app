// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

use std::process::ExitCode;

fn main() -> ExitCode {
    ExitCode::from(tersa_cli_macos::run(
        std::env::args_os().skip(1),
        &mut std::io::stdout(),
        &mut std::io::stderr(),
    ))
}
