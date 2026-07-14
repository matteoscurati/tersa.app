// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Runs the Apple-only Slint diagnostic interface.

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod apple {
    #[allow(
        clippy::cast_possible_wrap,
        clippy::clone_on_ref_ptr,
        clippy::multiple_inherent_impl,
        clippy::same_name_method,
        clippy::todo,
        clippy::unwrap_used,
        unsafe_code,
        missing_debug_implementations,
        trivial_numeric_casts,
        reason = "Slint 1.16.1 generates these constructs; handwritten adapter code remains warning-clean"
    )]
    mod generated {
        slint::include_modules!();
    }

    use generated::{InboxRow, TersaSlintSpike};
    use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

    const INBOX_ROWS: usize = 10_000;

    /// Starts the diagnostic interface with synthetic, non-production data.
    pub fn run() -> Result<(), slint::PlatformError> {
        let window = TersaSlintSpike::new()?;
        window.set_rows(ModelRc::new(VecModel::from(mock_rows())));
        let protocol_version =
            i32::try_from(tersa_presentation::presentation_protocol_version()).unwrap_or(i32::MAX);
        window.set_protocol_version(protocol_version);
        window.run()
    }

    fn mock_rows() -> Vec<InboxRow> {
        (0..INBOX_ROWS)
            .map(|index| InboxRow {
                sender: SharedString::from(format!("Research desk {:04}", index % 250)),
                subject: SharedString::from(format!("Diagnostic thread {:05}", index + 1)),
                preview: SharedString::from("Synthetic inbox row for virtual-scroll feasibility."),
                time: SharedString::from(format!("{:02}:{:02}", 8 + (index % 10), index % 60)),
                unread: index % 4 == 0,
            })
            .collect()
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn main() -> Result<(), slint::PlatformError> {
    apple::run()
}

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
fn main() {
    // The diagnostic executable is intentionally Apple-target-only.
    let _ = tersa_presentation::presentation_protocol_version();
}

// Rust guideline compliant 1.0.
