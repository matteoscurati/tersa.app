// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! C-compatible bootstrap surface for the Apple application targets.

#![deny(unsafe_code)]

mod oauth;

#[cfg(target_os = "macos")]
use std::slice;

/// Confirms that the Apple application linked the Rust static library.
#[expect(
    unsafe_code,
    reason = "a stable unmangled symbol is required by the C-compatible Apple bridge"
)]
#[unsafe(no_mangle)]
pub extern "C" fn tersa_apple_bridge_version() -> u32 {
    tersa_presentation::presentation_protocol_version()
}

/// Runs the product-only bootstrap after copying at most 256 opaque bytes.
///
/// # Safety
///
/// A non-null `account_id` must point to `account_id_len` readable bytes for
/// the duration of this call.
#[cfg(target_os = "macos")]
#[expect(
    unsafe_code,
    reason = "the narrow C ABI validates and immediately copies caller-owned account bytes"
)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tersa_macos_bootstrap_default_account(
    account_id: *const u8,
    account_id_len: usize,
) -> i32 {
    if account_id.is_null() || account_id_len == 0 || account_id_len > 256 {
        return tersa_keychain_macos::ProductBootstrapStatus::InvalidAccountIdentifier as i32;
    }
    // SAFETY: The C ABI contract requires the checked range to be readable.
    let bytes = unsafe { slice::from_raw_parts(account_id, account_id_len) }.to_vec();
    tersa_keychain_macos::bootstrap_default_account_bytes(&bytes) as i32
}

#[doc(inline)]
pub use oauth::{tersa_oauth_cancel, tersa_oauth_ios_begin, tersa_oauth_ios_finish};

#[cfg(target_os = "macos")]
#[doc(inline)]
pub use oauth::{
    tersa_oauth_macos_begin, tersa_oauth_macos_entitlement_probe, tersa_oauth_macos_poll,
};

#[cfg(test)]
#[expect(
    unsafe_code,
    reason = "the public C ABI is unsafe to call and these tests exercise its checked boundary"
)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    #[test]
    fn bootstrap_ffi_rejects_invalid_boundary_inputs_without_capability_access() {
        let invalid = tersa_keychain_macos::ProductBootstrapStatus::InvalidAccountIdentifier as i32;
        let one = [b'a'];
        // SAFETY: the non-null pointer is valid, and zero length is rejected before dereference.
        let zero = unsafe { tersa_macos_bootstrap_default_account(one.as_ptr(), 0) };
        assert_eq!(zero, invalid);
        // SAFETY: null inputs are rejected before any pointer dereference.
        let null = unsafe { tersa_macos_bootstrap_default_account(std::ptr::null(), 1) };
        assert_eq!(null, invalid);
        let bytes = [b'a'; 257];
        // SAFETY: `bytes` has the stated readable length; the ABI rejects its size.
        let oversized =
            unsafe { tersa_macos_bootstrap_default_account(bytes.as_ptr(), bytes.len()) };
        assert_eq!(oversized, invalid);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn bootstrap_ffi_background_thread_preserves_boundary_status_mapping() {
        let status = std::thread::spawn(|| {
            let invalid = b"invalid account";
            // SAFETY: `invalid` has the stated readable length and is copied by the ABI.
            unsafe { tersa_macos_bootstrap_default_account(invalid.as_ptr(), invalid.len()) }
        })
        .join()
        .expect("background boundary call must not panic");
        assert_eq!(
            status,
            tersa_keychain_macos::ProductBootstrapStatus::InvalidAccountIdentifier as i32
        );
    }
}

// Rust guideline compliant 1.0.
