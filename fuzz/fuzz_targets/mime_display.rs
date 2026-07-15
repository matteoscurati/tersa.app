// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Exercises deterministic MIME display parsing with bounded resource limits.

#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use tersa_mime_spike::{DisplayDocument, Limits, inspect_synthetic_mime};

const MAX_INPUT_BYTES: usize = 512 * 1024;
const LIMIT_PREFIX_BYTES: usize = 6;
const HTML_EXPANSION_FACTOR: usize = 8;
const HTML_FIXED_ALLOWANCE: usize = 1_024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let (message, limits) = input_and_limits(data);
    let first = inspect_synthetic_mime(message, limits);
    let second = inspect_synthetic_mime(message, limits);
    assert_equal_without_content(&first, &second);

    if let (Ok(first), Ok(second)) = (&first, &second) {
        assert_success_invariants(message, limits, first, second);
    }
});

fn input_and_limits(data: &[u8]) -> (&[u8], Limits) {
    if data.len() < LIMIT_PREFIX_BYTES {
        return (data, Limits::default());
    }

    let defaults = Limits::default();
    let prefix = &data[..LIMIT_PREFIX_BYTES];
    let select = |byte: u8, values: [usize; 4]| values[usize::from(byte % 4)];
    let limits = Limits {
        input_bytes: select(prefix[0], [0, 64, 4_096, defaults.input_bytes]),
        nesting: select(prefix[1], [0, 1, 4, defaults.nesting]),
        parts: select(prefix[2], [1, 4, 32, defaults.parts]),
        header_count: select(prefix[3], [1, 8, 32, defaults.header_count]),
        header_bytes: select(prefix[4], [32, 512, 4_096, defaults.header_bytes]),
        decoded_display_bytes: select(prefix[5], [0, 64, 4_096, defaults.decoded_display_bytes]),
    };
    (&data[LIMIT_PREFIX_BYTES..], limits)
}

fn assert_success_invariants(
    message: &[u8],
    limits: Limits,
    first: &DisplayDocument,
    second: &DisplayDocument,
) {
    assert_equal_without_content(&first.source(), &second.source());
    assert_equal_without_content(first.html().as_str(), second.html().as_str());
    assert_equal_without_content(
        &first.html().diagnostic_hash(),
        &second.html().diagnostic_hash(),
    );
    assert_equal_without_content(first.cid_placeholders(), second.cid_placeholders());

    let html_len = first.html().as_str().len();
    let input_bound = message
        .len()
        .saturating_mul(HTML_EXPANSION_FACTOR)
        .saturating_add(HTML_FIXED_ALLOWANCE);
    let decoded_bound = limits
        .decoded_display_bytes
        .saturating_mul(HTML_EXPANSION_FACTOR)
        .saturating_add(HTML_FIXED_ALLOWANCE);
    assert!(html_len <= input_bound);
    assert!(html_len <= decoded_bound);

    let placeholders = first.cid_placeholders();
    for placeholder in placeholders {
        let identifier = placeholder.identifier();
        assert!(!identifier.is_empty());
        assert!(identifier.len() <= 255);
    }
    assert!(
        placeholders
            .windows(2)
            .all(|pair| pair[0].identifier() < pair[1].identifier())
    );
}

fn assert_equal_without_content<T: PartialEq + ?Sized>(left: &T, right: &T) {
    // `assert_eq!` would render parser-derived values into fuzz logs.
    assert!(left == right);
}

// Rust guideline compliant 1.0.
