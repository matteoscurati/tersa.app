// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Emits privacy-preserving aggregate MIME diagnostic evidence.

#![forbid(unsafe_code)]

use std::env;
use std::path::Path;
use std::process::ExitCode;

use tersa_mime_spike::{Limits, inspect_synthetic_mime};

fn main() -> ExitCode {
    if let Ok(()) = run() {
        ExitCode::SUCCESS
    } else {
        eprintln!("MIME diagnostic failed.");
        ExitCode::FAILURE
    }
}

fn run() -> Result<(), ()> {
    if let Some(path) = export_path()? {
        export_sanitized_fixture(&path).map_err(|_error| ())?;
        return Ok(());
    }
    let nested = nested_multipart(20);
    let corpus = vec![
        (
            b"Content-Type: text/plain\r\n\r\nportable diagnostic".to_vec(),
            true,
        ),
        (
            b"Content-Type: text/html\r\n\r\n<p>portable diagnostic</p>".to_vec(),
            true,
        ),
        (
            b"Content-Type: text/html\r\n\r\n<script>blocked</script><img src=https://example.invalid/pixel><p>safe</p>".to_vec(),
            true,
        ),
        (
            b"Content-Type: multipart/alternative; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nplain\r\n--b\r\nContent-Type: text/html\r\n\r\n<p>html</p>\r\n--b--\r\n".to_vec(),
            true,
        ),
        (
            b"Content-Type: text/html\r\nContent-Disposition: attachment\r\n\r\n<p>excluded</p>".to_vec(),
            false,
        ),
        (
            b"Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n%%%".to_vec(),
            false,
        ),
        (
            b"Content-Type: text/plain; charset=iso-2022-jp\r\n\r\ntext".to_vec(),
            false,
        ),
        (
            b"Content-Type: multipart/mixed; boundary=missing\r\n\r\n--wrong--\r\n".to_vec(),
            false,
        ),
        (vec![b'x'; Limits::default().input_bytes + 1], false),
        (nested.into_bytes(), false),
    ];
    let mut accepted = 0_usize;
    let mut rejected = 0_usize;
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for (message, should_accept) in corpus {
        let first = inspect_synthetic_mime(&message, Limits::default());
        let second = inspect_synthetic_mime(&message, Limits::default());
        if first != second || first.is_ok() != should_accept {
            return Err(());
        }
        match first {
            Ok(document) => {
                accepted += 1;
                hash = hash.rotate_left(5) ^ document.html().diagnostic_hash();
            }
            Err(error) => {
                rejected += 1;
                hash = hash.rotate_left(5) ^ stable_hash(error.to_string().as_bytes());
            }
        }
    }
    println!("mime_spike.accepted={accepted}");
    println!("mime_spike.rejected={rejected}");
    println!("mime_spike.output_hash={hash:016x}");
    println!("NOT A DEVICE-GATE RESULT");
    Ok(())
}

fn nested_multipart(depth: usize) -> String {
    if depth == 0 {
        return "Content-Type: text/plain\r\n\r\nleaf".to_owned();
    }
    format!(
        "Content-Type: multipart/mixed; boundary=b{depth}\r\n\r\n--b{depth}\r\n{}\r\n--b{depth}--\r\n",
        nested_multipart(depth - 1)
    )
}

fn stable_hash(input: &[u8]) -> u64 {
    input.iter().fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

fn export_path() -> Result<Option<std::path::PathBuf>, ()> {
    let mut arguments = env::args_os().skip(1);
    let Some(command) = arguments.next() else {
        return Ok(None);
    };
    if command != "--export-sanitized-html" {
        return Err(());
    }
    let Some(path) = arguments.next() else {
        return Err(());
    };
    if arguments.next().is_some() {
        return Err(());
    }
    Ok(Some(path.into()))
}

fn export_sanitized_fixture(path: &Path) -> Result<(), &'static str> {
    let message = b"Content-Type: text/html; charset=utf-8\r\n\r\n<section><script>blocked</script><p>Sanitized MIME diagnostic content.</p><img src=https://example.invalid/pixel><a href=cid:fixture@example.invalid>inert</a></section>";
    let document = inspect_synthetic_mime(message, Limits::default()).map_err(|_error| "M01")?;
    std::fs::write(path, document.html().as_str()).map_err(|_error| "M02")
}

// Rust guideline compliant 1.0.
