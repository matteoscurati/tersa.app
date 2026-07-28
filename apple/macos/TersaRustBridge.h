// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef TERSA_RUST_BRIDGE_H
#define TERSA_RUST_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

uint32_t tersa_apple_bridge_version(void);
int32_t tersa_macos_bootstrap_default_account(const uint8_t *account_id, size_t account_id_len);
int32_t tersa_macos_mailbox_read_inbox(
    const uint8_t *account_id,
    size_t account_id_len,
    uint16_t limit,
    uint8_t *output,
    size_t output_capacity,
    size_t *output_len
);
int32_t tersa_macos_mailbox_read_thread(
    const uint8_t *account_id,
    size_t account_id_len,
    const uint8_t *thread_id,
    size_t thread_id_len,
    uint16_t limit,
    uint8_t *output,
    size_t output_capacity,
    size_t *output_len
);
int32_t tersa_macos_mailbox_search(
    const uint8_t *account_id,
    size_t account_id_len,
    const uint8_t *query,
    size_t query_len,
    uint16_t limit,
    uint8_t *output,
    size_t output_capacity,
    size_t *output_len
);
int32_t tersa_oauth_macos_begin(
    const uint8_t *client_id,
    size_t client_id_len,
    uint64_t *output_session_id,
    uint8_t *output_url,
    size_t output_url_capacity,
    size_t *output_url_len
);
int32_t tersa_oauth_macos_poll(uint64_t session_id);
// Invariant (see `tersa_oauth_cancel` in oauth.rs): session_id is a lookup
// key, NOT a capability; callers must only pass an id from their own begin.
int32_t tersa_oauth_cancel(uint64_t session_id);

// Mailbox sync FFI (adapters/mailbox-sync-ffi-macos). The macOS app links only
// that crate's archive, which also re-exports the bridge symbols above.
int32_t tersa_mailbox_macos_sync_begin(
    const uint8_t *client_id,
    size_t client_id_len,
    const uint8_t *account_id,
    size_t account_id_len,
    uint64_t *output_session_id
);
int32_t tersa_mailbox_macos_connect_begin(
    const uint8_t *account_id,
    size_t account_id_len,
    uint64_t oauth_session_id,
    uint64_t *output_session_id
);
int32_t tersa_mailbox_macos_disconnect_begin(
    const uint8_t *account_id,
    size_t account_id_len,
    uint64_t *output_session_id
);
int32_t tersa_mailbox_macos_sync_poll(uint64_t session_id);

#endif
