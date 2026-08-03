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
// Mailbox sync FFI (adapters/mailbox-sync-ffi-macos). The macOS app links only
// that crate's archive, which also re-exports the bridge symbols above.
// Begins a broker-driven sync. The access token and subject both come from
// the same token broker reply and are scoped to this sync cycle; the caller
// must wipe/discard its own buffers after this call returns. The output
// session id is written only when the return value is STATUS_STARTED.
int32_t tersa_mailbox_macos_broker_sync_begin(
    const uint8_t *account_id,
    size_t account_id_len,
    const uint8_t *access_token,
    size_t access_token_len,
    const uint8_t *subject,
    size_t subject_len,
    uint64_t *output_session_id
);
// Broker-driven disconnect, two-phase. prepare follows the durable outer
// disconnect intent and writes the SQLCipher pre-marker/fence for the account.
int32_t tersa_mailbox_macos_broker_disconnect_prepare(
    const uint8_t *account_id,
    size_t account_id_len
);
// finalize is allowed only after broker token deletion; revoke_unconfirmed
// accepts only 0/1 as the revoke disposition, and output_session_id is
// published only when the return value is STATUS_STARTED.
int32_t tersa_mailbox_macos_broker_disconnect_finalize(
    const uint8_t *account_id,
    size_t account_id_len,
    int32_t revoke_unconfirmed,
    uint64_t *output_session_id
);
// Broker subject routing value, two-phase access. The subject is an
// account-identifying broker routing value stored only in the encrypted
// mailbox DB; it is not an OAuth credential. store persists the value for
// the account.
int32_t tersa_mailbox_macos_broker_subject_store(
    const uint8_t *account_id,
    size_t account_id_len,
    const uint8_t *subject,
    size_t subject_len
);
// get publishes output_subject bytes and output_subject_len only on status
// 0, and returns -6 when no subject is stored for the account. The caller
// must wipe or discard its output buffer after use.
int32_t tersa_mailbox_macos_broker_subject_get(
    const uint8_t *account_id,
    size_t account_id_len,
    uint8_t *output_subject,
    size_t output_subject_capacity,
    size_t *output_subject_len
);
int32_t tersa_mailbox_macos_lifecycle_get(
    const uint8_t *account_id,
    size_t account_id_len,
    int32_t *output_recovery,
    int64_t *output_last_successful_sync_unix_millis
);
int32_t tersa_mailbox_macos_sync_poll(uint64_t session_id);

#endif
