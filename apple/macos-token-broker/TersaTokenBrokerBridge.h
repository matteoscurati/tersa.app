// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef TERSA_TOKEN_BROKER_BRIDGE_H
#define TERSA_TOKEN_BROKER_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

// Narrow C ABI for the embedded token-broker composition. Status integers
// match TersaTokenBrokerStatusV1. No refresh token, PKCE material, or
// provider body ever crosses these entry points.

int32_t tersa_token_broker_begin_authorization(
    const uint8_t *redirect_uri,
    size_t redirect_uri_len,
    uint8_t *authorization_url_out,
    size_t authorization_url_capacity,
    size_t *authorization_url_len,
    uint8_t *session_handle_out,
    size_t session_handle_capacity,
    size_t *session_handle_len
);

int32_t tersa_token_broker_complete_authorization(
    const uint8_t *session_handle,
    size_t session_handle_len,
    const uint8_t *callback_url,
    size_t callback_url_len,
    uint8_t *access_token_out,
    size_t access_token_capacity,
    size_t *access_token_len,
    uint8_t *subject_out,
    size_t subject_capacity,
    size_t *subject_len,
    int64_t *expires_out
);

int32_t tersa_token_broker_refresh_access_token(
    const uint8_t *account_subject,
    size_t account_subject_len,
    uint8_t *access_token_out,
    size_t access_token_capacity,
    size_t *access_token_len,
    uint8_t *subject_out,
    size_t subject_capacity,
    size_t *subject_len,
    int64_t *expires_out
);

int32_t tersa_token_broker_revoke_provider_grant(
    const uint8_t *account_subject,
    size_t account_subject_len
);

int32_t tersa_token_broker_delete_stored_tokens(
    const uint8_t *account_subject,
    size_t account_subject_len
);

#endif
