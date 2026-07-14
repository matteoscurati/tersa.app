// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef TERSA_RUST_BRIDGE_H
#define TERSA_RUST_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

uint32_t tersa_apple_bridge_version(void);
int32_t tersa_oauth_ios_begin(
    const uint8_t *client_id,
    size_t client_id_len,
    const uint8_t *redirect_scheme,
    size_t redirect_scheme_len,
    uint64_t *output_session_id,
    uint8_t *output_url,
    size_t output_url_capacity,
    size_t *output_url_len
);
int32_t tersa_oauth_ios_finish(
    uint64_t session_id,
    const uint8_t *callback_url,
    size_t callback_url_len
);
int32_t tersa_oauth_cancel(uint64_t session_id);

#endif
