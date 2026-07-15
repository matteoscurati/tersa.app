-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

CREATE TABLE pending_operations (
    id INTEGER PRIMARY KEY,
    message_id INTEGER REFERENCES messages(id),
    operation BLOB NOT NULL
);
