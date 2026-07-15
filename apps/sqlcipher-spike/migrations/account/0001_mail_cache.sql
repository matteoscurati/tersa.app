-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

CREATE TABLE threads (
    id INTEGER PRIMARY KEY
);

CREATE TABLE messages (
    id INTEGER PRIMARY KEY,
    thread_id INTEGER REFERENCES threads(id)
);

CREATE TABLE labels (
    id INTEGER PRIMARY KEY
);

CREATE TABLE message_labels (
    message_id INTEGER REFERENCES messages(id),
    label_id INTEGER REFERENCES labels(id),
    PRIMARY KEY (message_id, label_id)
);
