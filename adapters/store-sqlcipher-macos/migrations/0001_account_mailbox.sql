CREATE TABLE account_binding (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    account_id TEXT NOT NULL
);

CREATE TABLE messages (
    message_id TEXT PRIMARY KEY,
    thread_id TEXT NOT NULL,
    sender TEXT NOT NULL,
    subject TEXT NOT NULL,
    preview TEXT NOT NULL,
    received_at INTEGER NOT NULL,
    unread INTEGER NOT NULL CHECK (unread IN (0, 1)),
    content BLOB NULL
);

CREATE INDEX messages_list_order
    ON messages (received_at DESC, message_id ASC);
CREATE INDEX messages_thread_order
    ON messages (thread_id ASC, received_at ASC, message_id ASC);

CREATE TABLE account_identity (
    account_id TEXT PRIMARY KEY,
    identity_hash BLOB NOT NULL,
    algo_version INTEGER NOT NULL
);

-- Single bounded, content-free lifecycle row. The account database is already
-- bound to one opaque account identifier by account_binding, so this row never
-- stores an OAuth subject, provider identifier, token, or mailbox content.
CREATE TABLE account_lifecycle (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    disconnect_recovery INTEGER NULL CHECK (disconnect_recovery IN (1, 2)),
    last_successful_sync_unix_millis INTEGER NULL CHECK (last_successful_sync_unix_millis >= 0)
);
