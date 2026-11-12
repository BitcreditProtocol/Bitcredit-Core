-- subject id is e.g. bill id, identity id etc.
-- subject type is the event type, e.g. Bill, Company, Identity, Contact
CREATE TABLE nostr_propagations (
    id TEXT PRIMARY KEY NOT NULL,
    sequence BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE, -- monotonic sequence for ordering
    subject_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    created_at BIGINT NOT NULL
);

CREATE INDEX idx_nostr_propagations_subject_sequence
    ON nostr_propagations (
        subject_type,
        subject_id,
        sequence DESC
    );

-- prepared and signed Nostr events, ready to send
CREATE TABLE nostr_propagation_messages (
    id TEXT PRIMARY KEY NOT NULL,
    propagation_id TEXT NOT NULL
        REFERENCES nostr_propagations(id)
        ON DELETE CASCADE,
    -- EventType, e.g. BillChain, BillChainInvite etc.
    event_type TEXT NOT NULL,
    -- only for private events
    recipient_id TEXT,
    -- only for blockchain events
    chain_id TEXT,
    block_hash TEXT,
    -- signed Nostr event ID
    nostr_event_id TEXT NOT NULL,
    -- encrypted serialized nostr::Event
    payload BYTEA NOT NULL
);

CREATE INDEX nostr_propagation_messages_group_idx
    ON nostr_propagation_messages(propagation_id);

CREATE INDEX nostr_propagation_messages_block_idx
    ON nostr_propagation_messages(chain_id, block_hash);

-- relays track acceptance independently
CREATE TABLE nostr_propagation_relays (
    message_id TEXT NOT NULL
        REFERENCES nostr_propagation_messages(id)
        ON DELETE CASCADE,
    relay_url TEXT NOT NULL,
    -- NULL means not yet accepted
    accepted_at BIGINT,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_try_at BIGINT NOT NULL DEFAULT 0,
    last_error TEXT,
    PRIMARY KEY (message_id, relay_url),
    CHECK (attempts >= 0),
    CHECK (next_try_at >= 0),
    CHECK (accepted_at IS NULL OR accepted_at >= 0)
);

CREATE INDEX nostr_propagation_relays_pending_idx
    ON nostr_propagation_relays(next_try_at)
    WHERE accepted_at IS NULL;

-- remove old queue is no longer needed
DROP TABLE IF EXISTS nostr_send_queue;

