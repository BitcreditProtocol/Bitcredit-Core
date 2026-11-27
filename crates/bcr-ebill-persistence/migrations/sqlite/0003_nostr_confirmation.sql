CREATE TABLE nostr_incoming_chain_events (
    -- metadata snapshot of incoming chain events
    event_id TEXT PRIMARY KEY NOT NULL,
    chain_type TEXT NOT NULL CHECK (chain_type IN ('bill', 'company', 'identity')),
    chain_id TEXT NOT NULL,
    payload BLOB NOT NULL,
    relay_urls_json TEXT NOT NULL,
    required_relays INTEGER NOT NULL CHECK (required_relays > 0),
    first_seen_at INTEGER NOT NULL CHECK (first_seen_at >= 0),
    -- verification of acceptance on relays
    next_try_at INTEGER NOT NULL CHECK (next_try_at >= 0),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'verified', 'applied', 'rejected')),
    last_error TEXT,
    verified_at INTEGER,
    confirmed_relays_json TEXT,
    -- application to local chain
    application_attempts INTEGER NOT NULL DEFAULT 0
        CHECK (application_attempts >= 0),
    application_next_try_at INTEGER
        CHECK (
            application_next_try_at IS NULL
            OR application_next_try_at >= 0
        ),
    application_wait_reason TEXT
        CHECK (
            application_wait_reason IS NULL
            OR application_wait_reason IN (
                'missing_keys',
                'missing_predecessor',
                'transient',
                'conflicting_fork'
            )
        ),
    application_last_error TEXT,
    -- table level constraints
        CHECK (status != 'verified' OR (verified_at IS NOT NULL AND confirmed_relays_json IS NOT NULL))
);

CREATE INDEX nostr_incoming_chain_events_due_idx
    ON nostr_incoming_chain_events(next_try_at, event_id)
    WHERE status = 'pending';

CREATE INDEX nostr_incoming_chain_events_chain_idx
    ON nostr_incoming_chain_events(chain_type, chain_id);

CREATE INDEX nostr_incoming_chain_events_verified_idx
    ON nostr_incoming_chain_events(verified_at, event_id)
    WHERE status = 'verified';

CREATE TABLE nostr_catchup_cursor (
    scope TEXT NOT NULL, -- dm, bill, company, identity
    subject_id TEXT NOT NULL,
    relay_url TEXT NOT NULL,
    until_seconds BIGINT NOT NULL CHECK (until_seconds >= 0),

    PRIMARY KEY (scope, subject_id, relay_url)
);

ALTER TABLE nostr_event_offset
    ADD COLUMN ignored BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE nostr_event_offset
    ADD COLUMN ignore_reason TEXT;
