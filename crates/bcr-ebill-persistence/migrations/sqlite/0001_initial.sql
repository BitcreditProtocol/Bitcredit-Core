-- CONTACTS

CREATE TABLE contacts (
    node_id TEXT PRIMARY KEY NOT NULL,

    contact_type INTEGER NOT NULL
    CHECK (contact_type IN (0, 1, 2)),

    name TEXT NOT NULL,
    email TEXT,

    postal_address_country TEXT,
    postal_address_city TEXT,
    postal_address_zip TEXT,
    postal_address_address TEXT,

    date_of_birth_or_registration TEXT,
    country_of_birth_or_registration TEXT,
    city_of_birth_or_registration TEXT,
    identification_number TEXT,

    avatar_file_name TEXT,
    avatar_file_hash TEXT,
    avatar_file_nostr_hash TEXT,

    proof_document_file_name TEXT,
    proof_document_file_hash TEXT,
    proof_document_file_nostr_hash TEXT,

    nostr_relays TEXT NOT NULL DEFAULT '[]',
    mint_url TEXT,

    CHECK (
        (
            postal_address_country IS NULL
            AND postal_address_city IS NULL
            AND postal_address_zip IS NULL
            AND postal_address_address IS NULL
        )
        OR
        (
            postal_address_country IS NOT NULL
            AND postal_address_city IS NOT NULL
            AND postal_address_address IS NOT NULL
        )
    ),

    CHECK (
        (
            avatar_file_name IS NULL
            AND avatar_file_hash IS NULL
            AND avatar_file_nostr_hash IS NULL
        )
        OR
        (
            avatar_file_name IS NOT NULL
            AND avatar_file_hash IS NOT NULL
            AND avatar_file_nostr_hash IS NOT NULL
        )
    ),

    CHECK (
        (
            proof_document_file_name IS NULL
            AND proof_document_file_hash IS NULL
            AND proof_document_file_nostr_hash IS NULL
        )
        OR
        (
            proof_document_file_name IS NOT NULL
            AND proof_document_file_hash IS NOT NULL
            AND proof_document_file_nostr_hash IS NOT NULL
        )
    )
);

-- EMAIL NOTIFICATIONS

CREATE TABLE email_notifications (
    node_id TEXT PRIMARY KEY NOT NULL,
    email_preferences_link TEXT NOT NULL
);

-- MINT REQUESTS

CREATE TABLE mint_requests (
    mint_request_id TEXT PRIMARY KEY NOT NULL,
    requester_node_id TEXT NOT NULL,
    bill_id TEXT NOT NULL,
    mint_node_id TEXT NOT NULL,
    timestamp INTEGER NOT NULL
        CHECK (timestamp >= 0),
    status TEXT NOT NULL,
    status_timestamp INTEGER
    CHECK (
        status_timestamp IS NULL
        OR status_timestamp >= 0
    ),
    CHECK (
        (
            status IN (
                'denied',
                'rejected',
                'cancelled',
                'expired'
            )
            AND status_timestamp IS NOT NULL
        )
        OR
        (
            status IN (
                'pending',
                'offered',
                'accepted',
                'minting_enabled'
            )
            AND status_timestamp IS NULL
        )
    )
);

CREATE INDEX mint_requests_lookup_idx
ON mint_requests (
    requester_node_id,
    bill_id,
    mint_node_id
);

CREATE INDEX mint_requests_bill_id_idx
ON mint_requests (bill_id);

CREATE INDEX mint_requests_status_idx
ON mint_requests (status);

-- MINT OFFERS

CREATE TABLE mint_offers (
    mint_request_id TEXT PRIMARY KEY NOT NULL,
    keyset_id TEXT NOT NULL,
    expiration_timestamp INTEGER NOT NULL
    CHECK (expiration_timestamp >= 0),

    discounted_sum_amount INTEGER NOT NULL
    CHECK (discounted_sum_amount >= 0),
    discounted_sum_currency_code TEXT NOT NULL,
    discounted_sum_currency_decimals INTEGER NOT NULL
    CHECK (
        discounted_sum_currency_decimals >= 0
        AND discounted_sum_currency_decimals <= 255
    ),
    discounted_sum_reference_exchange_rate TEXT NOT NULL,

    proofs TEXT,
    proofs_spent INTEGER NOT NULL DEFAULT 0
    CHECK (proofs_spent IN (0, 1)),

    recovery_data TEXT,

    FOREIGN KEY (mint_request_id)
        REFERENCES mint_requests(mint_request_id)
        ON DELETE CASCADE
);

