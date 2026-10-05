-- CONTACTS

CREATE TABLE contacts (
    node_id TEXT PRIMARY KEY NOT NULL,

    contact_type BIGINT NOT NULL
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
    timestamp BIGINT NOT NULL
    CHECK (timestamp >= 0),
    status TEXT NOT NULL,
    status_timestamp BIGINT
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
    expiration_timestamp BIGINT NOT NULL
    CHECK (expiration_timestamp >= 0),

    discounted_sum_amount BIGINT NOT NULL
    CHECK (discounted_sum_amount >= 0),
    discounted_sum_currency_code TEXT NOT NULL,
    discounted_sum_currency_decimals BIGINT NOT NULL
    CHECK (
        discounted_sum_currency_decimals >= 0
        AND discounted_sum_currency_decimals <= 255
    ),
    discounted_sum_reference_exchange_rate TEXT NOT NULL,

    proofs TEXT,
    proofs_spent BOOLEAN NOT NULL DEFAULT FALSE,

    recovery_data TEXT,
    FOREIGN KEY (mint_request_id)
        REFERENCES mint_requests(mint_request_id)
        ON DELETE CASCADE
);

-- Bill Chain

-- lock-table to uphold consistency guarantees for bill chains
CREATE TABLE bill_chain_locks (
    bill_id TEXT PRIMARY KEY NOT NULL
);

CREATE TABLE bill_chain (
    bill_id TEXT NOT NULL,
    block_id BIGINT NOT NULL
    CHECK (block_id >= 1),
    plaintext_hash TEXT NOT NULL,
    hash TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    signature TEXT NOT NULL,
    timestamp BIGINT NOT NULL
    CHECK (timestamp >= 0),
    public_key TEXT NOT NULL,
    data BYTEA NOT NULL,
    op_code TEXT NOT NULL,
    PRIMARY KEY (bill_id, block_id) -- only one block per chain height
);

-- Bill

CREATE TABLE bill_cache (
    bill_id TEXT PRIMARY KEY NOT NULL,
    identity_node_id TEXT NOT NULL,
    payload JSONB NOT NULL
    CHECK (json_valid(payload))
);

CREATE INDEX bill_cache_identity_node_id_idx
ON bill_cache(identity_node_id);

CREATE TABLE bill_keys (
    bill_id TEXT PRIMARY KEY NOT NULL,
    private_key TEXT NOT NULL
);

CREATE TABLE bill_paid (
    bill_id TEXT PRIMARY KEY NOT NULL,
    payment_state TEXT NOT NULL,
    block_time BIGINT
    CHECK (block_time IS NULL OR block_time >= 0),
    block_hash TEXT,
    confirmations BIGINT
    CHECK (confirmations IS NULL OR confirmations >= 0),
    tx_id TEXT,
    CHECK (
        (
            payment_state IN (
                'paid_confirmed',
                'paid_unconfirmed'
            )
            AND block_time IS NOT NULL
            AND block_hash IS NOT NULL
            AND confirmations IS NOT NULL
            AND tx_id IS NOT NULL
        )
        OR
        (
            payment_state = 'in_mempool'
            AND block_time IS NULL
            AND block_hash IS NULL
            AND confirmations IS NULL
            AND tx_id IS NOT NULL
        )
        OR
        (
            payment_state = 'not_found'
            AND block_time IS NULL
            AND block_hash IS NULL
            AND confirmations IS NULL
            AND tx_id IS NULL
        )
    )
);

CREATE TABLE offer_to_sell_bill_paid (
    bill_id TEXT NOT NULL,
    block_id BIGINT NOT NULL
    CHECK (block_id >= 1),
    payment_state TEXT NOT NULL,
    block_time BIGINT
    CHECK (block_time IS NULL OR block_time >= 0),
    block_hash TEXT,
    confirmations BIGINT
    CHECK (confirmations IS NULL OR confirmations >= 0),
    tx_id TEXT,
    PRIMARY KEY (bill_id, block_id),
    CHECK (
        (
            payment_state IN (
                'paid_confirmed',
                'paid_unconfirmed'
            )
            AND block_time IS NOT NULL
            AND block_hash IS NOT NULL
            AND confirmations IS NOT NULL
            AND tx_id IS NOT NULL
        )
        OR
        (
            payment_state = 'in_mempool'
            AND block_time IS NULL
            AND block_hash IS NULL
            AND confirmations IS NULL
            AND tx_id IS NOT NULL
        )
        OR
        (
            payment_state = 'not_found'
            AND block_time IS NULL
            AND block_hash IS NULL
            AND confirmations IS NULL
            AND tx_id IS NULL
        )
    )
);

CREATE TABLE recourse_bill_paid (
    bill_id TEXT NOT NULL,
    block_id BIGINT NOT NULL
    CHECK (block_id >= 1),
    payment_state TEXT NOT NULL,
    block_time BIGINT
    CHECK (block_time IS NULL OR block_time >= 0),
    block_hash TEXT,
    confirmations BIGINT
    CHECK (confirmations IS NULL OR confirmations >= 0),
    tx_id TEXT,
    PRIMARY KEY (bill_id, block_id),
    CHECK (
        (
            payment_state IN (
                'paid_confirmed',
                'paid_unconfirmed'
            )
            AND block_time IS NOT NULL
            AND block_hash IS NOT NULL
            AND confirmations IS NOT NULL
            AND tx_id IS NOT NULL
        )
        OR
        (
            payment_state = 'in_mempool'
            AND block_time IS NULL
            AND block_hash IS NULL
            AND confirmations IS NULL
            AND tx_id IS NOT NULL
        )
        OR
        (
            payment_state = 'not_found'
            AND block_time IS NULL
            AND block_hash IS NULL
            AND confirmations IS NULL
            AND tx_id IS NULL
        )
    )
);

-- Company Chain

CREATE TABLE company_chain_locks (
    company_id TEXT PRIMARY KEY NOT NULL
);

CREATE TABLE company_chain (
    company_id TEXT NOT NULL,
    block_id BIGINT NOT NULL
    CHECK (block_id >= 1),
    plaintext_hash TEXT NOT NULL,
    hash TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    signature TEXT NOT NULL,
    timestamp BIGINT NOT NULL
    CHECK (timestamp >= 0),
    public_key TEXT NOT NULL,
    signatory_node_id TEXT NOT NULL,
    data BYTEA NOT NULL,
    op_code TEXT NOT NULL,

    PRIMARY KEY (company_id, block_id)
);

-- Identity Chain

CREATE TABLE identity_chain_lock (
    id BIGINT PRIMARY KEY NOT NULL
    CHECK (id = 1)
);

INSERT INTO identity_chain_lock (id)
VALUES (1);

CREATE TABLE identity_chain (
    block_id BIGINT PRIMARY KEY NOT NULL
    CHECK (block_id >= 1),
    plaintext_hash TEXT NOT NULL,
    hash TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    signature TEXT NOT NULL,
    timestamp BIGINT NOT NULL
    CHECK (timestamp >= 0),
    public_key TEXT NOT NULL,
    data BYTEA NOT NULL,
    op_code TEXT NOT NULL
);

-- Identity

CREATE TABLE identity (
    id BIGINT PRIMARY KEY NOT NULL CHECK (id = 1),
    identity_type BIGINT NOT NULL
    CHECK (identity_type IN (0, 1)),
    node_id TEXT NOT NULL,
    name TEXT NOT NULL,
    email TEXT,

    postal_address_country TEXT,
    postal_address_city TEXT,
    postal_address_zip TEXT,
    postal_address_address TEXT,
    date_of_birth TEXT,
    country_of_birth TEXT,
    city_of_birth TEXT,
    identification_number TEXT,

    identity_document_file_name TEXT,
    identity_document_file_hash TEXT,
    identity_document_file_nostr_hash TEXT,

    profile_picture_file_name TEXT,
    profile_picture_file_hash TEXT,
    profile_picture_file_nostr_hash TEXT,
    nostr_relays TEXT NOT NULL DEFAULT '[]',

    CHECK (
        (
            identity_document_file_name IS NULL
            AND identity_document_file_hash IS NULL
            AND identity_document_file_nostr_hash IS NULL
        )
        OR
        (
            identity_document_file_name IS NOT NULL
            AND identity_document_file_hash IS NOT NULL
            AND identity_document_file_nostr_hash IS NOT NULL
        )
    ),

    CHECK (
        (
            profile_picture_file_name IS NULL
            AND profile_picture_file_hash IS NULL
            AND profile_picture_file_nostr_hash IS NULL
        )
        OR
        (
            profile_picture_file_name IS NOT NULL
            AND profile_picture_file_hash IS NOT NULL
            AND profile_picture_file_nostr_hash IS NOT NULL
        )
    )
);

CREATE TABLE identity_keys (
    id BIGINT PRIMARY KEY NOT NULL CHECK (id = 1),
    key TEXT NOT NULL,
    seed_phrase TEXT NOT NULL
);


CREATE TABLE identity_network (
    id BIGINT PRIMARY KEY NOT NULL CHECK (id = 1),
    network TEXT NOT NULL
);


CREATE TABLE active_identity (
    id BIGINT PRIMARY KEY NOT NULL CHECK (id = 1),
    personal TEXT NOT NULL,
    company TEXT
);


CREATE TABLE email_confirmation (
    witness TEXT PRIMARY KEY NOT NULL,
    signature TEXT NOT NULL,
    node_id TEXT NOT NULL,
    company_node_id TEXT,
    email TEXT NOT NULL,
    created_at BIGINT NOT NULL
    CHECK (created_at >= 0)
);

-- Company


CREATE TABLE company (
    id TEXT PRIMARY KEY NOT NULL,

    name TEXT NOT NULL,
    country_of_registration TEXT,
    city_of_registration TEXT,

    postal_address_country TEXT NOT NULL,
    postal_address_city TEXT NOT NULL,
    postal_address_zip TEXT,
    postal_address_address TEXT NOT NULL,

    email TEXT NOT NULL,
    registration_number TEXT,
    registration_date TEXT,

    proof_of_registration_file_name TEXT,
    proof_of_registration_file_hash TEXT,
    proof_of_registration_file_nostr_hash TEXT,

    logo_file_name TEXT,
    logo_file_hash TEXT,
    logo_file_nostr_hash TEXT,

    creation_time BIGINT NOT NULL
    CHECK (creation_time >= 0),
    status TEXT NOT NULL,

    CHECK (
        (
            proof_of_registration_file_name IS NULL
            AND proof_of_registration_file_hash IS NULL
            AND proof_of_registration_file_nostr_hash IS NULL
        )
        OR
        (
            proof_of_registration_file_name IS NOT NULL
            AND proof_of_registration_file_hash IS NOT NULL
            AND proof_of_registration_file_nostr_hash IS NOT NULL
        )
    ),

    CHECK (
        (
            logo_file_name IS NULL
            AND logo_file_hash IS NULL
            AND logo_file_nostr_hash IS NULL
        )
        OR
        (
            logo_file_name IS NOT NULL
            AND logo_file_hash IS NOT NULL
            AND logo_file_nostr_hash IS NOT NULL
        )
    )
);

CREATE TABLE company_signatory (
    company_id TEXT NOT NULL,
    position BIGINT NOT NULL
    CHECK (position >= 0),
    signatory_type TEXT NOT NULL,
    node_id TEXT NOT NULL,
    status TEXT NOT NULL,
    ts BIGINT
    CHECK (ts IS NULL OR ts >= 0),
    inviter TEXT,
    remover TEXT,
    data_node_id TEXT,
    data_company_node_id TEXT,
    data_email TEXT,
    data_created_at BIGINT
    CHECK (
        data_created_at IS NULL
        OR data_created_at >= 0
    ),
    proof_signature TEXT,
    proof_witness TEXT,
    PRIMARY KEY (company_id, node_id),
    UNIQUE (company_id, position),
    FOREIGN KEY (company_id)
        REFERENCES company(id)
        ON DELETE CASCADE,
    CHECK (
        (
            proof_signature IS NULL
            AND proof_witness IS NULL
        )
        OR
        (
            proof_signature IS NOT NULL
            AND proof_witness IS NOT NULL
        )
    ),

    CHECK (
        (
            data_node_id IS NULL
            AND data_company_node_id IS NULL
            AND data_email IS NULL
            AND data_created_at IS NULL
        )
        OR
        (
            data_node_id IS NOT NULL
            AND data_email IS NOT NULL
            AND data_created_at IS NOT NULL
        )
    )
);

CREATE TABLE company_keys (
    id TEXT PRIMARY KEY NOT NULL,
    private_key TEXT NOT NULL
);

CREATE TABLE company_email_confirmation (
    company_id TEXT NOT NULL,
    signature TEXT NOT NULL,
    witness TEXT NOT NULL,
    node_id TEXT NOT NULL,
    company_node_id TEXT,
    email TEXT NOT NULL,
    created_at BIGINT NOT NULL
    CHECK (created_at >= 0),
    PRIMARY KEY (company_id, witness)
);

CREATE TABLE company_local_signatory_override (
    company_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    status TEXT NOT NULL,
    PRIMARY KEY (company_id, node_id)
);

