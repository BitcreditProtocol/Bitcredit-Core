-- Quote ids are only unique per Mint: scope requests and offers by (mint_node_id, mint_request_id).
-- Existing offers take the Mint of their request; ids, terms, proofs and recovery data are kept.

CREATE TABLE mint_requests_scoped (
    mint_request_id TEXT NOT NULL,
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
    ),
    PRIMARY KEY (mint_node_id, mint_request_id)
);

INSERT INTO mint_requests_scoped (
    mint_request_id,
    requester_node_id,
    bill_id,
    mint_node_id,
    timestamp,
    status,
    status_timestamp
)
SELECT
    mint_request_id,
    requester_node_id,
    bill_id,
    mint_node_id,
    timestamp,
    status,
    status_timestamp
FROM mint_requests;

CREATE TABLE mint_offers_scoped (
    mint_node_id TEXT NOT NULL,
    mint_request_id TEXT NOT NULL,
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

    proofs BLOB,
    proofs_spent INTEGER NOT NULL DEFAULT 0
    CHECK (proofs_spent IN (0, 1)),

    recovery_data BLOB,

    PRIMARY KEY (mint_node_id, mint_request_id),
    FOREIGN KEY (mint_node_id, mint_request_id)
        REFERENCES mint_requests_scoped(mint_node_id, mint_request_id)
        ON DELETE CASCADE
);

INSERT INTO mint_offers_scoped (
    mint_node_id,
    mint_request_id,
    keyset_id,
    expiration_timestamp,
    discounted_sum_amount,
    discounted_sum_currency_code,
    discounted_sum_currency_decimals,
    discounted_sum_reference_exchange_rate,
    proofs,
    proofs_spent,
    recovery_data
)
SELECT
    r.mint_node_id,
    o.mint_request_id,
    o.keyset_id,
    o.expiration_timestamp,
    o.discounted_sum_amount,
    o.discounted_sum_currency_code,
    o.discounted_sum_currency_decimals,
    o.discounted_sum_reference_exchange_rate,
    o.proofs,
    o.proofs_spent,
    o.recovery_data
FROM mint_offers o
JOIN mint_requests r ON r.mint_request_id = o.mint_request_id;

DROP TABLE mint_offers;
DROP TABLE mint_requests;

ALTER TABLE mint_requests_scoped RENAME TO mint_requests;
ALTER TABLE mint_offers_scoped RENAME TO mint_offers;

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
