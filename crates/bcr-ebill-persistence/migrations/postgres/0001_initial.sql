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

CREATE TABLE email_notifications (
    node_id TEXT PRIMARY KEY NOT NULL,
    email_preferences_link TEXT NOT NULL
);
