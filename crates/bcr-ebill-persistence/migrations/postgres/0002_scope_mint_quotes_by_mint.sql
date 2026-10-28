-- Quote ids are only unique per Mint: scope requests and offers by (mint_node_id, mint_request_id).
-- Existing offers take the Mint of their request; ids, terms, proofs and recovery data are kept.

ALTER TABLE mint_offers ADD COLUMN mint_node_id TEXT;

UPDATE mint_offers o
SET mint_node_id = r.mint_node_id
FROM mint_requests r
WHERE r.mint_request_id = o.mint_request_id;

ALTER TABLE mint_offers ALTER COLUMN mint_node_id SET NOT NULL;

ALTER TABLE mint_offers DROP CONSTRAINT mint_offers_mint_request_id_fkey;
ALTER TABLE mint_offers DROP CONSTRAINT mint_offers_pkey;
ALTER TABLE mint_requests DROP CONSTRAINT mint_requests_pkey;

ALTER TABLE mint_requests ADD PRIMARY KEY (mint_node_id, mint_request_id);
ALTER TABLE mint_offers ADD PRIMARY KEY (mint_node_id, mint_request_id);
ALTER TABLE mint_offers
    ADD FOREIGN KEY (mint_node_id, mint_request_id)
        REFERENCES mint_requests(mint_node_id, mint_request_id)
        ON DELETE CASCADE;
