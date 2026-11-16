use crate::{EncryptionContext, Error, Result, traits::propagation::IncomingChainCandidate};

pub(crate) const INSERT_CANDIDATE: &str = r#"
    INSERT INTO nostr_incoming_chain_events (
        event_id, chain_type, chain_id, payload,
        relay_urls_json, required_relays, first_seen_at, next_try_at
    )
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    ON CONFLICT(event_id) DO NOTHING
    "#;

pub(crate) const SELECT_DUE_CANDIDATES: &str = r#"
    SELECT event_id, chain_type, chain_id, payload,
           relay_urls_json, required_relays, attempts,
           application_attempts
    FROM nostr_incoming_chain_events
    WHERE status = 'pending' AND next_try_at <= $1
    ORDER BY next_try_at, event_id
    LIMIT $2
    "#;

pub(crate) const MARK_APPLIED: &str = r#"
    UPDATE nostr_incoming_chain_events
       SET status = 'applied', last_error = NULL
     WHERE event_id = $1 AND status = 'verified'
     "#;

pub(crate) const MARK_PENDING_RETRY: &str = r#"
    UPDATE nostr_incoming_chain_events
       SET attempts = attempts + 1,
           next_try_at = $2,
           last_error = $3
     WHERE event_id = $1 AND status = 'pending'
     "#;

pub(crate) const MARK_REJECTED: &str = r#"
    UPDATE nostr_incoming_chain_events
       SET status = 'rejected', last_error = $2
     WHERE event_id = $1 AND status IN ('pending', 'verified')
     "#;

pub(crate) const SELECT_VERIFIED_CANDIDATES: &str = r#"
    SELECT event_id, chain_type, chain_id, payload,
           relay_urls_json, required_relays,
           attempts, application_attempts
    FROM nostr_incoming_chain_events
    WHERE status = 'verified'
      AND application_next_try_at IS NOT NULL
      AND application_next_try_at <= $1
    ORDER BY application_next_try_at, event_id
    LIMIT $2
"#;

pub(crate) const MARK_VERIFIED: &str = r#"
    UPDATE nostr_incoming_chain_events
    SET status = 'verified',
        verified_at = $2,
        confirmed_relays_json = $3,
        application_next_try_at = $2,
        application_attempts = 0,
        application_wait_reason = NULL,
        application_last_error = NULL,
        last_error = NULL
    WHERE event_id = $1
      AND status = 'pending'
"#;

pub(crate) const MARK_APPLICATION_DEFERRED: &str = r#"
    UPDATE nostr_incoming_chain_events
    SET application_attempts = application_attempts + 1,
        application_next_try_at = $2,
        application_wait_reason = $3,
        application_last_error = $4
    WHERE event_id = $1
      AND status = 'verified'
"#;

pub(crate) const WAKE_APPLICATION_FOR_KEYS: &str = r#"
    UPDATE nostr_incoming_chain_events
    SET application_attempts = 0,
        application_next_try_at = 0,
        application_wait_reason = NULL,
        application_last_error = NULL
    WHERE status = 'verified'
      AND chain_type = $1
      AND chain_id = $2
      AND application_wait_reason = 'missing_keys'
"#;

pub(crate) const WAKE_APPLICATION_FOR_PREDECESSOR: &str = r#"
    UPDATE nostr_incoming_chain_events
    SET application_next_try_at = 0
    WHERE status = 'verified'
      AND chain_type = $1
      AND chain_id = $2
      AND application_wait_reason = 'missing_predecessor';
"#;

pub(crate) struct EncodedIncomingCandidate {
    pub event_id: String,
    pub chain_type: String,
    pub chain_id: String,
    pub payload: Vec<u8>,
    pub relay_urls_json: String,
    pub required_relays: i32,
}

impl EncodedIncomingCandidate {
    pub fn new(
        candidate: &IncomingChainCandidate,
        encryption_ctx: &EncryptionContext,
    ) -> Result<Self> {
        if !matches!(
            candidate.chain_type.as_str(),
            "bill" | "identity" | "company"
        ) {
            return Err(Error::InvalidData("invalid incoming chain type".into()));
        }
        if candidate.chain_id.is_empty() {
            return Err(Error::InvalidData("incoming chain ID is empty".into()));
        }
        if candidate
            .relays
            .iter()
            .any(|relay| !matches!(relay.scheme(), "ws" | "wss"))
        {
            return Err(Error::InvalidData(
                "invalid verification relay scheme".into(),
            ));
        }
        let mut relay_urls: Vec<String> =
            candidate.relays.iter().map(ToString::to_string).collect();
        relay_urls.sort();
        relay_urls.dedup();
        if candidate.required_relays == 0 || candidate.required_relays > relay_urls.len() {
            return Err(Error::InvalidData(
                "invalid incoming verification threshold".into(),
            ));
        }
        let required_relays = i32::try_from(candidate.required_relays).map_err(|_| {
            Error::InvalidData("too many required verification relays - overflow".into())
        })?;
        let payload = encryption_ctx.encrypt(&serde_json::to_vec(&candidate.event)?)?;
        let relay_urls_json = serde_json::to_string(&relay_urls)?;
        Ok(Self {
            event_id: candidate.event.id.to_string(),
            chain_type: candidate.chain_type.clone(),
            chain_id: candidate.chain_id.clone(),
            payload,
            relay_urls_json,
            required_relays,
        })
    }
}

#[derive(Debug, sqlx::FromRow)]
pub(crate) struct IncomingCandidateRow {
    pub event_id: String,
    pub chain_type: String,
    pub chain_id: String,
    pub payload: Vec<u8>,
    pub relay_urls_json: String,
    pub required_relays: i32,
    pub attempts: i32,
    pub application_attempts: i32,
}

impl IncomingCandidateRow {
    pub fn decrypt(self, crypto: &EncryptionContext) -> Result<IncomingChainCandidate> {
        let plaintext = crypto.decrypt(&self.payload)?;
        let event: nostr::event::Event = serde_json::from_slice(&plaintext)?;
        if event.id.to_string() != self.event_id {
            return Err(Error::InvalidData(
                "incoming Nostr event_id mismatch".into(),
            ));
        }
        let urls: Vec<String> = serde_json::from_str(&self.relay_urls_json)?;
        let relays = urls
            .into_iter()
            .map(|url| {
                url::Url::parse(&url)
                    .map_err(|e| Error::InvalidData(format!("invalid stored relay URL: {e}")))
            })
            .collect::<Result<Vec<_>>>()?;
        let required_relays = usize::try_from(self.required_relays)
            .map_err(|_| Error::InvalidData("negative required relay count".into()))?;
        if required_relays == 0 || required_relays > relays.len() {
            return Err(Error::InvalidData("corrupted relay quorum snapshot".into()));
        }
        let attempts = u32::try_from(self.attempts)
            .map_err(|_| Error::InvalidData("negative verification attempt count".into()))?;
        let application_attempts = u32::try_from(self.application_attempts).map_err(|_| {
            Error::InvalidData("negative verification application_attempt count".into())
        })?;
        Ok(IncomingChainCandidate {
            event,
            chain_type: self.chain_type,
            chain_id: self.chain_id,
            relays,
            required_relays,
            attempts,
            application_attempts,
        })
    }
}
