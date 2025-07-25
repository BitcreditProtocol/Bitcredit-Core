use bcr_ebill_core::{
    blockchain::BlockchainType,
    constants::BCR_NOSTR_CHAIN_PREFIX,
    util::{
        BcrKeys, base58_decode, base58_encode,
        crypto::{decrypt_ecies, encrypt_ecies},
    },
};

use bcr_ebill_api::service::notification_service::{Error, Result, event::EventEnvelope};

use log::{error, info};

use nostr::{
    Event,
    event::{EventBuilder, EventId, Kind, Tag, TagKind, TagStandard, UnsignedEvent},
    filter::{Alphabet, Filter, SingleLetterTag},
    key::PublicKey,
    nips::{nip10::Marker, nip59::UnwrappedGift, nip73::ExternalContentId},
    signer::NostrSigner,
    types::Timestamp,
};

// A bit abitrary. This is to protect our client from beeing overwhelmed by spam. The downside is
// that we will not be able to extract a chain even if there are valid blocks on the relay.
const CHAIN_EVENT_LIMIT: usize = 1000;

pub async fn unwrap_direct_message<T: NostrSigner>(
    event: Box<Event>,
    signer: &T,
) -> Option<(EventEnvelope, PublicKey, EventId, Timestamp)> {
    match event.kind {
        Kind::EncryptedDirectMessage => unwrap_nip04_envelope(event, signer).await,
        Kind::GiftWrap => unwrap_nip17_envelope(event, signer).await,
        _ => {
            error!(
                "Received event with kind {} but expected EncryptedDirectMessage or GiftWrap",
                event.kind
            );
            None
        }
    }
}

/// Unwrap envelope from private direct message
async fn unwrap_nip04_envelope<T: NostrSigner>(
    event: Box<Event>,
    signer: &T,
) -> Option<(EventEnvelope, PublicKey, EventId, Timestamp)> {
    let mut result: Option<(EventEnvelope, PublicKey, EventId, Timestamp)> = None;
    if event.kind == Kind::EncryptedDirectMessage {
        match signer.nip04_decrypt(&event.pubkey, &event.content).await {
            Ok(decrypted) => {
                result = extract_text_envelope(&decrypted)
                    .map(|e| (e, event.pubkey, event.id, event.created_at));
            }
            Err(e) => {
                error!("Decrypting event failed: {e}");
            }
        }
    } else {
        info!(
            "Received event with kind {} but expected EncryptedDirectMessage",
            event.kind
        );
    }
    result
}

/// Unwrap envelope from private direct message
async fn unwrap_nip17_envelope<T: NostrSigner>(
    event: Box<Event>,
    signer: &T,
) -> Option<(EventEnvelope, PublicKey, EventId, Timestamp)> {
    let mut result: Option<(EventEnvelope, PublicKey, EventId, Timestamp)> = None;
    if event.kind == Kind::GiftWrap {
        result = match UnwrappedGift::from_gift_wrap(signer, &event).await {
            Ok(UnwrappedGift { rumor, sender }) => {
                extract_event_envelope(rumor).map(|e| (e, sender, event.id, event.created_at))
            }
            Err(e) => {
                error!("Unwrapping gift wrap failed: {e}");
                None
            }
        }
    }
    result
}

/// Unwraps a Nostr chain event with its metadata. Will return the encrypted payload and
/// the metadata if the event matches a public chain event. Otherwise it returns None.
pub fn unwrap_public_chain_event(event: Box<Event>) -> Result<Option<EncryptedPublicEventData>> {
    let data: Vec<EncryptedPublicEventData> = event
        .tags
        .filter_standardized(TagKind::SingleLetter(SingleLetterTag::lowercase(
            Alphabet::I,
        )))
        .filter_map(|t| match t {
            TagStandard::ExternalContent {
                content:
                    ExternalContentId::BlockchainAddress {
                        address, chain_id, ..
                    },
                ..
            } => chain_id
                .as_ref()
                .and_then(|id| BlockchainType::try_from(id.as_ref()).ok())
                .map(|chain_type| EncryptedPublicEventData {
                    id: address.to_owned(),
                    chain_type,
                    payload: event.content.clone(),
                }),
            _ => None,
        })
        .collect();
    Ok(data.first().cloned())
}

pub fn chain_filter(id: &str, chain_type: BlockchainType) -> Filter {
    Filter::new()
        .kind(Kind::TextNote)
        .custom_tag(chain_tag(), tag_content(id, chain_type).to_string())
        .limit(CHAIN_EVENT_LIMIT)
}

pub fn chain_tag() -> SingleLetterTag {
    SingleLetterTag::lowercase(Alphabet::I)
}

pub fn tag_content(id: &str, blockchain: BlockchainType) -> ExternalContentId {
    ExternalContentId::BlockchainAddress {
        chain: BCR_NOSTR_CHAIN_PREFIX.to_string(),
        address: id.to_string(),
        chain_id: Some(blockchain.to_string()),
    }
}

pub fn bcr_nostr_tag(id: &str, blockchain: BlockchainType) -> Tag {
    TagStandard::ExternalContent {
        content: tag_content(id, blockchain),
        hint: None,
        uppercase: false,
    }
    .into()
}

pub fn root_and_reply_id(event: &Event) -> (Option<EventId>, Option<EventId>) {
    let mut root: Option<EventId> = None;
    let mut reply: Option<EventId> = None;
    event.tags.filter_standardized(TagKind::e()).for_each(|t| {
        if let TagStandard::Event {
            event_id, marker, ..
        } = t
        {
            match marker {
                Some(Marker::Root) => root = Some(event_id.to_owned()),
                Some(Marker::Reply) => reply = Some(event_id.to_owned()),
                _ => {}
            }
        }
    });
    (root, reply)
}

/// Given an encrypted payload and a private key, decrypts the payload and returns
/// its content as an EventEnvelope.
pub fn decrypt_public_chain_event(data: &str, keys: &BcrKeys) -> Result<EventEnvelope> {
    let decrypted = decrypt_ecies(&base58_decode(data)?, &keys.get_private_key())?;
    let payload = serde_json::from_slice::<EventEnvelope>(&decrypted)?;
    Ok(payload)
}

#[derive(Clone, Debug)]
pub struct EncryptedPublicEventData {
    pub id: String,
    pub chain_type: BlockchainType,
    pub payload: String,
}

/// Creates a NIP-04 encrypted event for sending as private message.
pub async fn create_nip04_event<T: NostrSigner>(
    signer: &T,
    public_key: &PublicKey,
    message: &str,
) -> Result<EventBuilder> {
    Ok(EventBuilder::new(
        Kind::EncryptedDirectMessage,
        signer
            .nip04_encrypt(public_key, message)
            .await
            .map_err(|e| {
                error!("Failed to encrypt direct private message: {e}");
                Error::Crypto("Failed to encrypt direct private message".to_string())
            })?,
    )
    .tag(Tag::public_key(*public_key)))
}

/// Takes an event envelope and creates a public chain event with appropriate tags and encrypted
/// base58 encoded payload.
pub fn create_public_chain_event(
    id: &str,
    event: EventEnvelope,
    block_time: u64,
    blockchain: BlockchainType,
    keys: BcrKeys,
    previous_event: Option<Event>,
    root_event: Option<Event>,
) -> Result<EventBuilder> {
    let payload = base58_encode(&encrypt_ecies(
        &serde_json::to_vec(&event)?,
        &keys.pub_key(),
    )?);
    let event = match previous_event {
        Some(evt) => EventBuilder::text_note_reply(payload, &evt, root_event.as_ref(), None)
            .tag(bcr_nostr_tag(id, blockchain)),
        None => EventBuilder::text_note(payload).tag(bcr_nostr_tag(id, blockchain)),
    };
    let event = event.custom_created_at(nostr::Timestamp::from(block_time));
    Ok(event)
}

fn extract_text_envelope(message: &str) -> Option<EventEnvelope> {
    match serde_json::from_str::<EventEnvelope>(message) {
        Ok(envelope) => Some(envelope),
        Err(e) => {
            error!("Json deserializing event envelope failed: {e}");
            None
        }
    }
}

fn extract_event_envelope(rumor: UnsignedEvent) -> Option<EventEnvelope> {
    if rumor.kind == Kind::PrivateDirectMessage {
        match serde_json::from_str::<EventEnvelope>(rumor.content.as_str()) {
            Ok(envelope) => Some(envelope),
            Err(e) => {
                error!("Json deserializing event envelope failed: {e}");
                None
            }
        }
    } else {
        None
    }
}
