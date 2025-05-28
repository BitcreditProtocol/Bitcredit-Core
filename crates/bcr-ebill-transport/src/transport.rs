use async_trait::async_trait;
use bcr_ebill_core::{
    ServiceTraitBounds, blockchain::BlockchainType, contact::BillParticipant, util::BcrKeys,
};

use log::{error, info};
#[cfg(test)]
use mockall::automock;

use nostr::{
    Event,
    event::{EventId, Kind, Tag, TagStandard, UnsignedEvent},
    key::PublicKey,
    nips::{nip01::Metadata, nip59::UnwrappedGift, nip73::ExternalContentId},
    signer::NostrSigner,
    types::{RelayUrl, Timestamp},
};

use crate::{Result, event::EventEnvelope};

#[cfg(test)]
impl ServiceTraitBounds for MockNotificationJsonTransportApi {}

#[cfg_attr(test, automock)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait NotificationJsonTransportApi: ServiceTraitBounds {
    /// Returns the senders public key for this instance.
    fn get_sender_key(&self) -> String;
    /// Sends a private json event to the given recipient.
    async fn send_private_event(
        &self,
        recipient: &BillParticipant,
        event: EventEnvelope,
    ) -> Result<()>;
    /// Sends a public json chain event to our Nostr relays. The id is the chain id
    /// eg. bill_id or company_id etc. The id will be published as a tag on the Nostr
    /// event. This will return the sent event so we can add it to the local store.
    async fn send_public_chain_event(
        &self,
        id: &str,
        blockchain: BlockchainType,
        keys: BcrKeys,
        event: EventEnvelope,
        previous_event: Option<Event>,
        root_event: Option<Event>,
    ) -> Result<Event>;
    /// Resolves a nostr contact by node id.
    async fn resolve_contact(&self, node_id: &str) -> Result<Option<NostrContactData>>;
}

#[derive(Debug, Clone)]
pub struct NostrContactData {
    pub metadata: Metadata,
    pub relays: Vec<RelayUrl>,
}

pub fn bcr_nostr_tag(id: &str, blockchain: BlockchainType) -> Tag {
    TagStandard::ExternalContent {
        content: ExternalContentId::BlockchainAddress {
            chain: "bitcredit".to_string(),
            address: id.to_string(),
            chain_id: Some(blockchain.to_string()),
        },
        hint: None,
        uppercase: false,
    }
    .into()
}

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
