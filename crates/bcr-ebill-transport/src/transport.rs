use bcr_ebill_core::protocol::{
    Timestamp,
    blockchain::BlockchainType,
    constants::BCR_NOSTR_CHAIN_PREFIX,
    crypto::{BcrKeys, decrypt_ecies},
    event::EventEnvelope,
};

use bcr_ebill_api::service::transport_service::{Error, Result};

use bitcoin::base58;
use log::error;

use nostr::{
    event::{Event, EventBuilder, EventId, IntoEventBuilder, Kind, Tag, UnsignedEvent},
    filter::{Filter, SingleLetterTag},
    key::{Keys, PublicKey},
    nips::{
        nip10::{Marker, Nip10Tag, TextNoteReplyBuilder},
        nip59::UnwrappedGift,
        nip73::{ExternalContentId, Nip73Tag},
    },
};

// A bit abitrary. This is to protect our client from beeing overwhelmed by spam. The downside is
// that we will not be able to extract a chain even if there are valid blocks on the relay.
const CHAIN_EVENT_LIMIT: usize = 10000;

pub async fn unwrap_direct_message(
    event: &Event,
    signer: &Keys,
) -> Option<(EventEnvelope, PublicKey, EventId, nostr::types::Timestamp)> {
    match event.kind {
        Kind::GiftWrap => unwrap_nip17_envelope(event, signer).await,
        _ => {
            error!(
                "Received event with kind {} but expected GiftWrap",
                event.kind
            );
            None
        }
    }
}

/// Unwrap envelope from private direct message
async fn unwrap_nip17_envelope(
    event: &Event,
    signer: &Keys,
) -> Option<(EventEnvelope, PublicKey, EventId, nostr::types::Timestamp)> {
    let mut result: Option<(EventEnvelope, PublicKey, EventId, nostr::types::Timestamp)> = None;
    if event.kind == Kind::GiftWrap {
        result = match UnwrappedGift::from_gift_wrap_async(signer, event).await {
            Ok(UnwrappedGift { rumor, sender }) => {
                extract_event_envelope(rumor).map(|e| (e, sender, event.id, event.created_at))
            }
            Err(_) => None,
        }
    }
    result
}

/// Unwraps a Nostr chain event with its metadata. Will return the encrypted, or encoded payload and
/// the metadata if the event matches a public chain event. Otherwise it returns None.
pub fn unwrap_public_chain_event(
    event: &Event,
) -> Result<Option<EncryptedOrEncodedPublicEventData>> {
    let data: Vec<EncryptedOrEncodedPublicEventData> = event
        .tags
        .iter()
        .filter_map(|tag| Nip73Tag::try_from(tag).ok())
        .filter_map(|tag| match tag {
            Nip73Tag::ExternalContent {
                content:
                    ExternalContentId::BlockchainAddress {
                        address, chain_id, ..
                    },
                ..
            } => chain_id
                .as_ref()
                .and_then(|id| BlockchainType::try_from(id.as_ref()).ok())
                .map(|chain_type| EncryptedOrEncodedPublicEventData {
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
    SingleLetterTag::LOWERCASE_I
}

pub fn tag_content(id: &str, blockchain: BlockchainType) -> ExternalContentId {
    ExternalContentId::BlockchainAddress {
        chain: BCR_NOSTR_CHAIN_PREFIX.to_string(),
        address: id.to_string(),
        chain_id: Some(blockchain.to_string()),
    }
}

pub fn bcr_nostr_tag(id: &str, blockchain: BlockchainType) -> Tag {
    Nip73Tag::ExternalContent {
        content: tag_content(id, blockchain),
        hint: None,
    }
    .into()
}

pub fn root_and_reply_id(event: &Event) -> (Option<EventId>, Option<EventId>) {
    let mut root: Option<EventId> = None;
    let mut reply: Option<EventId> = None;
    for tag in event.tags.iter().filter(|tag| tag.kind() == "e") {
        if let Ok(Nip10Tag::Event { id, marker, .. }) = Nip10Tag::try_from(tag) {
            match marker {
                Some(Marker::Root) => root = Some(id.to_owned()),
                Some(Marker::Reply) => reply = Some(id.to_owned()),
                _ => {}
            }
        }
    }
    (root, reply)
}

/// Given an encoded payload, decodes the payload and returns its content as an EventEnvelope.
fn decode_public_chain_event(data: &str) -> Result<EventEnvelope> {
    let decoded = base58::decode(data)?;
    let payload = borsh::from_slice::<EventEnvelope>(&decoded)?;
    Ok(payload)
}

/// Given an encrypted payload and a private key, decrypts the payload and returns
/// its content as an EventEnvelope.
/// => For the deprecated chains, where metadata is encrypted (PR #938)
fn decrypt_and_decode_public_chain_event(data: &str, keys: &BcrKeys) -> Result<EventEnvelope> {
    let decrypted = decrypt_ecies(&base58::decode(data)?, &keys.get_private_key())?;
    let payload = borsh::from_slice::<EventEnvelope>(&decrypted)?;
    Ok(payload)
}

/// Attempts to decrypt and then decode the payload (old, deprecated payload)
/// If it's not encrypted, just decodes the payload
/// If no key is supplied, it also only decodes
pub fn decrypt_or_decode_public_chain_event(
    data: &str,
    keys: &Option<BcrKeys>,
) -> Result<EventEnvelope> {
    match keys {
        Some(keys) => match decrypt_and_decode_public_chain_event(data, keys) {
            Ok(decrypted) => Ok(decrypted),
            Err(decrypt_err) => match decode_public_chain_event(data) {
                Ok(decoded) => Ok(decoded),
                Err(decode_err) => Err(Error::Blockchain(format!(
                    "Could not decrypt or decode public chain event. Decrypt error: {decrypt_err}; decode error: {decode_err}"
                ))),
            },
        },
        // no keys - just decode - this is the code path to check the nostr chain based on the unencrypted metadata
        None => decode_public_chain_event(data),
    }
}

#[derive(Clone, Debug)]
pub struct EncryptedOrEncodedPublicEventData {
    pub id: String,
    pub chain_type: BlockchainType,
    pub payload: String,
}

/// Takes an event envelope and creates a public chain event with appropriate tags and base58
/// encoded payload.
pub fn create_public_chain_event(
    id: &str,
    event: EventEnvelope,
    block_time: Timestamp,
    blockchain: BlockchainType,
    previous_event: Option<Event>,
    root_event: Option<Event>,
) -> Result<EventBuilder> {
    let payload = base58::encode(&borsh::to_vec(&event)?);
    let event = match previous_event {
        Some(evt) => {
            let mut builder = TextNoteReplyBuilder::new(payload, &evt);

            if let Some(root) = root_event.as_ref() {
                builder = builder.root(root);
            }

            builder
                .into_event_builder()
                .tag(bcr_nostr_tag(id, blockchain))
        }
        None => EventBuilder::new(nostr::event::Kind::TextNote, payload)
            .tag(bcr_nostr_tag(id, blockchain)),
    };
    let event = event.custom_created_at(block_time.into());
    Ok(event)
}

fn extract_event_envelope(rumor: UnsignedEvent) -> Option<EventEnvelope> {
    if rumor.kind == Kind::PrivateDirectMessage
        && let Ok(data) = base58::decode(rumor.content.as_str())
        && let Ok(envelope) = borsh::from_slice::<EventEnvelope>(&data)
    {
        Some(envelope)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bcr_ebill_core::protocol::{crypto::encrypt_ecies, event::EventType};
    use borsh::{BorshDeserialize, BorshSerialize};

    #[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
    struct TestPayload {
        id: u64,
        message: String,
    }

    fn test_payload() -> TestPayload {
        TestPayload {
            id: 42,
            message: "hello public chain".to_string(),
        }
    }

    fn test_envelope() -> EventEnvelope {
        let payload = test_payload();

        EventEnvelope {
            event_type: EventType::Bill,
            version: "1.0".to_string(),
            data: borsh::to_vec(&payload).unwrap(),
        }
    }

    fn encode_envelope_base58(envelope: &EventEnvelope) -> String {
        let encoded = borsh::to_vec(envelope).unwrap();
        base58::encode(&encoded)
    }

    fn assert_envelope_eq(actual: &EventEnvelope, expected: &EventEnvelope) {
        assert_eq!(actual.event_type, expected.event_type);
        assert_eq!(actual.version, expected.version);
        assert_eq!(actual.data, expected.data);
        let actual_payload = TestPayload::try_from_slice(&actual.data).unwrap();
        let expected_payload = TestPayload::try_from_slice(&expected.data).unwrap();
        assert_eq!(actual_payload, expected_payload);
    }

    #[test]
    fn decode_public_chain_event_decodes_base58_borsh_envelope() {
        let envelope = test_envelope();
        let encoded = encode_envelope_base58(&envelope);
        let decoded = decode_public_chain_event(&encoded).unwrap();
        assert_envelope_eq(&decoded, &envelope);
    }

    #[test]
    fn decode_public_chain_event_returns_error_for_invalid_base58() {
        let result = decode_public_chain_event("invvalid base58");
        assert!(result.is_err());
    }

    #[test]
    fn decode_public_chain_event_returns_error_for_non_envelope_payload() {
        let encoded = base58::encode(b"valid base58 data but not a borsh envelope");
        let result = decode_public_chain_event(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_or_decode_public_chain_event_decodes_plain_payload_when_no_keys_are_supplied() {
        let envelope = test_envelope();
        let encoded = encode_envelope_base58(&envelope);
        let decoded = decrypt_or_decode_public_chain_event(&encoded, &None).unwrap();
        assert_envelope_eq(&decoded, &envelope);
    }

    #[test]
    fn decrypt_or_decode_public_chain_event_falls_back_to_decode_when_decryption_fails() {
        let envelope = test_envelope();
        let encoded = encode_envelope_base58(&envelope);
        let keys = BcrKeys::new();
        let decoded = decrypt_or_decode_public_chain_event(&encoded, &Some(keys)).unwrap();
        assert_envelope_eq(&decoded, &envelope);
    }

    #[test]
    fn decrypt_or_decode_public_chain_event_returns_combined_error_when_decrypt_and_decode_fail() {
        let invalid_payload = base58::encode(b"invalid payload");
        let keys = BcrKeys::new();
        let result = decrypt_or_decode_public_chain_event(&invalid_payload, &Some(keys));
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("Could not decrypt or decode public chain event"),
            "unexpected error: {err}"
        );
        assert!(
            err.contains("Decrypt error:"),
            "expected decrypt error in: {err}"
        );
        assert!(
            err.contains("decode error:"),
            "expected decode error in: {err}"
        );
    }

    #[test]
    fn decrypt_and_decode_public_chain_event_decodes_encrypted_payload() {
        let envelope = test_envelope();
        let serialized = borsh::to_vec(&envelope).unwrap();
        let keys = BcrKeys::new();
        let encrypted = encrypt_ecies(&serialized, &keys.pub_key()).unwrap();
        let encoded = base58::encode(&encrypted);
        let decoded = decrypt_and_decode_public_chain_event(&encoded, &keys).unwrap();
        assert_envelope_eq(&decoded, &envelope);
    }
}

#[cfg(test)]
mod mint_record_size_tests {
    use bcr_common::core::NodeId;
    use bcr_ebill_core::protocol::{
        BlockId, SchnorrSignature, Sha256Hash, Timestamp,
        blockchain::{Block, company::CompanyBlock, identity::IdentityBlock},
        crypto::BcrKeys,
        mint_record::*,
    };
    use bitcoin::{
        Network,
        secp256k1::{Keypair, Message, SECP256K1, Scalar, SecretKey},
    };
    use serde_json::{Value, json};
    fn keys(n: u8) -> BcrKeys {
        let mut b = [0u8; 32];
        b[31] = n;
        BcrKeys::from_private_key(&SecretKey::from_slice(&b).unwrap())
    }
    fn node(k: &BcrKeys) -> NodeId {
        NodeId::new(k.pub_key(), Network::Regtest)
    }
    fn ts(n: u64) -> Timestamp {
        Timestamp::new(1793361600 + n).unwrap()
    }
    fn sign(hash: [u8; 32], key: &SecretKey) -> bitcoin::secp256k1::schnorr::Signature {
        SECP256K1.sign_schnorr_with_aux_rand(
            &Message::from_digest(hash),
            &Keypair::from_secret_key(SECP256K1, key),
            &[0; 32],
        )
    }
    fn signed_entry(value: Value, issuer: u8) -> MintRecordBlockData {
        let entry = serde_json::to_vec(&value).unwrap();
        let signature = sign(
            domain_hash(ENTRY_DOMAIN, &entry),
            &keys(issuer).get_private_key(),
        )
        .serialize();
        MintRecordBlockData { entry, signature }
    }
    fn entry(
        person: &NodeId,
        company: Option<&NodeId>,
        _issuer: u8,
        _sequence: u64,
        _previous: Option<String>,
    ) -> MintRecordBlockData {
        signed_entry(
            json!({"schema":"mint-record-entry-v1","network":"regtest","issuer":{"signingKey":keys(5).pub_key().x_only_public_key().0.to_string(),"mintNodeId":node(&keys(5)),"name":"Synthetic Mint"},"subject":{"chain":if company.is_some(){"company"}else{"identity"},"nodeId":person,"companyNodeId":company},"sequence":1,"previousEntryDigest":null,"createdAt":"2026-10-30T12:00:00Z","reason":"applicant_request","record":{},"omissions":[]}),
            5,
        )
    }
    fn encrypt(plaintext: &[u8], key: &BcrKeys, _id: BlockId) -> Vec<u8> {
        bcr_ebill_core::protocol::crypto::encrypt_ecies(plaintext, &key.pub_key()).unwrap()
    }
    fn stable_company(
        block: &mut CompanyBlock,
        plaintext: &[u8],
        personal: &BcrKeys,
        key: &BcrKeys,
    ) {
        block.data = borsh::to_vec(&(encrypt(plaintext, key, block.id), None::<String>)).unwrap();
        block.hash = CompanyBlock::calculate_hash(block.get_block_data_to_hash()).unwrap();
        let aggregate = personal
            .get_private_key()
            .add_tweak(&Scalar::from(key.get_private_key()))
            .unwrap();
        block.signature = SchnorrSignature::from(sign(block.hash.decode_to_array(), &aggregate));
    }
    #[test]
    fn mint_record_max_entry_fits_single_block_nostr_events() {
        use bcr_ebill_core::protocol::{blockchain::BlockchainType, event::IdentityChainEvent};
        use nostr::event::{EventBuilder, FinalizeEvent};
        let key = keys(3);
        let subject = node(&key);
        let mut value: Value =
            serde_json::from_slice(&entry(&subject, None, 5, 1, None).entry).unwrap();
        value["record"]["padding"] = json!("");
        let overhead = serde_json::to_vec(&value).unwrap().len();
        value["record"]["padding"] = json!("x".repeat(MAX_MINT_RECORD_ENTRY_BYTES - overhead));
        let data = signed_entry(value, 5);
        assert_eq!(data.entry.len(), MAX_MINT_RECORD_ENTRY_BYTES);
        let block = IdentityBlock {
            id: BlockId::first().add(1),
            plaintext_hash: Sha256Hash::from_bytes(&borsh::to_vec(&data).unwrap()),
            hash: Sha256Hash::from_bytes(b"sizing"),
            timestamp: ts(1),
            data: encrypt(
                &borsh::to_vec(&data).unwrap(),
                &key,
                BlockId::first().add(1),
            ),
            public_key: key.pub_key(),
            previous_hash: Sha256Hash::from_bytes(key.get_public_key().as_bytes()),
            signature: SchnorrSignature::from(sign([0; 32], &key.get_private_key())),
            op_code: bcr_ebill_core::protocol::blockchain::identity::IdentityOpCode::MintRecord,
        };
        let envelope = IdentityChainEvent::new(&subject, &block, &key)
            .generate_blockchain_message()
            .unwrap()
            .try_into()
            .unwrap();
        let root = EventBuilder::new(nostr::event::Kind::TextNote, "synthetic-root")
            .finalize(&key.get_nostr_keys())
            .unwrap();
        let event = super::create_public_chain_event(
            &subject.to_string(),
            envelope,
            ts(1),
            BlockchainType::Identity,
            Some(root.clone()),
            Some(root.clone()),
        )
        .unwrap()
        .finalize(&key.get_nostr_keys())
        .unwrap();
        assert!(
            serde_json::to_vec(&event).unwrap().len() < 65536,
            "identity event bytes: {}",
            serde_json::to_vec(&event).unwrap().len()
        );
        let company_key = keys(7);
        let company = node(&company_key);
        let mut value: Value =
            serde_json::from_slice(&entry(&subject, Some(&company), 5, 1, None).entry).unwrap();
        value["record"]["padding"] = json!("");
        let overhead = serde_json::to_vec(&value).unwrap().len();
        value["record"]["padding"] = json!("x".repeat(MAX_MINT_RECORD_ENTRY_BYTES - overhead));
        let data = signed_entry(value, 5);
        assert_eq!(data.entry.len(), MAX_MINT_RECORD_ENTRY_BYTES);
        let mut block = CompanyBlock {
            company_id: company.clone(),
            id: BlockId::first().add(2),
            plaintext_hash: Sha256Hash::from_bytes(&borsh::to_vec(&data).unwrap()),
            hash: Sha256Hash::from_bytes(b"sizing"),
            timestamp: ts(2),
            data: vec![],
            public_key: key.pub_key().combine(&company_key.pub_key()).unwrap(),
            signatory_node_id: subject,
            previous_hash: Sha256Hash::from_bytes(b"sizing-parent"),
            signature: SchnorrSignature::from(sign([0; 32], &key.get_private_key())),
            op_code: bcr_ebill_core::protocol::blockchain::company::CompanyOpCode::MintRecord,
        };
        stable_company(
            &mut block,
            &borsh::to_vec(&data).unwrap(),
            &key,
            &company_key,
        );
        let envelope = bcr_ebill_core::protocol::event::Event::new_company_chain(
            bcr_ebill_core::protocol::event::CompanyBlockEvent {
                node_id: company.clone(),
                block_height: 3,
                block,
            },
        )
        .try_into()
        .unwrap();
        let event = super::create_public_chain_event(
            &company.to_string(),
            envelope,
            ts(2),
            BlockchainType::Company,
            Some(root.clone()),
            Some(root),
        )
        .unwrap()
        .finalize(&company_key.get_nostr_keys())
        .unwrap();
        assert!(
            serde_json::to_vec(&event).unwrap().len() < 65536,
            "company event bytes: {}",
            serde_json::to_vec(&event).unwrap().len()
        );
    }
}
