use bcr_common::core::BillId;
use bcr_common::core::NodeId;
use bitcoin::base58;
use borsh_derive::{BorshDeserialize, BorshSerialize};
use chain::BillBlockPlaintextWrapper;
use serde::{Deserialize, Serialize};

pub mod block;
pub mod chain;
pub mod participant;
pub mod validation;

pub use block::BillBlock;
pub use block::ContactType;
use block::{BillIdentParticipantBlockData, BillRecourseReasonBlockData};
pub use chain::BillBlockchain;
use uuid::Uuid;

use crate::protocol::City;
use crate::protocol::Country;
use crate::protocol::Currency;
use crate::protocol::Date;
use crate::protocol::File;
use crate::protocol::PostalAddress;
use crate::protocol::blockchain::Block;
use crate::protocol::blockchain::bill::participant::BillIdentParticipant;
use crate::protocol::blockchain::bill::participant::BillParticipant;
use crate::protocol::blockchain::bill::participant::PastEndorsee;
use crate::protocol::blockchain::bill::participant::SignedBy;
use crate::protocol::{
    BitcoinAddress, BlockId, PublicKey, SchnorrSignature, SecretKey, Sha256Hash, Sum, Timestamp,
    blockchain::{Result, bill::block::BillParticipantBlockData},
    crypto::{self, BcrKeys},
};

#[derive(
    BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash,
)]
pub enum BillOpCode {
    Issue,
    Accept,
    Endorse,
    RequestToAccept,
    RequestToPay,
    OfferToSell,
    Sell,
    Mint,
    RejectToAccept,
    RejectToPay,
    RejectToBuy,
    RejectToPayRecourse,
    RequestRecourse,
    Recourse,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OfferToSellWaitingForPayment {
    Yes(Box<SellPaymentInfo>),
    No,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecourseWaitingForPayment {
    Yes(Box<RecoursePaymentInfo>),
    No,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SellPaymentInfo {
    pub buyer: BillParticipant,  // buyer can be anone
    pub seller: BillParticipant, // seller can be anone
    pub sum: Sum,
    pub payment_address: BitcoinAddress,
    pub block_id: BlockId,
    pub buying_deadline_timestamp: Timestamp,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoursePaymentInfo {
    pub recourser: BillParticipantBlockData, // recourser can be anon
    pub recoursee: BillIdentParticipantBlockData, // recoursee has to be identified
    pub sum: Sum,
    pub reason: BillRecourseReasonBlockData,
    pub block_id: BlockId,
    pub recourse_deadline_timestamp: Timestamp,
}

#[derive(Debug, Clone)]
pub enum PastPaymentStatus {
    Paid(Timestamp),     // timestamp
    Rejected(Timestamp), // timestamp
    Expired(Timestamp),  // timestamp
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone)]
pub struct BillToShareWithExternalParty {
    /// The bill id
    pub bill_id: BillId,
    /// The base58 encoded, encrypted BillBlockPlaintextWrapper of the bill
    pub data: String,
    #[borsh(
        serialize_with = "crate::protocol::serialization::serialize_vec_url",
        deserialize_with = "crate::protocol::serialization::deserialize_vec_url"
    )]
    /// The file urls of bill files, encrypted with the receiver's key, uploaded to Nostr
    pub file_urls: Vec<url::Url>,
    /// The hash over the unencrypted data
    pub hash: Sha256Hash,
    /// The signature over the hash by the sharer of the bill
    pub signature: SchnorrSignature,
    #[borsh(
        serialize_with = "crate::protocol::serialization::serialize_pubkey",
        deserialize_with = "crate::protocol::serialization::deserialize_pubkey"
    )]
    /// The receiver's pub key
    pub receiver: PublicKey,
}

impl BillToShareWithExternalParty {
    pub fn get_unencrypted_data(
        &self,
        private_key: &SecretKey,
    ) -> Result<Vec<BillBlockPlaintextWrapper>> {
        let decoded = base58::decode(&self.data)?;
        let decrypted = crypto::decrypt_ecies(&decoded, private_key)?;
        let deserialized: Vec<BillBlockPlaintextWrapper> = borsh::from_slice(&decrypted)?;
        Ok(deserialized)
    }
}

/// Creates a payload of a bill, including the encrypted and plaintext block data, encrypted
/// with the pub key of an external party, and signed by the sharer of the data, so the receiver
/// can fully validate the bill
pub fn create_bill_to_share_with_external_party(
    bill_id: &BillId,
    chain: &BillBlockchain,
    bill_keys: &BcrKeys,
    external_party_pub_key: &PublicKey,
    sharer_keys: &BcrKeys,
    file_urls: &[url::Url],
) -> Result<BillToShareWithExternalParty> {
    let chain_with_plaintext = chain.get_chain_with_plaintext_block_data(bill_keys)?;
    let serialized = borsh::to_vec(&chain_with_plaintext)?;
    let encrypted = crypto::encrypt_ecies(&serialized, external_party_pub_key)?;
    let encoded = base58::encode(&encrypted);

    let hash = Sha256Hash::from_bytes(&serialized);
    let signature = SchnorrSignature::sign(&hash, &sharer_keys.get_private_key())?;

    let result = BillToShareWithExternalParty {
        bill_id: bill_id.to_owned(),
        data: encoded,
        file_urls: file_urls.to_owned(),
        hash,
        signature,
        receiver: external_party_pub_key.to_owned(),
    };
    Ok(result)
}

/// Concrete incoming bill Actions with their data
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BillAction {
    // deadline_ts
    RequestAcceptance(Timestamp),
    Accept,
    // currency, deadline_ts
    RequestToPay(Currency, Timestamp),
    // buyer, sum, deadline_ts
    OfferToSell(BillParticipant, Sum, Timestamp),
    // buyer, sum, currency, payment_address
    Sell(BillParticipant, Sum, BitcoinAddress),
    // endorsee
    Endorse(BillParticipant),
    // recoursee, recourse reason, deadline_ts
    RequestRecourse(BillIdentParticipant, RecourseReason, Timestamp),
    // recoursee, sum, currency reason/
    Recourse(BillIdentParticipant, Sum, RecourseReason),
    // mint, sum, currency
    Mint(BillParticipant, Sum),
    RejectAcceptance,
    RejectPayment,
    RejectBuying,
    RejectPaymentForRecourse,
}

impl BillAction {
    pub fn op_code(&self) -> BillOpCode {
        match self {
            BillAction::RequestAcceptance(_) => BillOpCode::RequestToAccept,
            BillAction::Accept => BillOpCode::Accept,
            BillAction::RequestToPay(_, _) => BillOpCode::RequestToPay,
            BillAction::OfferToSell(_, _, _) => BillOpCode::OfferToSell,
            BillAction::Sell(_, _, _) => BillOpCode::Sell,
            BillAction::Endorse(_) => BillOpCode::Endorse,
            BillAction::RequestRecourse(_, _, _) => BillOpCode::RequestRecourse,
            BillAction::Recourse(_, _, _) => BillOpCode::Recourse,
            BillAction::Mint(_, _) => BillOpCode::Mint,
            BillAction::RejectAcceptance => BillOpCode::RejectToAccept,
            BillAction::RejectPayment => BillOpCode::RejectToPay,
            BillAction::RejectBuying => BillOpCode::RejectToBuy,
            BillAction::RejectPaymentForRecourse => BillOpCode::RejectToPayRecourse,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecourseReason {
    Accept,
    Pay(Sum), // sum
}

#[derive(Debug, Clone)]
pub struct BillIssueData {
    pub t: u64,
    pub country_of_issuing: Country,
    pub city_of_issuing: City,
    pub issue_date: Date,
    pub maturity_date: Date,
    pub drawee: NodeId,
    pub payee: NodeId,
    pub sum: Sum,
    pub country_of_payment: Country,
    pub city_of_payment: City,
    pub file_upload_ids: Vec<Uuid>,
    pub drawer_public_data: BillParticipant,
    pub drawer_keys: BcrKeys,
    pub timestamp: Timestamp,
    pub blank_issue: bool,
}

#[derive(Debug, Clone)]
pub struct BillValidateActionData {
    pub blockchain: BillBlockchain,
    pub drawee_node_id: NodeId,
    pub payee_node_id: NodeId,
    pub endorsee_node_id: Option<NodeId>,
    pub maturity_date: Date,
    pub bill_keys: BcrKeys,
    pub timestamp: Timestamp,
    pub signer_node_id: NodeId,
    pub is_paid: bool,
    pub mode: BillValidationActionMode,
}

#[allow(clippy::large_enum_variant)] // not relevant, since this isn't stored/copied around much
#[derive(Debug, Clone)]
pub enum BillValidationActionMode {
    /// Deep validation both does the shallow validation, but also adds validation based on the data
    /// provided with the given bill action
    Deep(BillAction),
    /// Shallow validation only checks whether the given bill action can be executed given the bill state
    /// It is called with pre-computed values for checks, since the goal is to be able to call it efficiently
    /// for multiple bill actions
    Shallow(BillShallowValidationData),
}

#[derive(Debug, Clone)]
pub struct BillShallowValidationData {
    pub bill_action: BillOpCode,
    pub is_waiting_for_req_to_pay: bool, // waiting state - not calculated from maturity date
    pub waiting_for_recourse_payment: RecourseWaitingForPayment,
    pub waiting_for_offer_to_sell: OfferToSellWaitingForPayment,
    pub is_req_to_pay_expired: bool, // expiration state - calculated from maturity date
    pub is_req_to_accept_expired: bool,
    pub past_endorsees: Vec<PastEndorsee>,
    // has to be set if bill_action is RequestRecourse
    pub recourse_reason: Option<RecourseReason>,
}

#[derive(Debug, Clone)]
pub struct BillHistory {
    pub blocks: Vec<BillHistoryBlock>,
}

#[derive(Clone, Debug)]
pub struct BillHistoryBlock {
    pub block_id: BlockId,
    pub block_type: BillOpCode,
    pub pay_to_the_order_of: Option<BillParticipant>,
    pub request_deadline: Option<Timestamp>,
    pub signed: SignedBy,
    pub signing_timestamp: Timestamp,
    pub signing_address: Option<PostalAddress>,
}

impl BillHistoryBlock {
    pub fn new(
        block: &BillBlock,
        pay_to_the_order_of: Option<BillParticipant>,
        request_deadline: Option<Timestamp>,
        signed: SignedBy,
        signing_address: Option<PostalAddress>,
    ) -> Self {
        Self {
            block_id: block.id(),
            block_type: block.op_code().to_owned(),
            pay_to_the_order_of,
            request_deadline,
            signed,
            signing_timestamp: block.timestamp(),
            signing_address,
        }
    }
}

/// Compact type to pass around basic bill data
#[derive(Debug, Clone)]
pub struct BitcreditBill {
    pub id: BillId,
    pub country_of_issuing: Country,
    pub city_of_issuing: City,
    // The party obliged to pay a Bill
    pub drawee: BillIdentParticipant,
    // The party issuing a Bill
    pub drawer: BillIdentParticipant,
    pub payee: BillParticipant,
    // The person to whom the Payee or an Endorsee endorses a bill
    pub endorsee: Option<BillParticipant>,
    pub sum: Sum,
    pub maturity_date: Date,
    pub issue_date: Date,
    pub country_of_payment: Country,
    pub city_of_payment: City,
    pub files: Vec<File>,
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::protocol::blockchain::bill::{
        BillBlock, BillBlockchain, BillOpCode,
        block::{BillAcceptBlockData, BillIssueBlockData},
        chain::BillBlockPlaintextWrapper,
    };
    use crate::{
        protocol::Sha256Hash,
        protocol::blockchain::Blockchain,
        protocol::crypto::BcrKeys,
        protocol::tests::tests::{
            bill_identified_participant_only_node_id, empty_bitcredit_bill, node_id_test,
            private_key_test, valid_address,
        },
    };

    pub fn get_baseline_identity() -> (NodeId, BcrKeys) {
        (
            node_id_test(),
            BcrKeys::from_private_key(&private_key_test()),
        )
    }

    #[test]
    fn start_blockchain_for_new_bill_baseline() {
        let bill = empty_bitcredit_bill();
        let identity = get_baseline_identity();

        let result = BillBlockchain::new(
            &BillIssueBlockData::from(bill, None, Timestamp::new(1731593928).unwrap()),
            identity.1,
            None,
            BcrKeys::from_private_key(&private_key_test()),
            Timestamp::new(1731593928).unwrap(),
        );

        assert!(result.is_ok());
        assert_eq!(result.as_ref().unwrap().blocks().len(), 1);
    }

    #[test]
    fn test_share_bill_with_external_party() {
        let external_party_keys = BcrKeys::new();
        let external_party_pub_key = external_party_keys.pub_key();
        let sharer_keys = BcrKeys::new();

        let identity = get_baseline_identity();
        let mut bill = empty_bitcredit_bill();
        let bill_id = bill.id.clone();
        bill.drawee = bill_identified_participant_only_node_id(identity.0.clone());
        let drawee_node_id = bill.drawee.node_id.clone();

        let mut chain = BillBlockchain::new(
            &BillIssueBlockData::from(bill, None, Timestamp::new(1731593928).unwrap()),
            identity.1,
            None,
            BcrKeys::from_private_key(&private_key_test()),
            Timestamp::new(1731593928).unwrap(),
        )
        .unwrap();
        let last_block = chain.get_latest_block();
        let accept_block = BillBlock::create_block_for_accept(
            bill_id.clone(),
            last_block,
            &BillAcceptBlockData {
                accepter: bill_identified_participant_only_node_id(node_id_test()).into(),
                signatory: None,
                signing_timestamp: last_block.timestamp + 1,
                signing_address: valid_address(),
            },
            &BcrKeys::from_private_key(&private_key_test()),
            None,
            &BcrKeys::from_private_key(&private_key_test()),
            last_block.timestamp + 1,
        )
        .expect("block could not be created");
        chain.try_add_block(accept_block);
        let bill_keys = BcrKeys::from_private_key(&private_key_test());

        let result = create_bill_to_share_with_external_party(
            &bill_id,
            &chain,
            &bill_keys,
            &external_party_pub_key,
            &sharer_keys,
            &[],
        );
        assert!(result.is_ok());

        // Receiver side
        let unwrapped = result.unwrap().clone();
        assert_eq!(unwrapped.bill_id, bill_id);
        assert_eq!(unwrapped.receiver, external_party_pub_key);
        let data = unwrapped.data.clone();
        let hash = unwrapped.hash.clone();
        let signature = unwrapped.signature.clone();
        // receiver can check that req was signed by the sharer
        assert!(signature.verify(&hash, &sharer_keys.pub_key()).unwrap());
        let decoded = base58::decode(&data).unwrap();
        // receiver can decrypt it
        let decrypted =
            crypto::decrypt_ecies(&decoded, &external_party_keys.get_private_key()).unwrap();
        // receiver can check that hash matches the data
        assert_eq!(hash, Sha256Hash::from_bytes(&decrypted));
        let deserialized: Vec<BillBlockPlaintextWrapper> = borsh::from_slice(&decrypted).unwrap();
        let decrypted_method = unwrapped
            .get_unencrypted_data(&external_party_keys.get_private_key())
            .unwrap();
        assert_eq!(deserialized.len(), decrypted_method.len());
        assert_eq!(
            borsh::to_vec(&deserialized).unwrap(),
            borsh::to_vec(&decrypted_method).unwrap()
        );
        // receiver can check that plaintext hashes match
        for block_wrapper in deserialized.iter() {
            assert_eq!(
                block_wrapper.block.plaintext_hash,
                Sha256Hash::from_bytes(&block_wrapper.plaintext_data_bytes)
            )
        }
        // receiver can check that chain is valid
        BillBlockchain::new_from_blocks(
            deserialized
                .iter()
                .map(|wrapper| wrapper.block.to_owned())
                .collect::<Vec<BillBlock>>(),
        )
        .unwrap();
        // receiver can access actual block data
        let issue = deserialized[0].clone();
        assert!(matches!(issue.block.op_code, BillOpCode::Issue));
        let plaintext_issue: BillIssueBlockData =
            borsh::from_slice(&issue.plaintext_data_bytes).unwrap();
        assert_eq!(plaintext_issue.id, bill_id);
        assert_eq!(plaintext_issue.drawee.node_id, drawee_node_id);

        let accept = deserialized[1].clone();
        assert!(matches!(accept.block.op_code, BillOpCode::Accept));
        let plaintext_accept: BillAcceptBlockData =
            borsh::from_slice(&accept.plaintext_data_bytes).unwrap();
        assert_eq!(plaintext_accept.accepter.node_id, node_id_test());
    }
}
