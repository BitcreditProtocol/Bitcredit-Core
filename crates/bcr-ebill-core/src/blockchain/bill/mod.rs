use borsh_derive::{BorshDeserialize, BorshSerialize};
use chain::BillBlockPlaintextWrapper;
use serde::{Deserialize, Serialize};

pub mod block;
pub mod chain;

pub use block::BillBlock;
use block::{BillIdentParticipantBlockData, BillRecourseReasonBlockData};
pub use chain::BillBlockchain;

use crate::{
    PublicKey, SecretKey,
    bill::{BillId, BillKeys},
    blockchain::{Result, bill::block::BillParticipantBlockData},
    contact::BillParticipant,
    sum::Sum,
    util::{self, BcrKeys},
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
    pub payment_address: String,
    pub block_id: u64,
    pub buying_deadline_timestamp: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoursePaymentInfo {
    pub recourser: BillParticipantBlockData, // recourser can be anon
    pub recoursee: BillIdentParticipantBlockData, // recoursee has to be identified
    pub sum: Sum,
    pub reason: BillRecourseReasonBlockData,
    pub block_id: u64,
    pub recourse_deadline_timestamp: u64,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone)]
pub struct BillToShareWithExternalParty {
    /// The bill id
    pub bill_id: BillId,
    /// The base58 encoded, encrypted BillBlockPlaintextWrapper of the bill
    pub data: String,
    #[borsh(
        serialize_with = "crate::util::borsh::serialize_vec_url",
        deserialize_with = "crate::util::borsh::deserialize_vec_url"
    )]
    /// The file urls of bill files, encrypted with the receiver's key, uploaded to Nostr
    pub file_urls: Vec<url::Url>,
    /// The hash over the unencrypted data
    pub hash: String,
    /// The signature over the hash by the sharer of the bill
    pub signature: String,
    #[borsh(
        serialize_with = "crate::util::borsh::serialize_pubkey",
        deserialize_with = "crate::util::borsh::deserialize_pubkey"
    )]
    /// The receiver's pub key
    pub receiver: PublicKey,
}

impl BillToShareWithExternalParty {
    pub fn get_unencrypted_data(
        &self,
        private_key: &SecretKey,
    ) -> Result<Vec<BillBlockPlaintextWrapper>> {
        let decoded = util::base58_decode(&self.data)?;
        let decrypted = util::crypto::decrypt_ecies(&decoded, private_key)?;
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
    bill_keys: &BillKeys,
    external_party_pub_key: &PublicKey,
    sharer_keys: &BcrKeys,
    file_urls: &[url::Url],
) -> Result<BillToShareWithExternalParty> {
    let chain_with_plaintext = chain.get_chain_with_plaintext_block_data(bill_keys)?;
    let serialized = borsh::to_vec(&chain_with_plaintext)?;
    let encrypted = util::crypto::encrypt_ecies(&serialized, external_party_pub_key)?;
    let encoded = util::base58_encode(&encrypted);

    let hash = util::sha256_hash(&serialized);
    let signature = util::crypto::signature(&hash, &sharer_keys.get_private_key())?;

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

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{
        address::Address,
        bill::BillKeys,
        blockchain::Blockchain,
        city::City,
        country::Country,
        identity::IdentityWithAll,
        name::Name,
        tests::tests::{empty_bitcredit_bill, empty_identity, node_id_test, private_key_test},
        util::BcrKeys,
    };
    use crate::{
        blockchain::bill::{
            BillBlock, BillBlockchain, BillOpCode,
            block::{BillAcceptBlockData, BillIssueBlockData},
            chain::BillBlockPlaintextWrapper,
        },
        tests::tests::valid_address,
    };

    use crate::tests::tests::bill_identified_participant_only_node_id;

    pub fn get_baseline_identity() -> IdentityWithAll {
        let keys = BcrKeys::from_private_key(&private_key_test()).unwrap();
        let mut identity = empty_identity();
        identity.node_id = node_id_test();
        identity.name = Name::new("drawer").unwrap();
        identity.postal_address.country = Some(Country::AT);
        identity.postal_address.city = Some(City::new("Vienna").unwrap());
        identity.postal_address.address = Some(Address::new("Hayekweg 5").unwrap());
        IdentityWithAll {
            identity,
            key_pair: keys,
        }
    }

    #[test]
    fn start_blockchain_for_new_bill_baseline() {
        let bill = empty_bitcredit_bill();
        let identity = get_baseline_identity();

        let result = BillBlockchain::new(
            &BillIssueBlockData::from(bill, None, 1731593928),
            identity.key_pair,
            None,
            BcrKeys::from_private_key(&private_key_test()).unwrap(),
            1731593928,
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
        bill.drawee = bill_identified_participant_only_node_id(identity.identity.node_id.clone());
        let drawee_node_id = bill.drawee.node_id.clone();

        let mut chain = BillBlockchain::new(
            &BillIssueBlockData::from(bill, None, 1731593928),
            identity.key_pair,
            None,
            BcrKeys::from_private_key(&private_key_test()).unwrap(),
            1731593928,
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
            &BcrKeys::from_private_key(&private_key_test()).unwrap(),
            None,
            &BcrKeys::from_private_key(&private_key_test()).unwrap(),
            last_block.timestamp + 1,
        )
        .expect("block could not be created");
        chain.try_add_block(accept_block);
        let bill_keys = BillKeys {
            private_key: private_key_test(),
            public_key: node_id_test().pub_key(),
        };

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
        assert!(util::crypto::verify(&hash, &signature, &sharer_keys.pub_key()).unwrap());
        let decoded = util::base58_decode(&data).unwrap();
        // receiver can decrypt it
        let decrypted =
            util::crypto::decrypt_ecies(&decoded, &external_party_keys.get_private_key()).unwrap();
        // receiver can check that hash matches the data
        assert_eq!(hash, util::sha256_hash(&decrypted));
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
                util::sha256_hash(&block_wrapper.plaintext_data_bytes)
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
