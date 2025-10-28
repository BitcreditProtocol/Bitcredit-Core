use super::super::{Error, Result};
use super::BillOpCode;
use super::BillOpCode::{
    Accept, Endorse, Issue, Mint, OfferToSell, Recourse, RejectToAccept, RejectToBuy, RejectToPay,
    RejectToPayRecourse, RequestRecourse, RequestToAccept, RequestToPay, Sell,
};

use crate::bill::{BillAction, BillHistoryBlock, BillId, LightSignedBy, RecourseReason};
use crate::blockchain::{Block, FIRST_BLOCK_ID};
use crate::city::City;
use crate::constants::{
    ACCEPT_DEADLINE_SECONDS, PAYMENT_DEADLINE_SECONDS, RECOURSE_DEADLINE_SECONDS,
};
use crate::country::Country;
use crate::date::Date;
use crate::name::Name;
use crate::sum::{Currency, Sum};
use crate::util::BcrKeys;
use crate::util::{self, crypto};
use crate::{
    bill::{BillKeys, BitcreditBill},
    contact::{BillIdentParticipant, ContactType},
};

use crate::contact::{
    BillAnonParticipant, BillParticipant, LightBillAnonParticipant, LightBillIdentParticipant,
    LightBillIdentParticipantWithAddress, LightBillParticipant,
};
use crate::identity::Identity;
use crate::{File, NodeId, PostalAddress, Validate, ValidationError};
use borsh::{from_slice, to_vec};
use borsh_derive::{BorshDeserialize, BorshSerialize};
use log::error;
use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::str::FromStr;

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct BillBlock {
    pub bill_id: BillId,
    pub id: u64,
    pub plaintext_hash: String,
    pub hash: String,
    pub previous_hash: String,
    pub timestamp: u64,
    pub data: String,
    #[borsh(
        serialize_with = "crate::util::borsh::serialize_pubkey",
        deserialize_with = "crate::util::borsh::deserialize_pubkey"
    )]
    pub public_key: PublicKey,
    pub signature: String,
    pub op_code: BillOpCode,
}

#[derive(BorshSerialize)]
pub struct BillBlockDataToHash {
    pub bill_id: BillId,
    id: u64,
    plaintext_hash: String,
    previous_hash: String,
    data: String,
    timestamp: u64,
    public_key: String,
    op_code: BillOpCode,
}

/// Data for reject to accept/pay/recourse
#[derive(BorshSerialize, BorshDeserialize, Serialize, Debug, Clone, PartialEq)]
pub struct BillRejectBlockData {
    pub rejecter: BillIdentParticipantBlockData, // reject to accept/pay/recourse has to be identified
    pub signatory: Option<BillSignatoryBlockData>,
    pub signing_timestamp: u64,
    pub signing_address: PostalAddress,
}

impl Validate for BillRejectBlockData {
    fn validate(&self) -> std::result::Result<(), ValidationError> {
        self.rejecter.validate()?;

        if let Some(ref signatory) = self.signatory {
            signatory.validate()?;
        }

        self.signing_address.validate()?;

        Ok(())
    }
}

/// Data for reject to buy
#[derive(BorshSerialize, BorshDeserialize, Serialize, Debug, Clone, PartialEq)]
pub struct BillRejectToBuyBlockData {
    pub rejecter: BillParticipantBlockData, // reject to buy can be done by anon
    pub signatory: Option<BillSignatoryBlockData>,
    pub signing_timestamp: u64,
    pub signing_address: Option<PostalAddress>,
}

impl Validate for BillRejectToBuyBlockData {
    fn validate(&self) -> std::result::Result<(), ValidationError> {
        self.rejecter.validate()?;

        if let Some(ref signatory) = self.signatory {
            signatory.validate()?;
        }

        self.signing_address.validate()?;

        Ok(())
    }
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Debug, Clone, PartialEq)]
pub struct BillIssueBlockData {
    pub id: BillId,
    pub country_of_issuing: Country,
    pub city_of_issuing: City,
    pub drawee: BillIdentParticipantBlockData, // drawee always has to be identified
    pub drawer: BillIdentParticipantBlockData, // drawer always has to be identified
    pub payee: BillParticipantBlockData,       // payer can be anon
    pub sum: Sum,
    pub maturity_date: Date,
    pub issue_date: Date,
    pub country_of_payment: Country,
    pub city_of_payment: City,
    pub files: Vec<File>,
    pub signatory: Option<BillSignatoryBlockData>,
    pub signing_timestamp: u64,
    pub signing_address: PostalAddress,
}

impl Validate for BillIssueBlockData {
    fn validate(&self) -> std::result::Result<(), ValidationError> {
        if self.drawee.node_id == self.payee.node_id() {
            return Err(ValidationError::DraweeCantBePayee);
        }

        self.drawee.validate()?;
        self.drawer.validate()?;
        self.payee.validate()?;

        util::date::validate_timestamp(self.signing_timestamp)?;

        if let Some(ref signatory) = self.signatory {
            signatory.validate()?;
        }

        self.signing_address.validate()?;

        Ok(())
    }
}

impl BillIssueBlockData {
    pub fn from(
        value: BitcreditBill,
        signatory: Option<BillSignatoryBlockData>,
        timestamp: u64,
    ) -> Self {
        let signing_address = value.drawer.postal_address.clone();
        Self {
            id: value.id,
            country_of_issuing: value.country_of_issuing,
            city_of_issuing: value.city_of_issuing,
            drawee: value.drawee.into(),
            drawer: value.drawer.into(),
            payee: value.payee.into(),
            sum: value.sum,
            maturity_date: value.maturity_date,
            issue_date: value.issue_date,
            country_of_payment: value.country_of_payment,
            city_of_payment: value.city_of_payment,
            files: value.files,
            signatory,
            signing_timestamp: timestamp,
            signing_address, // address of the issuer
        }
    }
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Debug, Clone, PartialEq)]
pub struct BillAcceptBlockData {
    pub accepter: BillIdentParticipantBlockData, // accepter is drawer and has to be identified
    pub signatory: Option<BillSignatoryBlockData>,
    pub signing_timestamp: u64,
    pub signing_address: PostalAddress, // address of the accepter
}

impl Validate for BillAcceptBlockData {
    fn validate(&self) -> std::result::Result<(), ValidationError> {
        self.accepter.validate()?;

        util::date::validate_timestamp(self.signing_timestamp)?;

        if let Some(ref signatory) = self.signatory {
            signatory.validate()?;
        }

        self.signing_address.validate()?;

        Ok(())
    }
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Debug, Clone, PartialEq)]
pub struct BillRequestToPayBlockData {
    pub requester: BillParticipantBlockData, // requester is holder and can be anon
    pub currency: Currency,
    pub signatory: Option<BillSignatoryBlockData>,
    pub signing_timestamp: u64,
    pub signing_address: Option<PostalAddress>, // address of the requester
    pub payment_deadline_timestamp: u64,
}

impl Validate for BillRequestToPayBlockData {
    fn validate(&self) -> std::result::Result<(), ValidationError> {
        self.requester.validate()?;

        util::date::validate_timestamp(self.signing_timestamp)?;
        util::date::validate_timestamp(self.payment_deadline_timestamp)?;

        if let Some(ref signatory) = self.signatory {
            signatory.validate()?;
        }

        // The deadline has to be at or after the end of the day of signing time plus 48h
        let signing_ts_plus_minimum_deadline = self.signing_timestamp + PAYMENT_DEADLINE_SECONDS;
        if !util::date::deadline_is_at_or_after_end_of_day_of(
            self.payment_deadline_timestamp,
            signing_ts_plus_minimum_deadline,
        ) {
            return Err(ValidationError::DeadlineBeforeMinimum);
        }

        self.signing_address.validate()?;

        Ok(())
    }
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Debug, Clone, PartialEq)]
pub struct BillRequestToAcceptBlockData {
    pub requester: BillParticipantBlockData, // requester is holder and can be anon
    pub signatory: Option<BillSignatoryBlockData>,
    pub signing_timestamp: u64,
    pub signing_address: Option<PostalAddress>, // address of the requester
    pub acceptance_deadline_timestamp: u64,
}

impl Validate for BillRequestToAcceptBlockData {
    fn validate(&self) -> std::result::Result<(), ValidationError> {
        self.requester.validate()?;

        if let Some(ref signatory) = self.signatory {
            signatory.validate()?;
        }

        util::date::validate_timestamp(self.signing_timestamp)?;
        util::date::validate_timestamp(self.acceptance_deadline_timestamp)?;

        self.signing_address.validate()?;

        // The deadline has to be at or after the end of the day of signing time plus 48h
        let signing_ts_plus_minimum_deadline = self.signing_timestamp + ACCEPT_DEADLINE_SECONDS;
        if !util::date::deadline_is_at_or_after_end_of_day_of(
            self.acceptance_deadline_timestamp,
            signing_ts_plus_minimum_deadline,
        ) {
            return Err(ValidationError::DeadlineBeforeMinimum);
        }

        Ok(())
    }
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Debug, Clone, PartialEq)]
pub struct BillMintBlockData {
    pub endorser: BillParticipantBlockData, // bill can be minted by anon
    pub endorsee: BillParticipantBlockData, // mints can be anon
    pub sum: Sum,
    pub signatory: Option<BillSignatoryBlockData>,
    pub signing_timestamp: u64,
    pub signing_address: Option<PostalAddress>, // address of the endorser
}

impl Validate for BillMintBlockData {
    fn validate(&self) -> std::result::Result<(), ValidationError> {
        self.endorser.validate()?;
        self.endorsee.validate()?;

        if self.endorsee.node_id() == self.endorser.node_id() {
            return Err(ValidationError::EndorserCantBeEndorsee);
        }

        util::date::validate_timestamp(self.signing_timestamp)?;

        if let Some(ref signatory) = self.signatory {
            signatory.validate()?;
        }

        self.signing_address.validate()?;

        Ok(())
    }
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Debug, Clone, PartialEq)]
pub struct BillOfferToSellBlockData {
    pub seller: BillParticipantBlockData, // seller is holder and can be anon
    pub buyer: BillParticipantBlockData,  // buyer can be anon
    pub sum: Sum,
    pub payment_address: String,
    pub signatory: Option<BillSignatoryBlockData>,
    pub signing_timestamp: u64,
    pub signing_address: Option<PostalAddress>, // address of the seller
    pub buying_deadline_timestamp: u64,
}

impl Validate for BillOfferToSellBlockData {
    fn validate(&self) -> std::result::Result<(), ValidationError> {
        self.seller.validate()?;
        self.buyer.validate()?;

        if self.buyer.node_id() == self.seller.node_id() {
            return Err(ValidationError::BuyerCantBeSeller);
        }

        util::date::validate_timestamp(self.signing_timestamp)?;
        util::date::validate_timestamp(self.buying_deadline_timestamp)?;

        if bitcoin::Address::from_str(&self.payment_address).is_err() {
            return Err(ValidationError::InvalidPaymentAddress);
        }

        if let Some(ref signatory) = self.signatory {
            signatory.validate()?;
        }

        // The deadline has to be at or after the end of the day of signing time
        if !util::date::deadline_is_at_or_after_end_of_day_of(
            self.buying_deadline_timestamp,
            self.signing_timestamp,
        ) {
            return Err(ValidationError::DeadlineBeforeMinimum);
        }

        self.signing_address.validate()?;

        Ok(())
    }
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Debug, Clone, PartialEq)]
pub struct BillSellBlockData {
    pub seller: BillParticipantBlockData, // seller is holder and can be anon
    pub buyer: BillParticipantBlockData,  // buyer can be anon
    pub sum: Sum,
    pub payment_address: String,
    pub signatory: Option<BillSignatoryBlockData>,
    pub signing_timestamp: u64,
    pub signing_address: Option<PostalAddress>, // address of the seller
}

impl Validate for BillSellBlockData {
    fn validate(&self) -> std::result::Result<(), ValidationError> {
        self.seller.validate()?;
        self.buyer.validate()?;

        if self.buyer.node_id() == self.seller.node_id() {
            return Err(ValidationError::BuyerCantBeSeller);
        }

        util::date::validate_timestamp(self.signing_timestamp)?;

        if bitcoin::Address::from_str(&self.payment_address).is_err() {
            return Err(ValidationError::InvalidPaymentAddress);
        }

        if let Some(ref signatory) = self.signatory {
            signatory.validate()?;
        }

        self.signing_address.validate()?;

        Ok(())
    }
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Debug, Clone, PartialEq)]
pub struct BillEndorseBlockData {
    pub endorser: BillParticipantBlockData, // endorser is holder and can be anon
    pub endorsee: BillParticipantBlockData, // endorsee can be anon
    pub signatory: Option<BillSignatoryBlockData>,
    pub signing_timestamp: u64,
    pub signing_address: Option<PostalAddress>, // address of the endorser
}

impl Validate for BillEndorseBlockData {
    fn validate(&self) -> std::result::Result<(), ValidationError> {
        self.endorser.validate()?;
        self.endorsee.validate()?;

        if self.endorsee.node_id() == self.endorser.node_id() {
            return Err(ValidationError::EndorserCantBeEndorsee);
        }

        if let Some(ref signatory) = self.signatory {
            signatory.validate()?;
        }

        util::date::validate_timestamp(self.signing_timestamp)?;

        self.signing_address.validate()?;

        Ok(())
    }
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Debug, Clone, PartialEq)]
pub struct BillRequestRecourseBlockData {
    pub recourser: BillParticipantBlockData, // anon can do recourse
    pub recoursee: BillIdentParticipantBlockData, // anon can't be recoursed against
    pub sum: Sum,
    pub recourse_reason: BillRecourseReasonBlockData,
    pub signatory: Option<BillSignatoryBlockData>,
    pub signing_timestamp: u64,
    pub signing_address: Option<PostalAddress>, // address of the recourser
    pub recourse_deadline_timestamp: u64,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub enum BillRecourseReasonBlockData {
    Accept,
    Pay,
}

impl Validate for BillRequestRecourseBlockData {
    fn validate(&self) -> std::result::Result<(), ValidationError> {
        self.recourser.validate()?;
        self.recoursee.validate()?;

        if self.recoursee.node_id == self.recourser.node_id() {
            return Err(ValidationError::RecourserCantBeRecoursee);
        }

        util::date::validate_timestamp(self.signing_timestamp)?;
        util::date::validate_timestamp(self.recourse_deadline_timestamp)?;

        if let Some(ref signatory) = self.signatory {
            signatory.validate()?;
        }

        // The deadline has to be at or after the end of the day of signing time plus 48h
        let signing_ts_plus_minimum_deadline = self.signing_timestamp + RECOURSE_DEADLINE_SECONDS;
        if !util::date::deadline_is_at_or_after_end_of_day_of(
            self.recourse_deadline_timestamp,
            signing_ts_plus_minimum_deadline,
        ) {
            return Err(ValidationError::DeadlineBeforeMinimum);
        }

        self.signing_address.validate()?;

        Ok(())
    }
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Debug, Clone, PartialEq)]
pub struct BillRecourseBlockData {
    pub recourser: BillParticipantBlockData, // anon can do recourse
    pub recoursee: BillIdentParticipantBlockData, // anon can't be recoursed against
    pub sum: Sum,
    pub recourse_reason: BillRecourseReasonBlockData,
    pub signatory: Option<BillSignatoryBlockData>,
    pub signing_timestamp: u64,
    pub signing_address: Option<PostalAddress>, // address of the endorser
}

impl Validate for BillRecourseBlockData {
    fn validate(&self) -> std::result::Result<(), ValidationError> {
        self.recourser.validate()?;
        self.recoursee.validate()?;

        if self.recoursee.node_id == self.recourser.node_id() {
            return Err(ValidationError::RecourserCantBeRecoursee);
        }

        util::date::validate_timestamp(self.signing_timestamp)?;

        if let Some(ref signatory) = self.signatory {
            signatory.validate()?;
        }

        self.signing_address.validate()?;

        Ok(())
    }
}

/// Participant in a bill transaction - either anonymous, or identified
#[derive(BorshSerialize, BorshDeserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub enum BillParticipantBlockData {
    Anon(BillAnonParticipantBlockData),
    Ident(BillIdentParticipantBlockData),
}

impl BillParticipantBlockData {
    pub fn node_id(&self) -> NodeId {
        match self {
            BillParticipantBlockData::Anon(data) => data.node_id.clone(),
            BillParticipantBlockData::Ident(data) => data.node_id.clone(),
        }
    }
}

impl From<BillParticipant> for BillParticipantBlockData {
    fn from(value: BillParticipant) -> Self {
        match value {
            BillParticipant::Ident(data) => Self::Ident(BillIdentParticipantBlockData {
                t: data.t,
                node_id: data.node_id,
                name: data.name,
                postal_address: data.postal_address,
            }),
            BillParticipant::Anon(data) => Self::Anon(BillAnonParticipantBlockData {
                node_id: data.node_id,
            }),
        }
    }
}

impl From<BillParticipantBlockData> for BillParticipant {
    fn from(value: BillParticipantBlockData) -> Self {
        match value {
            BillParticipantBlockData::Ident(data) => Self::Ident(BillIdentParticipant {
                t: data.t,
                node_id: data.node_id,
                name: data.name,
                postal_address: data.postal_address,
                email: None,
                nostr_relays: vec![],
            }),
            BillParticipantBlockData::Anon(data) => Self::Anon(BillAnonParticipant {
                node_id: data.node_id,
                email: None,
                nostr_relays: vec![],
            }),
        }
    }
}

impl Validate for BillParticipantBlockData {
    fn validate(&self) -> std::result::Result<(), ValidationError> {
        match self {
            BillParticipantBlockData::Anon(data) => {
                data.validate()?;
            }
            BillParticipantBlockData::Ident(data) => {
                data.validate()?;
            }
        }
        Ok(())
    }
}

/// Anon bill participany data
#[derive(BorshSerialize, BorshDeserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct BillAnonParticipantBlockData {
    pub node_id: NodeId,
}

impl Validate for BillAnonParticipantBlockData {
    fn validate(&self) -> std::result::Result<(), ValidationError> {
        Ok(())
    }
}

/// Legal data for parties of a bill within the liability chain
#[derive(BorshSerialize, BorshDeserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct BillIdentParticipantBlockData {
    pub t: ContactType,
    pub node_id: NodeId,
    pub name: Name,
    pub postal_address: PostalAddress,
}

impl BillIdentParticipantBlockData {
    pub fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }
}

impl Validate for BillIdentParticipantBlockData {
    fn validate(&self) -> std::result::Result<(), ValidationError> {
        self.postal_address.validate()?;
        Ok(())
    }
}

impl From<BillIdentParticipant> for BillIdentParticipantBlockData {
    fn from(value: BillIdentParticipant) -> Self {
        Self {
            t: value.t,
            node_id: value.node_id,
            name: value.name,
            postal_address: value.postal_address,
        }
    }
}

impl From<BillIdentParticipantBlockData> for BillIdentParticipant {
    fn from(value: BillIdentParticipantBlockData) -> Self {
        Self {
            t: value.t,
            node_id: value.node_id,
            name: value.name,
            postal_address: value.postal_address,
            email: None,
            nostr_relays: vec![],
        }
    }
}

impl From<BillIdentParticipantBlockData> for LightBillIdentParticipantWithAddress {
    fn from(value: BillIdentParticipantBlockData) -> Self {
        Self {
            t: value.t,
            name: value.name,
            node_id: value.node_id,
            postal_address: value.postal_address,
        }
    }
}

impl From<BillParticipantBlockData> for LightBillParticipant {
    fn from(value: BillParticipantBlockData) -> Self {
        match value {
            BillParticipantBlockData::Anon(data) => LightBillParticipant::Anon(data.into()),
            BillParticipantBlockData::Ident(data) => LightBillParticipant::Ident(data.into()),
        }
    }
}
impl From<BillAnonParticipantBlockData> for LightBillAnonParticipant {
    fn from(value: BillAnonParticipantBlockData) -> Self {
        Self {
            node_id: value.node_id,
        }
    }
}

impl From<BillAnonParticipant> for BillAnonParticipantBlockData {
    fn from(value: BillAnonParticipant) -> Self {
        Self {
            node_id: value.node_id,
        }
    }
}

impl From<BillIdentParticipantBlockData> for LightBillIdentParticipant {
    fn from(value: BillIdentParticipantBlockData) -> Self {
        Self {
            t: value.t,
            name: value.name,
            node_id: value.node_id,
        }
    }
}

/// The name and node_id of a company signatory
#[derive(BorshSerialize, BorshDeserialize, Serialize, Debug, Clone, PartialEq)]
pub struct BillSignatoryBlockData {
    pub node_id: NodeId,
    pub name: Name,
}

impl Validate for BillSignatoryBlockData {
    fn validate(&self) -> std::result::Result<(), ValidationError> {
        Ok(())
    }
}

impl From<Identity> for BillSignatoryBlockData {
    fn from(value: Identity) -> Self {
        Self {
            name: value.name,
            node_id: value.node_id,
        }
    }
}

/// The data of the new holder in a holder-changing block, with the signatory data from the block
#[derive(Clone, Debug)]
pub struct HolderFromBlock {
    pub holder: BillParticipantBlockData, // holder can be anon
    pub signer: BillParticipantBlockData, // signer can be anon
    pub signatory: Option<BillSignatoryBlockData>,
}

impl Block for BillBlock {
    type OpCode = BillOpCode;
    type BlockDataToHash = BillBlockDataToHash;

    fn id(&self) -> u64 {
        self.id
    }

    fn timestamp(&self) -> u64 {
        self.timestamp
    }

    fn op_code(&self) -> &Self::OpCode {
        &self.op_code
    }

    fn plaintext_hash(&self) -> &str {
        &self.plaintext_hash
    }

    fn hash(&self) -> &str {
        &self.hash
    }

    fn previous_hash(&self) -> &str {
        &self.previous_hash
    }

    fn data(&self) -> &str {
        &self.data
    }

    fn signature(&self) -> &str {
        &self.signature
    }

    fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    fn validate(&self) -> bool {
        true
    }

    /// We validate the plaintext hash against the plaintext data from the BillBlockData wrapper
    fn validate_plaintext_hash(&self, private_key: &secp256k1::SecretKey) -> bool {
        match util::base58_decode(&self.data) {
            Ok(decoded_wrapper) => match from_slice::<BillBlockData>(&decoded_wrapper) {
                Ok(data_wrapper) => match util::base58_decode(&data_wrapper.data) {
                    Ok(decoded) => match util::crypto::decrypt_ecies(&decoded, private_key) {
                        Ok(decrypted) => self.plaintext_hash() == util::sha256_hash(&decrypted),
                        Err(e) => {
                            error!(
                                "Decrypt Error while validating plaintext hash for id {}: {e}",
                                self.id()
                            );
                            false
                        }
                    },
                    Err(e) => {
                        error!(
                            "Decode Error while validating plaintext hash for id {}: {e}",
                            self.id()
                        );
                        false
                    }
                },
                Err(e) => {
                    error!(
                        "Wrapper Deserialize Error while validating plaintext hash for id {}: {e}",
                        self.id()
                    );
                    false
                }
            },
            Err(e) => {
                error!(
                    "Wrapper Decode Error while validating plaintext hash for id {}: {e}",
                    self.id()
                );
                false
            }
        }
    }

    fn get_block_data_to_hash(&self) -> Self::BlockDataToHash {
        BillBlockDataToHash {
            bill_id: self.bill_id.clone(),
            id: self.id(),
            plaintext_hash: self.plaintext_hash().to_owned(),
            previous_hash: self.previous_hash().to_owned(),
            data: self.data().to_owned(),
            timestamp: self.timestamp(),
            public_key: self.public_key().to_string(),
            op_code: self.op_code().to_owned(),
        }
    }
}

/// Structure for the block data of a bill block
///
/// - `data` contains the actual data of the block, encrypted using the bill's pub key
/// - `key` is optional and if set, contains the bill private key encrypted by an identity
///   pub key (e.g. for Issue the issuer's and Endorse the endorsee's)
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq)]
pub struct BillBlockData {
    data: String,
    key: Option<String>,
}

impl BillBlock {
    /// Create a new block and sign it with an aggregated key, combining the identity key of the
    /// signer, and the company key if it exists and the bill key
    pub fn new(
        bill_id: BillId,
        id: u64,
        previous_hash: String,
        data: String,
        op_code: BillOpCode,
        identity_keys: &BcrKeys,
        company_keys: Option<&BcrKeys>,
        bill_keys: &BcrKeys,
        timestamp: u64,
        plaintext_hash: String,
    ) -> Result<Self> {
        // The order here is important: identity -> company -> bill
        let mut keys: Vec<secp256k1::SecretKey> = vec![];
        keys.push(identity_keys.get_private_key());
        if let Some(company_key) = company_keys {
            keys.push(company_key.get_private_key());
        }
        keys.push(bill_keys.get_private_key());

        let aggregated_public_key = crypto::get_aggregated_public_key(&keys)?;
        let hash = Self::calculate_hash(BillBlockDataToHash {
            bill_id: bill_id.clone(),
            id,
            plaintext_hash: plaintext_hash.clone(),
            previous_hash: previous_hash.clone(),
            data: data.clone(),
            timestamp,
            public_key: aggregated_public_key.to_string(),
            op_code: op_code.clone(),
        })?;
        let signature = crypto::aggregated_signature(&hash, &keys)?;

        Ok(Self {
            bill_id,
            id,
            plaintext_hash,
            hash,
            timestamp,
            previous_hash,
            signature,
            public_key: aggregated_public_key,
            data,
            op_code,
        })
    }

    pub fn create_block_for_issue(
        bill_id: BillId,
        genesis_hash: String,
        bill: &BillIssueBlockData,
        drawer_keys: &BcrKeys,
        drawer_company_keys: Option<&BcrKeys>,
        bill_keys: &BcrKeys,
        timestamp: u64,
    ) -> Result<Self> {
        let plaintext_hash = Self::calculate_plaintext_hash(bill)?;
        let key_bytes = to_vec(&bill_keys.get_private_key_string())?;
        // If drawer is a company, use drawer_company_keys for encryption
        let encrypted_key = match drawer_company_keys {
            None => util::base58_encode(&util::crypto::encrypt_ecies(
                &key_bytes,
                &drawer_keys.pub_key(),
            )?),
            Some(company_keys) => util::base58_encode(&util::crypto::encrypt_ecies(
                &key_bytes,
                &company_keys.pub_key(),
            )?),
        };

        let issue_data_bytes = to_vec(bill)?;

        let encrypted_and_hashed_bill_data = util::base58_encode(&util::crypto::encrypt_ecies(
            &issue_data_bytes,
            &bill_keys.pub_key(),
        )?);

        let data = BillBlockData {
            data: encrypted_and_hashed_bill_data,
            key: Some(encrypted_key),
        };
        let serialized_and_hashed_data = util::base58_encode(&to_vec(&data)?);

        Self::new(
            bill_id,
            FIRST_BLOCK_ID,
            genesis_hash,
            serialized_and_hashed_data,
            BillOpCode::Issue,
            drawer_keys,
            drawer_company_keys,
            bill_keys,
            timestamp,
            plaintext_hash,
        )
    }

    pub fn create_block_for_reject_to_accept(
        bill_id: BillId,
        previous_block: &Self,
        data: &BillRejectBlockData,
        identity_keys: &BcrKeys,
        company_keys: Option<&BcrKeys>,
        bill_keys: &BcrKeys,
        timestamp: u64,
    ) -> Result<Self> {
        let block = Self::encrypt_data_create_block_and_validate(
            bill_id,
            previous_block,
            data,
            identity_keys,
            company_keys,
            bill_keys,
            None,
            timestamp,
            BillOpCode::RejectToAccept,
        )?;
        Ok(block)
    }

    pub fn create_block_for_reject_to_pay(
        bill_id: BillId,
        previous_block: &Self,
        data: &BillRejectBlockData,
        identity_keys: &BcrKeys,
        company_keys: Option<&BcrKeys>,
        bill_keys: &BcrKeys,
        timestamp: u64,
    ) -> Result<Self> {
        let block = Self::encrypt_data_create_block_and_validate(
            bill_id,
            previous_block,
            data,
            identity_keys,
            company_keys,
            bill_keys,
            None,
            timestamp,
            BillOpCode::RejectToPay,
        )?;
        Ok(block)
    }

    pub fn create_block_for_reject_to_buy(
        bill_id: BillId,
        previous_block: &Self,
        data: &BillRejectToBuyBlockData,
        identity_keys: &BcrKeys,
        company_keys: Option<&BcrKeys>,
        bill_keys: &BcrKeys,
        timestamp: u64,
    ) -> Result<Self> {
        let block = Self::encrypt_data_create_block_and_validate(
            bill_id,
            previous_block,
            data,
            identity_keys,
            company_keys,
            bill_keys,
            None,
            timestamp,
            BillOpCode::RejectToBuy,
        )?;
        Ok(block)
    }

    pub fn create_block_for_reject_to_pay_recourse(
        bill_id: BillId,
        previous_block: &Self,
        data: &BillRejectBlockData,
        identity_keys: &BcrKeys,
        company_keys: Option<&BcrKeys>,
        bill_keys: &BcrKeys,
        timestamp: u64,
    ) -> Result<Self> {
        let block = Self::encrypt_data_create_block_and_validate(
            bill_id,
            previous_block,
            data,
            identity_keys,
            company_keys,
            bill_keys,
            None,
            timestamp,
            BillOpCode::RejectToPayRecourse,
        )?;
        Ok(block)
    }

    pub fn create_block_for_request_recourse(
        bill_id: BillId,
        previous_block: &Self,
        data: &BillRequestRecourseBlockData,
        identity_keys: &BcrKeys,
        company_keys: Option<&BcrKeys>,
        bill_keys: &BcrKeys,
        timestamp: u64,
    ) -> Result<Self> {
        let block = Self::encrypt_data_create_block_and_validate(
            bill_id,
            previous_block,
            data,
            identity_keys,
            company_keys,
            bill_keys,
            None,
            timestamp,
            BillOpCode::RequestRecourse,
        )?;
        Ok(block)
    }

    pub fn create_block_for_recourse(
        bill_id: BillId,
        previous_block: &Self,
        data: &BillRecourseBlockData,
        identity_keys: &BcrKeys,
        company_keys: Option<&BcrKeys>,
        bill_keys: &BcrKeys,
        timestamp: u64,
    ) -> Result<Self> {
        let block = Self::encrypt_data_create_block_and_validate(
            bill_id,
            previous_block,
            data,
            identity_keys,
            company_keys,
            bill_keys,
            None,
            timestamp,
            BillOpCode::Recourse,
        )?;
        Ok(block)
    }

    pub fn create_block_for_accept(
        bill_id: BillId,
        previous_block: &Self,
        data: &BillAcceptBlockData,
        identity_keys: &BcrKeys,
        company_keys: Option<&BcrKeys>,
        bill_keys: &BcrKeys,
        timestamp: u64,
    ) -> Result<Self> {
        let block = Self::encrypt_data_create_block_and_validate(
            bill_id,
            previous_block,
            data,
            identity_keys,
            company_keys,
            bill_keys,
            None,
            timestamp,
            BillOpCode::Accept,
        )?;
        Ok(block)
    }

    pub fn create_block_for_request_to_pay(
        bill_id: BillId,
        previous_block: &Self,
        data: &BillRequestToPayBlockData,
        identity_keys: &BcrKeys,
        company_keys: Option<&BcrKeys>,
        bill_keys: &BcrKeys,
        timestamp: u64,
    ) -> Result<Self> {
        let block = Self::encrypt_data_create_block_and_validate(
            bill_id,
            previous_block,
            data,
            identity_keys,
            company_keys,
            bill_keys,
            None,
            timestamp,
            BillOpCode::RequestToPay,
        )?;
        Ok(block)
    }

    pub fn create_block_for_request_to_accept(
        bill_id: BillId,
        previous_block: &Self,
        data: &BillRequestToAcceptBlockData,
        identity_keys: &BcrKeys,
        company_keys: Option<&BcrKeys>,
        bill_keys: &BcrKeys,
        timestamp: u64,
    ) -> Result<Self> {
        let block = Self::encrypt_data_create_block_and_validate(
            bill_id,
            previous_block,
            data,
            identity_keys,
            company_keys,
            bill_keys,
            None,
            timestamp,
            BillOpCode::RequestToAccept,
        )?;
        Ok(block)
    }

    pub fn create_block_for_mint(
        bill_id: BillId,
        previous_block: &Self,
        data: &BillMintBlockData,
        identity_keys: &BcrKeys,
        company_keys: Option<&BcrKeys>,
        bill_keys: &BcrKeys,
        timestamp: u64,
    ) -> Result<Self> {
        let block = Self::encrypt_data_create_block_and_validate(
            bill_id,
            previous_block,
            data,
            identity_keys,
            company_keys,
            bill_keys,
            Some(data.endorsee.node_id().pub_key()),
            timestamp,
            BillOpCode::Mint,
        )?;
        Ok(block)
    }

    pub fn create_block_for_offer_to_sell(
        bill_id: BillId,
        previous_block: &Self,
        data: &BillOfferToSellBlockData,
        identity_keys: &BcrKeys,
        company_keys: Option<&BcrKeys>,
        bill_keys: &BcrKeys,
        timestamp: u64,
    ) -> Result<Self> {
        let block = Self::encrypt_data_create_block_and_validate(
            bill_id,
            previous_block,
            data,
            identity_keys,
            company_keys,
            bill_keys,
            None,
            timestamp,
            BillOpCode::OfferToSell,
        )?;
        Ok(block)
    }

    pub fn create_block_for_sell(
        bill_id: BillId,
        previous_block: &Self,
        data: &BillSellBlockData,
        identity_keys: &BcrKeys,
        company_keys: Option<&BcrKeys>,
        bill_keys: &BcrKeys,
        timestamp: u64,
    ) -> Result<Self> {
        let block = Self::encrypt_data_create_block_and_validate(
            bill_id,
            previous_block,
            data,
            identity_keys,
            company_keys,
            bill_keys,
            Some(data.buyer.node_id().pub_key()),
            timestamp,
            BillOpCode::Sell,
        )?;
        Ok(block)
    }

    pub fn create_block_for_endorse(
        bill_id: BillId,
        previous_block: &Self,
        data: &BillEndorseBlockData,
        identity_keys: &BcrKeys,
        company_keys: Option<&BcrKeys>,
        bill_keys: &BcrKeys,
        timestamp: u64,
    ) -> Result<Self> {
        let block = Self::encrypt_data_create_block_and_validate(
            bill_id,
            previous_block,
            data,
            identity_keys,
            company_keys,
            bill_keys,
            Some(data.endorsee.node_id().pub_key()),
            timestamp,
            BillOpCode::Endorse,
        )?;
        Ok(block)
    }

    fn encrypt_data_create_block_and_validate<T: borsh::BorshSerialize>(
        bill_id: BillId,
        previous_block: &Self,
        data: &T,
        identity_keys: &BcrKeys,
        company_keys: Option<&BcrKeys>,
        bill_keys: &BcrKeys,
        public_key_for_keys: Option<PublicKey>, // when encrypting keys for a new holder
        timestamp: u64,
        op_code: BillOpCode,
    ) -> Result<Self> {
        let bytes = to_vec(&data)?;
        let plaintext_hash = Self::calculate_plaintext_hash(data)?;
        // encrypt data using the bill pub key
        let encrypted_data =
            util::base58_encode(&util::crypto::encrypt_ecies(&bytes, &bill_keys.pub_key())?);

        let mut key = None;

        // in case there are keys to encrypt, encrypt them using the receiver's identity pub key
        if (op_code == BillOpCode::Endorse
            || op_code == BillOpCode::Sell
            || op_code == BillOpCode::Mint)
            && let Some(new_holder_public_key) = public_key_for_keys
        {
            let key_bytes = to_vec(&bill_keys.get_private_key_string())?;
            let encrypted_key = util::base58_encode(&util::crypto::encrypt_ecies(
                &key_bytes,
                &new_holder_public_key,
            )?);
            key = Some(encrypted_key);
        }

        let data = BillBlockData {
            data: encrypted_data,
            key,
        };
        let serialized_and_hashed_data = util::base58_encode(&to_vec(&data)?);

        let new_block = Self::new(
            bill_id,
            previous_block.id + 1,
            previous_block.hash.clone(),
            serialized_and_hashed_data,
            op_code,
            identity_keys,
            company_keys,
            bill_keys,
            timestamp,
            plaintext_hash,
        )?;

        if !new_block.validate_with_previous(previous_block) {
            return Err(Error::BlockInvalid);
        }
        Ok(new_block)
    }

    /// Decrypts the block data using the bill's private key, returning the deserialized data
    pub fn get_decrypted_block<T: borsh::BorshDeserialize>(
        &self,
        bill_keys: &BillKeys,
    ) -> Result<T> {
        let decrypted_bytes = self.get_decrypted_block_bytes(bill_keys)?;
        let deserialized = from_slice::<T>(&decrypted_bytes)?;
        Ok(deserialized)
    }

    /// Decrypts the block data using the bill's private key, returning the deserialized data
    pub(super) fn get_decrypted_block_bytes(&self, bill_keys: &BillKeys) -> Result<Vec<u8>> {
        let bytes = util::base58_decode(&self.data)?;
        let block_data: BillBlockData = from_slice(&bytes)?;
        let decoded_data_bytes = util::base58_decode(&block_data.data)?;
        let decrypted_bytes =
            util::crypto::decrypt_ecies(&decoded_data_bytes, &bill_keys.private_key)?;
        Ok(decrypted_bytes)
    }

    /// Extracts a list of unique node IDs involved in a block operation.
    ///
    /// # Parameters
    /// - `bill_keys`: The bill's keys
    ///
    /// # Returns
    /// A `Vec<String>` containing the unique peer IDs involved in the block. Peer IDs are included
    /// only if they are non-empty.
    ///
    pub fn get_nodes_from_block(&self, bill_keys: &BillKeys) -> Result<Vec<NodeId>> {
        let mut nodes = HashSet::new();
        match self.op_code {
            Issue => {
                let bill: BillIssueBlockData = self.get_decrypted_block(bill_keys)?;
                nodes.insert(bill.drawer.node_id);
                nodes.insert(bill.payee.node_id().to_owned());
                nodes.insert(bill.drawee.node_id);
            }
            Endorse => {
                let block_data_decrypted: BillEndorseBlockData =
                    self.get_decrypted_block(bill_keys)?;
                nodes.insert(block_data_decrypted.endorsee.node_id());
                nodes.insert(block_data_decrypted.endorser.node_id());
            }
            Mint => {
                let block_data_decrypted: BillMintBlockData =
                    self.get_decrypted_block(bill_keys)?;
                nodes.insert(block_data_decrypted.endorsee.node_id());
                nodes.insert(block_data_decrypted.endorser.node_id());
            }
            RequestToAccept => {
                let block_data_decrypted: BillRequestToAcceptBlockData =
                    self.get_decrypted_block(bill_keys)?;
                nodes.insert(block_data_decrypted.requester.node_id());
            }
            Accept => {
                let block_data_decrypted: BillAcceptBlockData =
                    self.get_decrypted_block(bill_keys)?;
                nodes.insert(block_data_decrypted.accepter.node_id);
            }
            RequestToPay => {
                let block_data_decrypted: BillRequestToPayBlockData =
                    self.get_decrypted_block(bill_keys)?;
                nodes.insert(block_data_decrypted.requester.node_id());
            }
            OfferToSell => {
                let block_data_decrypted: BillOfferToSellBlockData =
                    self.get_decrypted_block(bill_keys)?;
                nodes.insert(block_data_decrypted.buyer.node_id());
                nodes.insert(block_data_decrypted.seller.node_id());
            }
            Sell => {
                let block_data_decrypted: BillSellBlockData =
                    self.get_decrypted_block(bill_keys)?;
                nodes.insert(block_data_decrypted.buyer.node_id());
                nodes.insert(block_data_decrypted.seller.node_id());
            }
            RejectToAccept | RejectToPay | RejectToPayRecourse => {
                let block_data_decrypted: BillRejectBlockData =
                    self.get_decrypted_block(bill_keys)?;
                nodes.insert(block_data_decrypted.rejecter.node_id);
            }
            RejectToBuy => {
                let block_data_decrypted: BillRejectToBuyBlockData =
                    self.get_decrypted_block(bill_keys)?;
                nodes.insert(block_data_decrypted.rejecter.node_id());
            }
            RequestRecourse => {
                let block_data_decrypted: BillRequestRecourseBlockData =
                    self.get_decrypted_block(bill_keys)?;
                nodes.insert(block_data_decrypted.recourser.node_id());
                nodes.insert(block_data_decrypted.recoursee.node_id);
            }
            Recourse => {
                let block_data_decrypted: BillRecourseBlockData =
                    self.get_decrypted_block(bill_keys)?;
                nodes.insert(block_data_decrypted.recourser.node_id());
                nodes.insert(block_data_decrypted.recoursee.node_id);
            }
        }
        Ok(nodes.into_iter().collect())
    }

    /// If the block is a holder-changing block with a financial beneficiary(sell, recourse),
    /// return the node_id of the beneficiary
    pub fn get_beneficiary_from_block(&self, bill_keys: &BillKeys) -> Result<Option<NodeId>> {
        match self.op_code {
            Sell => {
                let block: BillSellBlockData = self.get_decrypted_block(bill_keys)?;
                Ok(Some(block.seller.node_id()))
            }
            Recourse => {
                let block: BillRecourseBlockData = self.get_decrypted_block(bill_keys)?;
                Ok(Some(block.recourser.node_id()))
            }
            _ => Ok(None),
        }
    }

    /// If the block is a request with a financial beneficiary(req to pay, offer to sell, req to recourse),
    /// return the node_id of the beneficiary
    pub fn get_beneficiary_from_request_funds_block(
        &self,
        bill_keys: &BillKeys,
    ) -> Result<Option<NodeId>> {
        match self.op_code {
            OfferToSell => {
                let block: BillOfferToSellBlockData = self.get_decrypted_block(bill_keys)?;
                Ok(Some(block.seller.node_id()))
            }
            RequestRecourse => {
                let block: BillRequestRecourseBlockData = self.get_decrypted_block(bill_keys)?;
                Ok(Some(block.recourser.node_id()))
            }
            RequestToPay => {
                let block: BillRequestToPayBlockData = self.get_decrypted_block(bill_keys)?;
                Ok(Some(block.requester.node_id()))
            }
            _ => Ok(None),
        }
    }

    pub fn get_history_from_block(&self, bill_keys: &BillKeys) -> Result<BillHistoryBlock> {
        Ok(match self.op_code {
            Issue => {
                let block_data_decrypted: BillIssueBlockData =
                    self.get_decrypted_block(bill_keys)?;
                BillHistoryBlock::new(
                    self,
                    None,
                    LightSignedBy::from((
                        BillParticipantBlockData::Ident(block_data_decrypted.drawer),
                        block_data_decrypted.signatory,
                    )),
                    Some(block_data_decrypted.signing_address),
                )
            }
            Endorse => {
                let block_data_decrypted: BillEndorseBlockData =
                    self.get_decrypted_block(bill_keys)?;
                BillHistoryBlock::new(
                    self,
                    Some(block_data_decrypted.endorsee.into()),
                    LightSignedBy::from((
                        block_data_decrypted.endorser,
                        block_data_decrypted.signatory,
                    )),
                    block_data_decrypted.signing_address,
                )
            }
            Mint => {
                let block_data_decrypted: BillMintBlockData =
                    self.get_decrypted_block(bill_keys)?;
                BillHistoryBlock::new(
                    self,
                    Some(block_data_decrypted.endorsee.into()),
                    LightSignedBy::from((
                        block_data_decrypted.endorser,
                        block_data_decrypted.signatory,
                    )),
                    block_data_decrypted.signing_address,
                )
            }
            RequestToAccept => {
                let block_data_decrypted: BillRequestToAcceptBlockData =
                    self.get_decrypted_block(bill_keys)?;
                BillHistoryBlock::new(
                    self,
                    None,
                    LightSignedBy::from((
                        block_data_decrypted.requester,
                        block_data_decrypted.signatory,
                    )),
                    block_data_decrypted.signing_address,
                )
            }
            Accept => {
                let block_data_decrypted: BillAcceptBlockData =
                    self.get_decrypted_block(bill_keys)?;
                BillHistoryBlock::new(
                    self,
                    None,
                    LightSignedBy::from((
                        BillParticipantBlockData::Ident(block_data_decrypted.accepter),
                        block_data_decrypted.signatory,
                    )),
                    Some(block_data_decrypted.signing_address),
                )
            }
            RequestToPay => {
                let block_data_decrypted: BillRequestToPayBlockData =
                    self.get_decrypted_block(bill_keys)?;
                BillHistoryBlock::new(
                    self,
                    None,
                    LightSignedBy::from((
                        block_data_decrypted.requester,
                        block_data_decrypted.signatory,
                    )),
                    block_data_decrypted.signing_address,
                )
            }
            OfferToSell => {
                let block_data_decrypted: BillOfferToSellBlockData =
                    self.get_decrypted_block(bill_keys)?;
                BillHistoryBlock::new(
                    self,
                    Some(block_data_decrypted.buyer.into()),
                    LightSignedBy::from((
                        block_data_decrypted.seller,
                        block_data_decrypted.signatory,
                    )),
                    block_data_decrypted.signing_address,
                )
            }
            Sell => {
                let block_data_decrypted: BillSellBlockData =
                    self.get_decrypted_block(bill_keys)?;
                BillHistoryBlock::new(
                    self,
                    Some(block_data_decrypted.buyer.into()),
                    LightSignedBy::from((
                        block_data_decrypted.seller,
                        block_data_decrypted.signatory,
                    )),
                    block_data_decrypted.signing_address,
                )
            }
            RejectToAccept => {
                let block_data_decrypted: BillRejectBlockData =
                    self.get_decrypted_block(bill_keys)?;
                BillHistoryBlock::new(
                    self,
                    None,
                    LightSignedBy::from((
                        BillParticipantBlockData::Ident(block_data_decrypted.rejecter),
                        block_data_decrypted.signatory,
                    )),
                    Some(block_data_decrypted.signing_address),
                )
            }
            RejectToPay => {
                let block_data_decrypted: BillRejectBlockData =
                    self.get_decrypted_block(bill_keys)?;
                BillHistoryBlock::new(
                    self,
                    None,
                    LightSignedBy::from((
                        BillParticipantBlockData::Ident(block_data_decrypted.rejecter),
                        block_data_decrypted.signatory,
                    )),
                    Some(block_data_decrypted.signing_address),
                )
            }
            RejectToPayRecourse => {
                let block_data_decrypted: BillRejectBlockData =
                    self.get_decrypted_block(bill_keys)?;
                BillHistoryBlock::new(
                    self,
                    None,
                    LightSignedBy::from((
                        BillParticipantBlockData::Ident(block_data_decrypted.rejecter),
                        block_data_decrypted.signatory,
                    )),
                    Some(block_data_decrypted.signing_address),
                )
            }
            RejectToBuy => {
                let block_data_decrypted: BillRejectToBuyBlockData =
                    self.get_decrypted_block(bill_keys)?;
                BillHistoryBlock::new(
                    self,
                    None,
                    LightSignedBy::from((
                        block_data_decrypted.rejecter,
                        block_data_decrypted.signatory,
                    )),
                    block_data_decrypted.signing_address,
                )
            }
            RequestRecourse => {
                let block_data_decrypted: BillRequestRecourseBlockData =
                    self.get_decrypted_block(bill_keys)?;
                BillHistoryBlock::new(
                    self,
                    Some(BillParticipantBlockData::Ident(block_data_decrypted.recoursee).into()),
                    LightSignedBy::from((
                        block_data_decrypted.recourser,
                        block_data_decrypted.signatory,
                    )),
                    block_data_decrypted.signing_address,
                )
            }
            Recourse => {
                let block_data_decrypted: BillRecourseBlockData =
                    self.get_decrypted_block(bill_keys)?;
                BillHistoryBlock::new(
                    self,
                    Some(BillParticipantBlockData::Ident(block_data_decrypted.recoursee).into()),
                    LightSignedBy::from((
                        block_data_decrypted.recourser,
                        block_data_decrypted.signatory,
                    )),
                    block_data_decrypted.signing_address,
                )
            }
        })
    }

    /// If the block is holder-changing block (issue, endorse, sell, mint, recourse), returns
    /// the new holder and signer data from the block
    pub fn get_holder_from_block(&self, bill_keys: &BillKeys) -> Result<Option<HolderFromBlock>> {
        match self.op_code {
            Issue => {
                let bill: BillIssueBlockData = self.get_decrypted_block(bill_keys)?;
                Ok(Some(HolderFromBlock {
                    holder: bill.payee,
                    signer: BillParticipantBlockData::Ident(bill.drawer),
                    signatory: bill.signatory,
                }))
            }
            Endorse => {
                let block: BillEndorseBlockData = self.get_decrypted_block(bill_keys)?;
                Ok(Some(HolderFromBlock {
                    holder: block.endorsee,
                    signer: block.endorser,
                    signatory: block.signatory,
                }))
            }
            Mint => {
                let block: BillMintBlockData = self.get_decrypted_block(bill_keys)?;
                Ok(Some(HolderFromBlock {
                    holder: block.endorsee,
                    signer: block.endorser,
                    signatory: block.signatory,
                }))
            }
            Sell => {
                let block: BillSellBlockData = self.get_decrypted_block(bill_keys)?;
                Ok(Some(HolderFromBlock {
                    holder: block.buyer,
                    signer: block.seller,
                    signatory: block.signatory,
                }))
            }
            Recourse => {
                let block: BillRecourseBlockData = self.get_decrypted_block(bill_keys)?;
                Ok(Some(HolderFromBlock {
                    holder: BillParticipantBlockData::Ident(block.recoursee),
                    signer: block.recourser,
                    signatory: block.signatory,
                }))
            }
            _ => Ok(None),
        }
    }

    /// Validates the block data and Verifies that the signer/signatory combo in the block is the one who signed the block and
    /// returns the signer_node_id and bill action for the block
    pub fn verify_and_get_signer(
        &self,
        bill_keys: &BillKeys,
    ) -> Result<(NodeId, Option<BillAction>)> {
        let (signer, signatory, bill_action) = match self.op_code {
            Issue => {
                let data: BillIssueBlockData = self.get_decrypted_block(bill_keys)?;
                data.validate()?;
                (data.drawer.node_id, data.signatory.map(|s| s.node_id), None)
            }
            Endorse => {
                let data: BillEndorseBlockData = self.get_decrypted_block(bill_keys)?;
                data.validate()?;
                (
                    data.endorser.node_id(),
                    data.signatory.map(|s| s.node_id),
                    Some(BillAction::Endorse(data.endorsee.into())),
                )
            }
            Mint => {
                let data: BillMintBlockData = self.get_decrypted_block(bill_keys)?;
                data.validate()?;
                (
                    data.endorser.node_id(),
                    data.signatory.map(|s| s.node_id),
                    Some(BillAction::Mint(data.endorsee.into(), data.sum)),
                )
            }
            RequestToAccept => {
                let data: BillRequestToAcceptBlockData = self.get_decrypted_block(bill_keys)?;
                data.validate()?;
                (
                    data.requester.node_id(),
                    data.signatory.map(|s| s.node_id),
                    Some(BillAction::RequestAcceptance(
                        data.acceptance_deadline_timestamp,
                    )),
                )
            }
            Accept => {
                let data: BillAcceptBlockData = self.get_decrypted_block(bill_keys)?;
                data.validate()?;
                (
                    data.accepter.node_id,
                    data.signatory.map(|s| s.node_id),
                    Some(BillAction::Accept),
                )
            }
            RequestToPay => {
                let data: BillRequestToPayBlockData = self.get_decrypted_block(bill_keys)?;
                data.validate()?;
                (
                    data.requester.node_id(),
                    data.signatory.map(|s| s.node_id),
                    Some(BillAction::RequestToPay(
                        data.currency,
                        data.payment_deadline_timestamp,
                    )),
                )
            }
            OfferToSell => {
                let data: BillOfferToSellBlockData = self.get_decrypted_block(bill_keys)?;
                data.validate()?;
                (
                    data.seller.node_id(),
                    data.signatory.map(|s| s.node_id),
                    Some(BillAction::OfferToSell(
                        data.buyer.into(),
                        data.sum,
                        data.buying_deadline_timestamp,
                    )),
                )
            }
            Sell => {
                let data: BillSellBlockData = self.get_decrypted_block(bill_keys)?;
                data.validate()?;
                (
                    data.seller.node_id(),
                    data.signatory.map(|s| s.node_id),
                    Some(BillAction::Sell(
                        data.buyer.into(),
                        data.sum,
                        data.payment_address,
                    )),
                )
            }
            RejectToAccept => {
                let data: BillRejectBlockData = self.get_decrypted_block(bill_keys)?;
                data.validate()?;
                (
                    data.rejecter.node_id,
                    data.signatory.map(|s| s.node_id),
                    Some(BillAction::RejectAcceptance),
                )
            }
            RejectToBuy => {
                let data: BillRejectToBuyBlockData = self.get_decrypted_block(bill_keys)?;
                data.validate()?;
                (
                    data.rejecter.node_id(),
                    data.signatory.map(|s| s.node_id),
                    Some(BillAction::RejectBuying),
                )
            }
            RejectToPay => {
                let data: BillRejectBlockData = self.get_decrypted_block(bill_keys)?;
                data.validate()?;
                (
                    data.rejecter.node_id,
                    data.signatory.map(|s| s.node_id),
                    Some(BillAction::RejectPayment),
                )
            }
            RejectToPayRecourse => {
                let data: BillRejectBlockData = self.get_decrypted_block(bill_keys)?;
                data.validate()?;
                (
                    data.rejecter.node_id,
                    data.signatory.map(|s| s.node_id),
                    Some(BillAction::RejectPaymentForRecourse),
                )
            }
            RequestRecourse => {
                let data: BillRequestRecourseBlockData = self.get_decrypted_block(bill_keys)?;
                let reason = match data.recourse_reason {
                    BillRecourseReasonBlockData::Pay => RecourseReason::Pay(data.sum.clone()),
                    BillRecourseReasonBlockData::Accept => RecourseReason::Accept,
                };
                data.validate()?;
                (
                    data.recourser.node_id(),
                    data.signatory.map(|s| s.node_id),
                    Some(BillAction::RequestRecourse(
                        data.recoursee.into(),
                        reason,
                        data.recourse_deadline_timestamp,
                    )),
                )
            }
            Recourse => {
                let data: BillRecourseBlockData = self.get_decrypted_block(bill_keys)?;
                let reason = match data.recourse_reason {
                    BillRecourseReasonBlockData::Pay => RecourseReason::Pay(data.sum.clone()),
                    BillRecourseReasonBlockData::Accept => RecourseReason::Accept,
                };
                data.validate()?;
                (
                    data.recourser.node_id(),
                    data.signatory.map(|s| s.node_id),
                    Some(BillAction::Recourse(
                        data.recoursee.into(),
                        data.sum,
                        reason,
                    )),
                )
            }
        };
        if !self.verify_signer(&signer, &signatory, bill_keys)? {
            return Err(Error::BlockSignatureDoesNotMatchSigner);
        }

        Ok((signer, bill_action))
    }

    fn verify_signer(
        &self,
        signer: &NodeId,
        signatory: &Option<NodeId>,
        bill_keys: &BillKeys,
    ) -> Result<bool> {
        let mut keys: Vec<PublicKey> = vec![];
        // if there is a company signatory, add that key first, since it's the identity key
        if let Some(signatory) = signatory {
            keys.push(signatory.pub_key());
        }
        // then, add the signer key
        keys.push(signer.pub_key());
        // finally, add the bill key
        keys.push(BcrKeys::try_from(bill_keys)?.pub_key());
        let aggregated_public_key = match crypto::combine_pub_keys(&keys) {
            Ok(res) => res,
            Err(e) => {
                error!(
                    "Error while aggregating keys for block id {}: {e}",
                    self.id()
                );
                return Ok(false);
            }
        };
        match crypto::verify(self.hash(), self.signature(), &aggregated_public_key) {
            Err(e) => {
                error!("Error while verifying block id {}: {e}", self.id());
                Ok(false)
            }
            Ok(res) => Ok(res),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{
        address::Address,
        blockchain::bill::tests::get_baseline_identity,
        constants::DAY_IN_SECS,
        country::Country,
        tests::tests::{
            VALID_PAYMENT_ADDRESS_TESTNET, bill_id_test, bill_identified_participant_only_node_id,
            bill_participant_only_node_id, empty_bill_identified_participant, empty_bitcredit_bill,
            get_bill_keys, node_id_test, node_id_test_other, private_key_test, valid_address,
        },
        zip::Zip,
    };
    use rstest::rstest;

    fn get_first_block() -> BillBlock {
        let mut bill = empty_bitcredit_bill();
        bill.id = bill_id_test();
        let mut drawer = empty_bill_identified_participant();
        let node_id = NodeId::new(BcrKeys::new().pub_key(), bitcoin::Network::Testnet);
        let mut payer = empty_bill_identified_participant();
        let payer_node_id = NodeId::new(BcrKeys::new().pub_key(), bitcoin::Network::Testnet);
        payer.node_id = payer_node_id.clone();
        drawer.node_id = node_id.clone();

        bill.drawer = drawer.clone();
        bill.payee = BillParticipant::Ident(drawer.clone());
        bill.drawee = payer;

        BillBlock::create_block_for_issue(
            bill_id_test(),
            String::from("prevhash"),
            &BillIssueBlockData::from(bill, None, 1731593928),
            &get_baseline_identity().key_pair,
            None,
            &BcrKeys::from_private_key(&get_bill_keys().private_key).unwrap(),
            1731593928,
        )
        .unwrap()
    }

    #[test]
    fn test_plaintext_hash() {
        let bill = empty_bitcredit_bill();
        let bill_keys = BcrKeys::new();
        let block = BillBlock::create_block_for_issue(
            bill_id_test(),
            String::from("genesis"),
            &BillIssueBlockData::from(bill, None, 1731593928),
            &BcrKeys::new(),
            None,
            &bill_keys,
            1731593928,
        )
        .unwrap();
        assert!(block.verify());
        assert!(block.validate_plaintext_hash(&bill_keys.get_private_key()));
    }

    #[test]
    fn signature_can_be_verified() {
        let block = BillBlock::new(
            bill_id_test(),
            1,
            String::from("prevhash"),
            String::from("some_data"),
            BillOpCode::Issue,
            &BcrKeys::new(),
            None,
            &BcrKeys::new(),
            1731593928,
            String::from("some plaintext hash"),
        )
        .unwrap();
        assert!(block.verify());
    }

    #[test]
    fn get_nodes_from_block_issue() {
        let mut bill = empty_bitcredit_bill();
        let mut drawer = empty_bill_identified_participant();
        let node_id = NodeId::new(BcrKeys::new().pub_key(), bitcoin::Network::Testnet);
        let mut payer = empty_bill_identified_participant();
        let payer_node_id = NodeId::new(BcrKeys::new().pub_key(), bitcoin::Network::Testnet);
        payer.node_id = payer_node_id.clone();
        drawer.node_id = node_id.clone();
        bill.drawer = drawer.clone();
        bill.payee = BillParticipant::Ident(drawer.clone());
        bill.drawee = payer;

        let block = BillBlock::create_block_for_issue(
            bill_id_test(),
            String::from("prevhash"),
            &BillIssueBlockData::from(bill, None, 1731593928),
            &BcrKeys::new(),
            None,
            &BcrKeys::from_private_key(&get_bill_keys().private_key).unwrap(),
            1731593928,
        )
        .unwrap();
        let res = block.get_nodes_from_block(&get_bill_keys());
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().len(), 2);
        assert!(res.as_ref().unwrap().contains(&node_id));
        assert!(res.as_ref().unwrap().contains(&payer_node_id));
    }

    #[test]
    fn get_nodes_from_block_endorse() {
        let node_id = NodeId::new(BcrKeys::new().pub_key(), bitcoin::Network::Testnet);
        let endorsee = bill_participant_only_node_id(node_id.clone());
        let endorser = bill_participant_only_node_id(get_baseline_identity().identity.node_id);
        let block = BillBlock::create_block_for_endorse(
            bill_id_test(),
            &get_first_block(),
            &BillEndorseBlockData {
                endorser: endorser.clone().into(),
                endorsee: endorsee.into(),
                signatory: None,
                signing_timestamp: 1731593928,
                signing_address: Some(valid_address()),
            },
            &get_baseline_identity().key_pair,
            None,
            &BcrKeys::from_private_key(&private_key_test()).unwrap(),
            1731593928,
        )
        .unwrap();
        let res = block.get_nodes_from_block(&get_bill_keys());
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().len(), 2);
        assert!(res.as_ref().unwrap().contains(&node_id));
        assert!(res.as_ref().unwrap().contains(&endorser.node_id()));
    }

    #[test]
    fn get_nodes_from_block_mint() {
        let node_id = NodeId::new(BcrKeys::new().pub_key(), bitcoin::Network::Testnet);
        let mint = bill_participant_only_node_id(node_id.clone());
        let minter_node_id = NodeId::new(BcrKeys::new().pub_key(), bitcoin::Network::Testnet);
        let minter = bill_participant_only_node_id(minter_node_id.clone());
        let block = BillBlock::create_block_for_mint(
            bill_id_test(),
            &get_first_block(),
            &BillMintBlockData {
                endorser: minter.clone().into(),
                endorsee: mint.into(),
                sum: Sum::new_sat(5000).expect("sat works"),
                signatory: None,
                signing_timestamp: 1731593928,
                signing_address: Some(valid_address()),
            },
            &get_baseline_identity().key_pair,
            None,
            &BcrKeys::from_private_key(&private_key_test()).unwrap(),
            1731593928,
        )
        .unwrap();
        let res = block.get_nodes_from_block(&get_bill_keys());
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().len(), 2);
        assert!(res.as_ref().unwrap().contains(&node_id));
        assert!(res.as_ref().unwrap().contains(&minter_node_id));
    }

    #[test]
    fn get_nodes_from_block_req_to_accept() {
        let node_id = NodeId::new(BcrKeys::new().pub_key(), bitcoin::Network::Testnet);
        let requester = bill_participant_only_node_id(node_id.clone());

        let block = BillBlock::create_block_for_request_to_accept(
            bill_id_test(),
            &get_first_block(),
            &BillRequestToAcceptBlockData {
                requester: requester.clone().into(),
                signatory: None,
                signing_timestamp: 1731593928,
                signing_address: Some(valid_address()),
                acceptance_deadline_timestamp: 1731593928 + 2 * ACCEPT_DEADLINE_SECONDS,
            },
            &get_baseline_identity().key_pair,
            None,
            &BcrKeys::from_private_key(&private_key_test()).unwrap(),
            1731593928,
        )
        .unwrap();
        let res = block.get_nodes_from_block(&get_bill_keys());
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().len(), 1);
        assert!(res.as_ref().unwrap().contains(&node_id));
    }

    #[test]
    fn get_nodes_from_block_accept() {
        let mut accepter = empty_bill_identified_participant();
        let node_id = NodeId::new(BcrKeys::new().pub_key(), bitcoin::Network::Testnet);
        accepter.node_id = node_id.clone();
        accepter.postal_address = PostalAddress {
            country: Country::AT,
            city: City::new("Vienna").unwrap(),
            zip: Some(Zip::new("1020").unwrap()),
            address: Address::new("Hayekweg 12").unwrap(),
        };

        let block = BillBlock::create_block_for_accept(
            bill_id_test(),
            &get_first_block(),
            &BillAcceptBlockData {
                accepter: accepter.clone().into(),
                signatory: None,
                signing_timestamp: 1731593928,
                signing_address: accepter.postal_address,
            },
            &get_baseline_identity().key_pair,
            None,
            &BcrKeys::from_private_key(&private_key_test()).unwrap(),
            1731593928,
        )
        .unwrap();
        let res = block.get_nodes_from_block(&get_bill_keys());
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().len(), 1);
        assert!(res.as_ref().unwrap().contains(&node_id));
    }

    #[test]
    fn get_nodes_from_block_req_to_pay() {
        let node_id = NodeId::new(BcrKeys::new().pub_key(), bitcoin::Network::Testnet);
        let requester = bill_participant_only_node_id(node_id.clone());

        let block = BillBlock::create_block_for_request_to_pay(
            bill_id_test(),
            &get_first_block(),
            &BillRequestToPayBlockData {
                requester: requester.clone().into(),
                currency: Currency::sat(),
                signatory: None,
                signing_timestamp: 1731593928,
                signing_address: Some(valid_address()),
                payment_deadline_timestamp: 1731593928 + 2 * PAYMENT_DEADLINE_SECONDS,
            },
            &get_baseline_identity().key_pair,
            None,
            &BcrKeys::from_private_key(&private_key_test()).unwrap(),
            1731593928,
        )
        .unwrap();
        let res = block.get_nodes_from_block(&get_bill_keys());
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().len(), 1);
        assert!(res.as_ref().unwrap().contains(&node_id));
    }

    #[test]
    fn get_nodes_from_block_offer_to_sell() {
        let node_id = NodeId::new(BcrKeys::new().pub_key(), bitcoin::Network::Testnet);
        let buyer = bill_participant_only_node_id(node_id.clone());
        let seller_node_id = get_baseline_identity().identity.node_id;
        let seller = bill_participant_only_node_id(seller_node_id.clone());
        let block = BillBlock::create_block_for_offer_to_sell(
            bill_id_test(),
            &get_first_block(),
            &BillOfferToSellBlockData {
                buyer: buyer.clone().into(),
                seller: seller.clone().into(),
                sum: Sum::new_sat(5000).expect("sat works"),
                payment_address: VALID_PAYMENT_ADDRESS_TESTNET.to_string(),
                signatory: None,
                signing_timestamp: 1731593928,
                signing_address: Some(valid_address()),
                buying_deadline_timestamp: 1731593928 + 2 * DAY_IN_SECS,
            },
            &get_baseline_identity().key_pair,
            None,
            &BcrKeys::from_private_key(&private_key_test()).unwrap(),
            1731593928,
        )
        .unwrap();
        let res = block.get_nodes_from_block(&get_bill_keys());
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().len(), 2);
        assert!(res.as_ref().unwrap().contains(&node_id));
        assert!(res.as_ref().unwrap().contains(&seller_node_id));
    }

    #[test]
    fn get_nodes_from_block_sell() {
        let node_id = NodeId::new(BcrKeys::new().pub_key(), bitcoin::Network::Testnet);
        let buyer = bill_participant_only_node_id(node_id.clone());
        let seller_node_id = get_baseline_identity().identity.node_id;
        let seller = bill_participant_only_node_id(seller_node_id.clone());
        let block = BillBlock::create_block_for_sell(
            bill_id_test(),
            &get_first_block(),
            &BillSellBlockData {
                buyer: buyer.clone().into(),
                seller: seller.clone().into(),
                sum: Sum::new_sat(5000).expect("sat works"),
                payment_address: VALID_PAYMENT_ADDRESS_TESTNET.to_string(),
                signatory: Some(BillSignatoryBlockData {
                    node_id: buyer.node_id().clone(),
                    name: Name::new("some name").unwrap(),
                }),
                signing_timestamp: 1731593928,
                signing_address: Some(valid_address()),
            },
            &get_baseline_identity().key_pair,
            None,
            &BcrKeys::from_private_key(&private_key_test()).unwrap(),
            1731593928,
        )
        .unwrap();
        let res = block.get_nodes_from_block(&get_bill_keys());
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().len(), 2);
        assert!(res.as_ref().unwrap().contains(&node_id));
        assert!(res.as_ref().unwrap().contains(&seller_node_id));
    }

    #[test]
    fn get_nodes_from_block_reject_to_accept() {
        let rejecter = bill_identified_participant_only_node_id(NodeId::new(
            BcrKeys::new().pub_key(),
            bitcoin::Network::Testnet,
        ));
        let block = BillBlock::create_block_for_reject_to_accept(
            bill_id_test(),
            &get_first_block(),
            &BillRejectBlockData {
                rejecter: rejecter.clone().into(),
                signatory: None,
                signing_timestamp: 1731593928,
                signing_address: rejecter.postal_address,
            },
            &get_baseline_identity().key_pair,
            None,
            &BcrKeys::from_private_key(&private_key_test()).unwrap(),
            1731593928,
        )
        .unwrap();
        let res = block.get_nodes_from_block(&get_bill_keys());
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().len(), 1);
        assert!(res.as_ref().unwrap().contains(&rejecter.node_id));
    }

    #[test]
    fn get_nodes_from_block_reject_to_pay() {
        let rejecter = bill_identified_participant_only_node_id(NodeId::new(
            BcrKeys::new().pub_key(),
            bitcoin::Network::Testnet,
        ));
        let block = BillBlock::create_block_for_reject_to_pay(
            bill_id_test(),
            &get_first_block(),
            &BillRejectBlockData {
                rejecter: rejecter.clone().into(),
                signatory: None,
                signing_timestamp: 1731593928,
                signing_address: rejecter.postal_address,
            },
            &get_baseline_identity().key_pair,
            None,
            &BcrKeys::from_private_key(&private_key_test()).unwrap(),
            1731593928,
        )
        .unwrap();
        let res = block.get_nodes_from_block(&get_bill_keys());
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().len(), 1);
        assert!(res.as_ref().unwrap().contains(&rejecter.node_id));
    }

    #[test]
    fn get_nodes_from_block_reject_to_buy() {
        let rejecter = bill_identified_participant_only_node_id(NodeId::new(
            BcrKeys::new().pub_key(),
            bitcoin::Network::Testnet,
        ));
        let block = BillBlock::create_block_for_reject_to_buy(
            bill_id_test(),
            &get_first_block(),
            &BillRejectToBuyBlockData {
                rejecter: BillParticipant::Ident(rejecter.clone()).into(),
                signatory: None,
                signing_timestamp: 1731593928,
                signing_address: Some(rejecter.postal_address),
            },
            &get_baseline_identity().key_pair,
            None,
            &BcrKeys::from_private_key(&private_key_test()).unwrap(),
            1731593928,
        )
        .unwrap();
        let res = block.get_nodes_from_block(&get_bill_keys());
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().len(), 1);
        assert!(res.as_ref().unwrap().contains(&rejecter.node_id));
    }

    #[test]
    fn get_nodes_from_block_reject_to_pay_recourse() {
        let rejecter = bill_identified_participant_only_node_id(NodeId::new(
            BcrKeys::new().pub_key(),
            bitcoin::Network::Testnet,
        ));
        let block = BillBlock::create_block_for_reject_to_pay_recourse(
            bill_id_test(),
            &get_first_block(),
            &BillRejectBlockData {
                rejecter: rejecter.clone().into(),
                signatory: None,
                signing_timestamp: 1731593928,
                signing_address: rejecter.postal_address,
            },
            &get_baseline_identity().key_pair,
            None,
            &BcrKeys::from_private_key(&private_key_test()).unwrap(),
            1731593928,
        )
        .unwrap();
        let res = block.get_nodes_from_block(&get_bill_keys());
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().len(), 1);
        assert!(res.as_ref().unwrap().contains(&rejecter.node_id));
    }

    #[test]
    fn get_nodes_from_block_request_recourse() {
        let recoursee = bill_identified_participant_only_node_id(NodeId::new(
            BcrKeys::new().pub_key(),
            bitcoin::Network::Testnet,
        ));
        let recourser = bill_identified_participant_only_node_id(NodeId::new(
            BcrKeys::new().pub_key(),
            bitcoin::Network::Testnet,
        ));
        let block = BillBlock::create_block_for_request_recourse(
            bill_id_test(),
            &get_first_block(),
            &BillRequestRecourseBlockData {
                recourser: BillParticipant::Ident(recourser.clone()).into(),
                recoursee: recoursee.clone().into(),
                sum: Sum::new_sat(15000).expect("sat works"),
                recourse_reason: BillRecourseReasonBlockData::Pay,
                signatory: None,
                signing_timestamp: 1731593928,
                signing_address: Some(recourser.postal_address),
                recourse_deadline_timestamp: 1731593928 + 2 * RECOURSE_DEADLINE_SECONDS,
            },
            &get_baseline_identity().key_pair,
            None,
            &BcrKeys::from_private_key(&private_key_test()).unwrap(),
            1731593928,
        )
        .unwrap();
        let res = block.get_nodes_from_block(&get_bill_keys());
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().len(), 2);
        assert!(res.as_ref().unwrap().contains(&recourser.node_id));
        assert!(res.as_ref().unwrap().contains(&recoursee.node_id));
    }

    #[test]
    fn get_nodes_from_block_recourse() {
        let recoursee = bill_identified_participant_only_node_id(NodeId::new(
            BcrKeys::new().pub_key(),
            bitcoin::Network::Testnet,
        ));
        let recourser = bill_identified_participant_only_node_id(NodeId::new(
            BcrKeys::new().pub_key(),
            bitcoin::Network::Testnet,
        ));
        let block = BillBlock::create_block_for_recourse(
            bill_id_test(),
            &get_first_block(),
            &BillRecourseBlockData {
                recourser: BillParticipant::Ident(recourser.clone()).into(),
                recoursee: recoursee.clone().into(),
                sum: Sum::new_sat(15000).expect("sat works"),
                recourse_reason: BillRecourseReasonBlockData::Pay,
                signatory: None,
                signing_timestamp: 1731593928,
                signing_address: Some(recourser.postal_address),
            },
            &get_baseline_identity().key_pair,
            None,
            &BcrKeys::from_private_key(&private_key_test()).unwrap(),
            1731593928,
        )
        .unwrap();
        let res = block.get_nodes_from_block(&get_bill_keys());
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().len(), 2);
        assert!(res.as_ref().unwrap().contains(&recourser.node_id));
        assert!(res.as_ref().unwrap().contains(&recoursee.node_id));
    }

    #[test]
    fn verify_and_get_signer_baseline() {
        let bill_keys = BcrKeys::new();
        let identity_keys = BcrKeys::new();
        let bill_keys_obj = BillKeys {
            private_key: bill_keys.get_private_key(),
            public_key: bill_keys.pub_key(),
        };

        let mut bill = empty_bitcredit_bill();
        let signer = bill_identified_participant_only_node_id(NodeId::new(
            identity_keys.pub_key(),
            bitcoin::Network::Testnet,
        ));
        let other_party = bill_identified_participant_only_node_id(NodeId::new(
            BcrKeys::new().pub_key(),
            bitcoin::Network::Testnet,
        ));
        bill.drawer = signer.clone();
        bill.drawee = signer.clone();
        bill.payee = BillParticipant::Ident(other_party.clone());

        let issue_block = BillBlock::create_block_for_issue(
            bill_id_test(),
            String::from("genesis"),
            &BillIssueBlockData::from(bill, None, 1731593928),
            &identity_keys,
            None,
            &bill_keys,
            1731593928,
        )
        .unwrap();
        let issue_result = issue_block.verify_and_get_signer(&bill_keys_obj);
        assert!(issue_result.is_ok());
        assert_eq!(
            issue_result.as_ref().unwrap().0,
            NodeId::new(identity_keys.pub_key(), bitcoin::Network::Testnet)
        );
        assert!(issue_result.as_ref().unwrap().1.is_none());
        assert!(issue_block.validate_plaintext_hash(&bill_keys.get_private_key()));

        let endorse_block = BillBlock::create_block_for_endorse(
            bill_id_test(),
            &issue_block,
            &BillEndorseBlockData {
                endorser: BillParticipant::Ident(signer.clone()).into(),
                endorsee: BillParticipant::Ident(other_party.clone()).into(),
                signatory: None,
                signing_timestamp: 1731593928,
                signing_address: Some(signer.postal_address.clone()),
            },
            &identity_keys,
            None,
            &bill_keys,
            1731593928,
        )
        .unwrap();
        let endorse_result = endorse_block.verify_and_get_signer(&bill_keys_obj);
        assert!(endorse_result.is_ok());
        assert_eq!(
            endorse_result.as_ref().unwrap().0,
            NodeId::new(identity_keys.pub_key(), bitcoin::Network::Testnet)
        );
        assert!(matches!(
            endorse_result.as_ref().unwrap().1,
            Some(BillAction::Endorse(_))
        ));
        assert!(endorse_block.validate_plaintext_hash(&bill_keys.get_private_key()));

        let mint_block = BillBlock::create_block_for_mint(
            bill_id_test(),
            &issue_block,
            &BillMintBlockData {
                endorser: BillParticipant::Ident(signer.clone()).into(),
                endorsee: BillParticipant::Ident(other_party.clone()).into(),
                sum: Sum::new_sat(5000).expect("sat works"),
                signatory: None,
                signing_timestamp: 1731593928,
                signing_address: Some(signer.postal_address.clone()),
            },
            &identity_keys,
            None,
            &bill_keys,
            1731593928,
        )
        .unwrap();
        let mint_result = mint_block.verify_and_get_signer(&bill_keys_obj);
        assert!(mint_result.is_ok());
        assert_eq!(
            mint_result.as_ref().unwrap().0,
            NodeId::new(identity_keys.pub_key(), bitcoin::Network::Testnet)
        );
        assert!(matches!(
            mint_result.as_ref().unwrap().1,
            Some(BillAction::Mint(_, _))
        ));
        assert!(mint_block.validate_plaintext_hash(&bill_keys.get_private_key()));

        let req_to_accept_block = BillBlock::create_block_for_request_to_accept(
            bill_id_test(),
            &issue_block,
            &BillRequestToAcceptBlockData {
                requester: BillParticipant::Ident(signer.clone()).into(),
                signatory: None,
                signing_timestamp: 1731593928,
                signing_address: Some(signer.postal_address.clone()),
                acceptance_deadline_timestamp: 1731593928 + 2 * ACCEPT_DEADLINE_SECONDS,
            },
            &identity_keys,
            None,
            &bill_keys,
            1731593928,
        )
        .unwrap();
        let req_to_accept_result = req_to_accept_block.verify_and_get_signer(&bill_keys_obj);
        assert!(req_to_accept_result.is_ok());
        assert_eq!(
            req_to_accept_result.as_ref().unwrap().0,
            NodeId::new(identity_keys.pub_key(), bitcoin::Network::Testnet)
        );
        assert!(matches!(
            req_to_accept_result.as_ref().unwrap().1,
            Some(BillAction::RequestAcceptance(_))
        ));
        assert!(req_to_accept_block.validate_plaintext_hash(&bill_keys.get_private_key()));

        let req_to_pay_block = BillBlock::create_block_for_request_to_pay(
            bill_id_test(),
            &issue_block,
            &BillRequestToPayBlockData {
                requester: BillParticipant::Ident(signer.clone()).into(),
                currency: Currency::sat(),
                signatory: None,
                signing_timestamp: 1731593928,
                signing_address: Some(signer.postal_address.clone()),
                payment_deadline_timestamp: 1731593928 + 2 * PAYMENT_DEADLINE_SECONDS,
            },
            &identity_keys,
            None,
            &bill_keys,
            1731593928,
        )
        .unwrap();
        let req_to_pay_result = req_to_pay_block.verify_and_get_signer(&bill_keys_obj);
        assert!(req_to_pay_result.is_ok());
        assert_eq!(
            req_to_pay_result.as_ref().unwrap().0,
            NodeId::new(identity_keys.pub_key(), bitcoin::Network::Testnet)
        );
        assert!(matches!(
            req_to_pay_result.as_ref().unwrap().1,
            Some(BillAction::RequestToPay(_, _))
        ));
        assert!(req_to_pay_block.validate_plaintext_hash(&bill_keys.get_private_key()));

        let accept_block = BillBlock::create_block_for_accept(
            bill_id_test(),
            &issue_block,
            &BillAcceptBlockData {
                accepter: signer.clone().into(),
                signatory: None,
                signing_timestamp: 1731593928,
                signing_address: signer.postal_address.clone(),
            },
            &identity_keys,
            None,
            &bill_keys,
            1731593928,
        )
        .unwrap();
        let accept_result = accept_block.verify_and_get_signer(&bill_keys_obj);
        assert!(accept_result.is_ok());
        assert_eq!(
            accept_result.as_ref().unwrap().0,
            NodeId::new(identity_keys.pub_key(), bitcoin::Network::Testnet)
        );
        assert!(matches!(
            accept_result.as_ref().unwrap().1,
            Some(BillAction::Accept)
        ));
        assert!(accept_block.validate_plaintext_hash(&bill_keys.get_private_key()));

        let offer_to_sell_block = BillBlock::create_block_for_offer_to_sell(
            bill_id_test(),
            &issue_block,
            &BillOfferToSellBlockData {
                seller: BillParticipant::Ident(signer.clone()).into(),
                buyer: BillParticipant::Ident(other_party.clone()).into(),
                sum: Sum::new_sat(5000).expect("sat works"),
                payment_address: VALID_PAYMENT_ADDRESS_TESTNET.to_string(),
                signatory: None,
                signing_timestamp: 1731593928,
                signing_address: Some(signer.postal_address.clone()),
                buying_deadline_timestamp: 1731593928 + 2 * DAY_IN_SECS,
            },
            &identity_keys,
            None,
            &bill_keys,
            1731593928,
        )
        .unwrap();
        let offer_to_sell_result = offer_to_sell_block.verify_and_get_signer(&bill_keys_obj);
        assert!(offer_to_sell_result.is_ok());
        assert_eq!(
            offer_to_sell_result.as_ref().unwrap().0,
            NodeId::new(identity_keys.pub_key(), bitcoin::Network::Testnet)
        );
        assert!(matches!(
            offer_to_sell_result.as_ref().unwrap().1,
            Some(BillAction::OfferToSell(_, _, _))
        ));
        assert!(offer_to_sell_block.validate_plaintext_hash(&bill_keys.get_private_key()));

        let sell_block = BillBlock::create_block_for_sell(
            bill_id_test(),
            &issue_block,
            &BillSellBlockData {
                seller: BillParticipant::Ident(signer.clone()).into(),
                buyer: BillParticipant::Ident(other_party.clone()).into(),
                sum: Sum::new_sat(5000).expect("sat works"),
                payment_address: VALID_PAYMENT_ADDRESS_TESTNET.to_string(),
                signatory: None,
                signing_timestamp: 1731593928,
                signing_address: Some(signer.postal_address.clone()),
            },
            &identity_keys,
            None,
            &bill_keys,
            1731593928,
        )
        .unwrap();
        let sell_result = sell_block.verify_and_get_signer(&bill_keys_obj);
        assert!(sell_result.is_ok());
        assert_eq!(
            sell_result.as_ref().unwrap().0,
            NodeId::new(identity_keys.pub_key(), bitcoin::Network::Testnet)
        );
        assert!(matches!(
            sell_result.as_ref().unwrap().1,
            Some(BillAction::Sell(_, _, _))
        ));
        assert!(sell_block.validate_plaintext_hash(&bill_keys.get_private_key()));

        let reject_to_accept_block = BillBlock::create_block_for_reject_to_accept(
            bill_id_test(),
            &issue_block,
            &BillRejectBlockData {
                rejecter: signer.clone().into(),
                signatory: None,
                signing_timestamp: 1731593928,
                signing_address: signer.postal_address.clone(),
            },
            &identity_keys,
            None,
            &bill_keys,
            1731593928,
        )
        .unwrap();
        let reject_to_accept_result = reject_to_accept_block.verify_and_get_signer(&bill_keys_obj);
        assert!(reject_to_accept_result.is_ok());
        assert_eq!(
            reject_to_accept_result.as_ref().unwrap().0,
            NodeId::new(identity_keys.pub_key(), bitcoin::Network::Testnet)
        );
        assert!(matches!(
            reject_to_accept_result.as_ref().unwrap().1,
            Some(BillAction::RejectAcceptance)
        ));
        assert!(reject_to_accept_block.validate_plaintext_hash(&bill_keys.get_private_key()));

        let reject_to_buy_block = BillBlock::create_block_for_reject_to_buy(
            bill_id_test(),
            &issue_block,
            &BillRejectToBuyBlockData {
                rejecter: BillParticipant::Ident(signer.clone()).into(),
                signatory: None,
                signing_timestamp: 1731593928,
                signing_address: Some(signer.postal_address.clone()),
            },
            &identity_keys,
            None,
            &bill_keys,
            1731593928,
        )
        .unwrap();
        let reject_to_buy_result = reject_to_buy_block.verify_and_get_signer(&bill_keys_obj);
        assert!(reject_to_buy_result.is_ok());
        assert_eq!(
            reject_to_buy_result.as_ref().unwrap().0,
            NodeId::new(identity_keys.pub_key(), bitcoin::Network::Testnet)
        );
        assert!(matches!(
            reject_to_buy_result.as_ref().unwrap().1,
            Some(BillAction::RejectBuying)
        ));
        assert!(reject_to_buy_block.validate_plaintext_hash(&bill_keys.get_private_key()));

        let reject_to_pay_block = BillBlock::create_block_for_reject_to_pay(
            bill_id_test(),
            &issue_block,
            &BillRejectBlockData {
                rejecter: signer.clone().into(),
                signatory: None,
                signing_timestamp: 1731593928,
                signing_address: signer.postal_address.clone(),
            },
            &identity_keys,
            None,
            &bill_keys,
            1731593928,
        )
        .unwrap();
        let reject_to_pay_result = reject_to_pay_block.verify_and_get_signer(&bill_keys_obj);
        assert!(reject_to_pay_result.is_ok());
        assert_eq!(
            reject_to_pay_result.as_ref().unwrap().0,
            NodeId::new(identity_keys.pub_key(), bitcoin::Network::Testnet)
        );
        assert!(matches!(
            reject_to_pay_result.as_ref().unwrap().1,
            Some(BillAction::RejectPayment)
        ));
        assert!(reject_to_pay_block.validate_plaintext_hash(&bill_keys.get_private_key()));

        let reject_to_pay_recourse_block = BillBlock::create_block_for_reject_to_pay_recourse(
            bill_id_test(),
            &issue_block,
            &BillRejectBlockData {
                rejecter: signer.clone().into(),
                signatory: None,
                signing_timestamp: 1731593928,
                signing_address: signer.postal_address.clone(),
            },
            &identity_keys,
            None,
            &bill_keys,
            1731593928,
        )
        .unwrap();
        let reject_to_pay_recourse_result =
            reject_to_pay_recourse_block.verify_and_get_signer(&bill_keys_obj);
        assert!(reject_to_pay_recourse_result.is_ok());
        assert_eq!(
            reject_to_pay_recourse_result.as_ref().unwrap().0,
            NodeId::new(identity_keys.pub_key(), bitcoin::Network::Testnet)
        );
        assert!(matches!(
            reject_to_pay_recourse_result.as_ref().unwrap().1,
            Some(BillAction::RejectPaymentForRecourse)
        ));
        assert!(reject_to_pay_recourse_block.validate_plaintext_hash(&bill_keys.get_private_key()));

        let request_recourse_block = BillBlock::create_block_for_request_recourse(
            bill_id_test(),
            &issue_block,
            &BillRequestRecourseBlockData {
                recourser: BillParticipant::Ident(signer.clone()).into(),
                recoursee: other_party.clone().into(),
                sum: Sum::new_sat(15000).expect("sat works"),
                recourse_reason: BillRecourseReasonBlockData::Accept,
                signatory: None,
                signing_timestamp: 1731593928,
                signing_address: Some(signer.postal_address.clone()),
                recourse_deadline_timestamp: 1731593928 + 2 * RECOURSE_DEADLINE_SECONDS,
            },
            &identity_keys,
            None,
            &bill_keys,
            1731593928,
        )
        .unwrap();
        let request_recourse_result = request_recourse_block.verify_and_get_signer(&bill_keys_obj);
        assert!(request_recourse_result.is_ok());
        assert_eq!(
            request_recourse_result.as_ref().unwrap().0,
            NodeId::new(identity_keys.pub_key(), bitcoin::Network::Testnet)
        );
        assert!(matches!(
            request_recourse_result.as_ref().unwrap().1,
            Some(BillAction::RequestRecourse(_, _, _))
        ));
        assert!(request_recourse_block.validate_plaintext_hash(&bill_keys.get_private_key()));

        let recourse_block = BillBlock::create_block_for_recourse(
            bill_id_test(),
            &issue_block,
            &BillRecourseBlockData {
                recourser: BillParticipant::Ident(signer.clone()).into(),
                recoursee: other_party.clone().into(),
                sum: Sum::new_sat(15000).expect("sat works"),
                recourse_reason: BillRecourseReasonBlockData::Pay,
                signatory: None,
                signing_timestamp: 1731593928,
                signing_address: Some(signer.postal_address.clone()),
            },
            &identity_keys,
            None,
            &bill_keys,
            1731593928,
        )
        .unwrap();
        let recourse_result = recourse_block.verify_and_get_signer(&bill_keys_obj);
        assert!(recourse_result.is_ok());
        assert_eq!(
            recourse_result.as_ref().unwrap().0,
            NodeId::new(identity_keys.pub_key(), bitcoin::Network::Testnet)
        );
        assert!(matches!(
            recourse_result.as_ref().unwrap().1,
            Some(BillAction::Recourse(_, _, _))
        ));
        assert!(recourse_block.validate_plaintext_hash(&bill_keys.get_private_key()));
    }

    #[test]
    fn verify_and_get_signer_baseline_company() {
        let bill_keys = BcrKeys::new();
        let company_keys = BcrKeys::new();
        let identity_keys = BcrKeys::new();
        let bill_keys_obj = BillKeys {
            private_key: bill_keys.get_private_key(),
            public_key: bill_keys.pub_key(),
        };

        let mut bill = empty_bitcredit_bill();
        let signer = bill_identified_participant_only_node_id(NodeId::new(
            company_keys.pub_key(),
            bitcoin::Network::Testnet,
        ));
        let other_party = bill_identified_participant_only_node_id(NodeId::new(
            BcrKeys::new().pub_key(),
            bitcoin::Network::Testnet,
        ));
        bill.drawer = signer.clone();
        bill.drawee = signer.clone();
        bill.payee = BillParticipant::Ident(other_party.clone());

        let issue_block = BillBlock::create_block_for_issue(
            bill_id_test(),
            String::from("genesis"),
            &BillIssueBlockData::from(
                bill,
                Some(BillSignatoryBlockData {
                    node_id: NodeId::new(identity_keys.pub_key(), bitcoin::Network::Testnet),
                    name: Name::new("signatory name").unwrap(),
                }),
                1731593928,
            ),
            &identity_keys,
            Some(&company_keys),
            &bill_keys,
            1731593928,
        )
        .unwrap();

        let issue_result = issue_block.verify_and_get_signer(&bill_keys_obj);
        assert!(issue_result.is_ok());
        assert_eq!(
            issue_result.as_ref().unwrap().0,
            NodeId::new(company_keys.pub_key(), bitcoin::Network::Testnet)
        );
        assert!(issue_result.as_ref().unwrap().1.is_none());
        assert!(issue_block.validate_plaintext_hash(&bill_keys.get_private_key()));

        let endorse_block = BillBlock::create_block_for_endorse(
            bill_id_test(),
            &issue_block,
            &BillEndorseBlockData {
                endorser: BillParticipant::Ident(signer.clone()).into(),
                endorsee: BillParticipant::Ident(other_party.clone()).into(),
                signatory: Some(BillSignatoryBlockData {
                    node_id: NodeId::new(identity_keys.pub_key(), bitcoin::Network::Testnet),
                    name: Name::new("signatory name").unwrap(),
                }),
                signing_timestamp: 1731593928,
                signing_address: Some(signer.postal_address.clone()),
            },
            &identity_keys,
            Some(&company_keys),
            &bill_keys,
            1731593928,
        )
        .unwrap();
        let endorse_result = endorse_block.verify_and_get_signer(&bill_keys_obj);
        assert!(endorse_result.is_ok());
        assert_eq!(
            endorse_result.as_ref().unwrap().0,
            NodeId::new(company_keys.pub_key(), bitcoin::Network::Testnet)
        );
        assert!(matches!(
            endorse_result.as_ref().unwrap().1,
            Some(BillAction::Endorse(_))
        ));
        assert!(endorse_block.validate_plaintext_hash(&bill_keys.get_private_key()));

        let mint_block = BillBlock::create_block_for_mint(
            bill_id_test(),
            &issue_block,
            &BillMintBlockData {
                endorser: BillParticipant::Ident(signer.clone()).into(),
                endorsee: BillParticipant::Ident(other_party.clone()).into(),
                sum: Sum::new_sat(5000).expect("sat works"),
                signatory: Some(BillSignatoryBlockData {
                    node_id: NodeId::new(identity_keys.pub_key(), bitcoin::Network::Testnet),
                    name: Name::new("signatory name").unwrap(),
                }),
                signing_timestamp: 1731593928,
                signing_address: Some(signer.postal_address.clone()),
            },
            &identity_keys,
            Some(&company_keys),
            &bill_keys,
            1731593928,
        )
        .unwrap();
        let mint_result = mint_block.verify_and_get_signer(&bill_keys_obj);
        assert!(mint_result.is_ok());
        assert_eq!(
            mint_result.as_ref().unwrap().0,
            NodeId::new(company_keys.pub_key(), bitcoin::Network::Testnet)
        );
        assert!(matches!(
            mint_result.as_ref().unwrap().1,
            Some(BillAction::Mint(_, _))
        ));
        assert!(mint_block.validate_plaintext_hash(&bill_keys.get_private_key()));

        let req_to_accept_block = BillBlock::create_block_for_request_to_accept(
            bill_id_test(),
            &issue_block,
            &BillRequestToAcceptBlockData {
                requester: BillParticipant::Ident(signer.clone()).into(),
                signatory: Some(BillSignatoryBlockData {
                    node_id: NodeId::new(identity_keys.pub_key(), bitcoin::Network::Testnet),
                    name: Name::new("signatory name").unwrap(),
                }),
                signing_timestamp: 1731593928,
                signing_address: Some(signer.postal_address.clone()),
                acceptance_deadline_timestamp: 1731593928 + 2 * ACCEPT_DEADLINE_SECONDS,
            },
            &identity_keys,
            Some(&company_keys),
            &bill_keys,
            1731593928,
        )
        .unwrap();
        let req_to_accept_result = req_to_accept_block.verify_and_get_signer(&bill_keys_obj);
        assert!(req_to_accept_result.is_ok());
        assert_eq!(
            req_to_accept_result.as_ref().unwrap().0,
            NodeId::new(company_keys.pub_key(), bitcoin::Network::Testnet)
        );
        assert!(matches!(
            req_to_accept_result.as_ref().unwrap().1,
            Some(BillAction::RequestAcceptance(_))
        ));
        assert!(req_to_accept_block.validate_plaintext_hash(&bill_keys.get_private_key()));

        let req_to_pay_block = BillBlock::create_block_for_request_to_pay(
            bill_id_test(),
            &issue_block,
            &BillRequestToPayBlockData {
                requester: BillParticipant::Ident(signer.clone()).into(),
                currency: Currency::sat(),
                signatory: Some(BillSignatoryBlockData {
                    node_id: NodeId::new(identity_keys.pub_key(), bitcoin::Network::Testnet),
                    name: Name::new("signatory name").unwrap(),
                }),
                signing_timestamp: 1731593928,
                signing_address: Some(signer.postal_address.clone()),
                payment_deadline_timestamp: 1731593928 + 2 * PAYMENT_DEADLINE_SECONDS,
            },
            &identity_keys,
            Some(&company_keys),
            &bill_keys,
            1731593928,
        )
        .unwrap();
        let req_to_pay_result = req_to_pay_block.verify_and_get_signer(&bill_keys_obj);
        assert!(req_to_pay_result.is_ok());
        assert_eq!(
            req_to_pay_result.as_ref().unwrap().0,
            NodeId::new(company_keys.pub_key(), bitcoin::Network::Testnet)
        );
        assert!(matches!(
            req_to_pay_result.as_ref().unwrap().1,
            Some(BillAction::RequestToPay(_, _))
        ));
        assert!(req_to_pay_block.validate_plaintext_hash(&bill_keys.get_private_key()));

        let accept_block = BillBlock::create_block_for_accept(
            bill_id_test(),
            &issue_block,
            &BillAcceptBlockData {
                accepter: signer.clone().into(),
                signatory: Some(BillSignatoryBlockData {
                    node_id: NodeId::new(identity_keys.pub_key(), bitcoin::Network::Testnet),
                    name: Name::new("signatory name").unwrap(),
                }),
                signing_timestamp: 1731593928,
                signing_address: signer.postal_address.clone(),
            },
            &identity_keys,
            Some(&company_keys),
            &bill_keys,
            1731593928,
        )
        .unwrap();
        let accept_result = accept_block.verify_and_get_signer(&bill_keys_obj);
        assert!(accept_result.is_ok());
        assert_eq!(
            accept_result.as_ref().unwrap().0,
            NodeId::new(company_keys.pub_key(), bitcoin::Network::Testnet)
        );
        assert!(matches!(
            accept_result.as_ref().unwrap().1,
            Some(BillAction::Accept)
        ));
        assert!(accept_block.validate_plaintext_hash(&bill_keys.get_private_key()));

        let offer_to_sell_block = BillBlock::create_block_for_offer_to_sell(
            bill_id_test(),
            &issue_block,
            &BillOfferToSellBlockData {
                seller: BillParticipant::Ident(signer.clone()).into(),
                buyer: BillParticipant::Ident(other_party.clone()).into(),
                sum: Sum::new_sat(5000).expect("sat works"),
                payment_address: VALID_PAYMENT_ADDRESS_TESTNET.to_string(),
                signatory: Some(BillSignatoryBlockData {
                    node_id: NodeId::new(identity_keys.pub_key(), bitcoin::Network::Testnet),
                    name: Name::new("signatory name").unwrap(),
                }),
                signing_timestamp: 1731593928,
                signing_address: Some(signer.postal_address.clone()),
                buying_deadline_timestamp: 1731593928 + 2 * DAY_IN_SECS,
            },
            &identity_keys,
            Some(&company_keys),
            &bill_keys,
            1731593928,
        )
        .unwrap();
        let offer_to_sell_result = offer_to_sell_block.verify_and_get_signer(&bill_keys_obj);
        assert!(offer_to_sell_result.is_ok());
        assert_eq!(
            offer_to_sell_result.as_ref().unwrap().0,
            NodeId::new(company_keys.pub_key(), bitcoin::Network::Testnet)
        );
        assert!(matches!(
            offer_to_sell_result.as_ref().unwrap().1,
            Some(BillAction::OfferToSell(_, _, _))
        ));
        assert!(offer_to_sell_block.validate_plaintext_hash(&bill_keys.get_private_key()));

        let sell_block = BillBlock::create_block_for_sell(
            bill_id_test(),
            &issue_block,
            &BillSellBlockData {
                seller: BillParticipant::Ident(signer.clone()).into(),
                buyer: BillParticipant::Ident(other_party.clone()).into(),
                sum: Sum::new_sat(5000).expect("sat works"),
                payment_address: VALID_PAYMENT_ADDRESS_TESTNET.to_string(),
                signatory: Some(BillSignatoryBlockData {
                    node_id: NodeId::new(identity_keys.pub_key(), bitcoin::Network::Testnet),
                    name: Name::new("signatory name").unwrap(),
                }),
                signing_timestamp: 1731593928,
                signing_address: Some(signer.postal_address.clone()),
            },
            &identity_keys,
            Some(&company_keys),
            &bill_keys,
            1731593928,
        )
        .unwrap();
        let sell_result = sell_block.verify_and_get_signer(&bill_keys_obj);
        assert!(sell_result.is_ok());
        assert_eq!(
            sell_result.as_ref().unwrap().0,
            NodeId::new(company_keys.pub_key(), bitcoin::Network::Testnet)
        );
        assert!(matches!(
            sell_result.as_ref().unwrap().1,
            Some(BillAction::Sell(_, _, _))
        ));
        assert!(sell_block.validate_plaintext_hash(&bill_keys.get_private_key()));

        let reject_to_accept_block = BillBlock::create_block_for_reject_to_accept(
            bill_id_test(),
            &issue_block,
            &BillRejectBlockData {
                rejecter: signer.clone().into(),
                signatory: Some(BillSignatoryBlockData {
                    node_id: NodeId::new(identity_keys.pub_key(), bitcoin::Network::Testnet),
                    name: Name::new("signatory name").unwrap(),
                }),
                signing_timestamp: 1731593928,
                signing_address: signer.postal_address.clone(),
            },
            &identity_keys,
            Some(&company_keys),
            &bill_keys,
            1731593928,
        )
        .unwrap();
        let reject_to_accept_result = reject_to_accept_block.verify_and_get_signer(&bill_keys_obj);
        assert!(reject_to_accept_result.is_ok());
        assert_eq!(
            reject_to_accept_result.as_ref().unwrap().0,
            NodeId::new(company_keys.pub_key(), bitcoin::Network::Testnet)
        );
        assert!(matches!(
            reject_to_accept_result.as_ref().unwrap().1,
            Some(BillAction::RejectAcceptance)
        ));
        assert!(reject_to_accept_block.validate_plaintext_hash(&bill_keys.get_private_key()));

        let reject_to_buy_block = BillBlock::create_block_for_reject_to_buy(
            bill_id_test(),
            &issue_block,
            &BillRejectToBuyBlockData {
                rejecter: BillParticipant::Ident(signer.clone()).into(),
                signatory: Some(BillSignatoryBlockData {
                    node_id: NodeId::new(identity_keys.pub_key(), bitcoin::Network::Testnet),
                    name: Name::new("signatory name").unwrap(),
                }),
                signing_timestamp: 1731593928,
                signing_address: Some(signer.postal_address.clone()),
            },
            &identity_keys,
            Some(&company_keys),
            &bill_keys,
            1731593928,
        )
        .unwrap();
        let reject_to_buy_result = reject_to_buy_block.verify_and_get_signer(&bill_keys_obj);
        assert!(reject_to_buy_result.is_ok());
        assert_eq!(
            reject_to_buy_result.as_ref().unwrap().0,
            NodeId::new(company_keys.pub_key(), bitcoin::Network::Testnet)
        );
        assert!(matches!(
            reject_to_buy_result.as_ref().unwrap().1,
            Some(BillAction::RejectBuying)
        ));
        assert!(reject_to_buy_block.validate_plaintext_hash(&bill_keys.get_private_key()));

        let reject_to_pay_block = BillBlock::create_block_for_reject_to_pay(
            bill_id_test(),
            &issue_block,
            &BillRejectBlockData {
                rejecter: signer.clone().into(),
                signatory: Some(BillSignatoryBlockData {
                    node_id: NodeId::new(identity_keys.pub_key(), bitcoin::Network::Testnet),
                    name: Name::new("signatory name").unwrap(),
                }),
                signing_timestamp: 1731593928,
                signing_address: signer.postal_address.clone(),
            },
            &identity_keys,
            Some(&company_keys),
            &bill_keys,
            1731593928,
        )
        .unwrap();
        let reject_to_pay_result = reject_to_pay_block.verify_and_get_signer(&bill_keys_obj);
        assert!(reject_to_pay_result.is_ok());
        assert_eq!(
            reject_to_pay_result.as_ref().unwrap().0,
            NodeId::new(company_keys.pub_key(), bitcoin::Network::Testnet)
        );
        assert!(matches!(
            reject_to_pay_result.as_ref().unwrap().1,
            Some(BillAction::RejectPayment)
        ));
        assert!(reject_to_pay_block.validate_plaintext_hash(&bill_keys.get_private_key()));

        let reject_to_pay_recourse_block = BillBlock::create_block_for_reject_to_pay_recourse(
            bill_id_test(),
            &issue_block,
            &BillRejectBlockData {
                rejecter: signer.clone().into(),
                signatory: Some(BillSignatoryBlockData {
                    node_id: NodeId::new(identity_keys.pub_key(), bitcoin::Network::Testnet),
                    name: Name::new("signatory name").unwrap(),
                }),
                signing_timestamp: 1731593928,
                signing_address: signer.postal_address.clone(),
            },
            &identity_keys,
            Some(&company_keys),
            &bill_keys,
            1731593928,
        )
        .unwrap();
        let reject_to_pay_recourse_result =
            reject_to_pay_recourse_block.verify_and_get_signer(&bill_keys_obj);
        assert!(reject_to_pay_recourse_result.is_ok());
        assert_eq!(
            reject_to_pay_recourse_result.as_ref().unwrap().0,
            NodeId::new(company_keys.pub_key(), bitcoin::Network::Testnet)
        );
        assert!(matches!(
            reject_to_pay_recourse_result.as_ref().unwrap().1,
            Some(BillAction::RejectPaymentForRecourse)
        ));
        assert!(reject_to_pay_recourse_block.validate_plaintext_hash(&bill_keys.get_private_key()));

        let request_recourse_block = BillBlock::create_block_for_request_recourse(
            bill_id_test(),
            &issue_block,
            &BillRequestRecourseBlockData {
                recourser: BillParticipant::Ident(signer.clone()).into(),
                recoursee: other_party.clone().into(),
                sum: Sum::new_sat(15000).expect("sat works"),
                recourse_reason: BillRecourseReasonBlockData::Accept,
                signatory: Some(BillSignatoryBlockData {
                    node_id: NodeId::new(identity_keys.pub_key(), bitcoin::Network::Testnet),
                    name: Name::new("signatory name").unwrap(),
                }),
                signing_timestamp: 1731593928,
                signing_address: Some(signer.postal_address.clone()),
                recourse_deadline_timestamp: 1731593928 + 2 * RECOURSE_DEADLINE_SECONDS,
            },
            &identity_keys,
            Some(&company_keys),
            &bill_keys,
            1731593928,
        )
        .unwrap();
        let request_recourse_result = request_recourse_block.verify_and_get_signer(&bill_keys_obj);
        assert!(request_recourse_result.is_ok());
        assert_eq!(
            request_recourse_result.as_ref().unwrap().0,
            NodeId::new(company_keys.pub_key(), bitcoin::Network::Testnet)
        );
        assert!(matches!(
            request_recourse_result.as_ref().unwrap().1,
            Some(BillAction::RequestRecourse(_, _, _))
        ));
        assert!(request_recourse_block.validate_plaintext_hash(&bill_keys.get_private_key()));

        let recourse_block = BillBlock::create_block_for_recourse(
            bill_id_test(),
            &issue_block,
            &BillRecourseBlockData {
                recourser: BillParticipant::Ident(signer.clone()).into(),
                recoursee: other_party.clone().into(),
                sum: Sum::new_sat(15000).expect("sat works"),
                recourse_reason: BillRecourseReasonBlockData::Pay,
                signatory: Some(BillSignatoryBlockData {
                    node_id: NodeId::new(identity_keys.pub_key(), bitcoin::Network::Testnet),
                    name: Name::new("signatory name").unwrap(),
                }),
                signing_timestamp: 1731593928,
                signing_address: Some(signer.postal_address.clone()),
            },
            &identity_keys,
            Some(&company_keys),
            &bill_keys,
            1731593928,
        )
        .unwrap();
        let recourse_result = recourse_block.verify_and_get_signer(&bill_keys_obj);
        assert!(recourse_result.is_ok());
        assert_eq!(
            recourse_result.as_ref().unwrap().0,
            NodeId::new(company_keys.pub_key(), bitcoin::Network::Testnet)
        );
        assert!(matches!(
            recourse_result.as_ref().unwrap().1,
            Some(BillAction::Recourse(_, _, _))
        ));
        assert!(recourse_block.validate_plaintext_hash(&bill_keys.get_private_key()));
    }

    #[test]
    fn verify_and_get_signer_baseline_wrong_key() {
        let bill_keys = BcrKeys::new();
        let company_keys = BcrKeys::new();
        let identity_keys = BcrKeys::new();
        let bill_keys_obj = BillKeys {
            private_key: bill_keys.get_private_key(),
            public_key: bill_keys.pub_key(),
        };

        let mut bill = empty_bitcredit_bill();
        bill.drawer = bill_identified_participant_only_node_id(NodeId::new(
            BcrKeys::new().pub_key(),
            bitcoin::Network::Testnet,
        )); //company is drawer

        let block = BillBlock::create_block_for_issue(
            bill_id_test(),
            String::from("genesis"),
            &BillIssueBlockData::from(
                bill,
                Some(BillSignatoryBlockData {
                    node_id: node_id_test(),
                    name: Name::new("signatory name").unwrap(),
                }),
                1731593928,
            ),
            &identity_keys,
            Some(&company_keys),
            &bill_keys,
            1731593928,
        )
        .unwrap();

        let result = block.verify_and_get_signer(&bill_keys_obj);
        assert!(result.is_err());
    }

    // Validation
    fn valid_bill_participant_block_data() -> BillParticipantBlockData {
        BillParticipantBlockData::Ident(BillIdentParticipantBlockData {
            t: ContactType::Person,
            node_id: node_id_test(),
            name: Name::new("Johanna Smith").unwrap(),
            postal_address: valid_address(),
        })
    }

    fn other_valid_bill_participant_block_data() -> BillParticipantBlockData {
        BillParticipantBlockData::Ident(BillIdentParticipantBlockData {
            t: ContactType::Person,
            node_id: node_id_test_other(),
            name: Name::new("John Smith").unwrap(),
            postal_address: valid_address(),
        })
    }

    fn valid_bill_identity_block_data() -> BillIdentParticipantBlockData {
        BillIdentParticipantBlockData {
            t: ContactType::Person,
            node_id: node_id_test(),
            name: Name::new("Johanna Smith").unwrap(),
            postal_address: valid_address(),
        }
    }

    fn other_valid_bill_identity_block_data() -> BillIdentParticipantBlockData {
        BillIdentParticipantBlockData {
            t: ContactType::Person,
            node_id: node_id_test_other(),
            name: Name::new("John Smith").unwrap(),
            postal_address: valid_address(),
        }
    }

    #[test]
    fn test_valid_bill_identity_block_data() {
        assert_eq!(valid_bill_identity_block_data().validate(), Ok(()));
    }

    fn valid_bill_signatory_block_data() -> BillSignatoryBlockData {
        BillSignatoryBlockData {
            node_id: node_id_test(),
            name: Name::new("Johanna Smith").unwrap(),
        }
    }

    #[test]
    fn test_valid_bill_signatory_block_data() {
        assert_eq!(valid_bill_signatory_block_data().validate(), Ok(()));
    }

    pub fn valid_bill_issue_block_data() -> BillIssueBlockData {
        BillIssueBlockData {
            id: bill_id_test(),
            country_of_issuing: Country::AT,
            city_of_issuing: City::new("Vienna").unwrap(),
            drawee: other_valid_bill_identity_block_data(),
            drawer: valid_bill_identity_block_data(),
            payee: valid_bill_participant_block_data(),
            sum: Sum::new_sat(500).expect("sat works"),
            maturity_date: Date::new("2025-11-12").unwrap(),
            issue_date: Date::new("2025-08-12").unwrap(),
            country_of_payment: Country::FR,
            city_of_payment: City::new("Paris").unwrap(),
            files: vec![],
            signatory: Some(valid_bill_signatory_block_data()),
            signing_timestamp: 1731593928,
            signing_address: valid_address(),
        }
    }

    #[test]
    fn test_valid_bill_issue_block_data() {
        let bill = valid_bill_issue_block_data();
        assert_eq!(bill.validate(), Ok(()));
    }

    fn valid_req_to_accept_block_data() -> BillRequestToAcceptBlockData {
        BillRequestToAcceptBlockData {
            requester: valid_bill_participant_block_data(),
            signatory: Some(valid_bill_signatory_block_data()),
            signing_timestamp: 1731593928,
            signing_address: Some(valid_address()),
            acceptance_deadline_timestamp: 1731593928 + 2 * ACCEPT_DEADLINE_SECONDS,
        }
    }

    #[test]
    fn test_valid_req_to_accept_block_data() {
        let accept = valid_req_to_accept_block_data();
        assert_eq!(accept.validate(), Ok(()));
    }

    fn valid_accept_block_data() -> BillAcceptBlockData {
        BillAcceptBlockData {
            accepter: valid_bill_identity_block_data(),
            signatory: Some(valid_bill_signatory_block_data()),
            signing_timestamp: 1731593928,
            signing_address: valid_address(),
        }
    }

    #[test]
    fn test_valid_accept_block_data() {
        let accept = valid_accept_block_data();
        assert_eq!(accept.validate(), Ok(()));
    }

    fn valid_req_to_pay_block_data() -> BillRequestToPayBlockData {
        BillRequestToPayBlockData {
            requester: valid_bill_participant_block_data(),
            currency: Currency::sat(),
            signatory: Some(valid_bill_signatory_block_data()),
            signing_timestamp: 1731593928,
            signing_address: Some(valid_address()),
            payment_deadline_timestamp: 1731593928 + 2 * PAYMENT_DEADLINE_SECONDS,
        }
    }

    #[test]
    fn test_valid_req_to_pay_block_data() {
        let accept = valid_req_to_pay_block_data();
        assert_eq!(accept.validate(), Ok(()));
    }

    fn valid_mint_block_data() -> BillMintBlockData {
        BillMintBlockData {
            endorser: valid_bill_participant_block_data(),
            endorsee: other_valid_bill_participant_block_data(),
            sum: Sum::new_sat(500).expect("sat works"),
            signatory: Some(valid_bill_signatory_block_data()),
            signing_timestamp: 1731593928,
            signing_address: Some(valid_address()),
        }
    }

    #[test]
    fn test_valid_mint_block_data() {
        let accept = valid_mint_block_data();
        assert_eq!(accept.validate(), Ok(()));
    }

    fn valid_offer_to_sell_block_data() -> BillOfferToSellBlockData {
        BillOfferToSellBlockData {
            seller: valid_bill_participant_block_data(),
            buyer: other_valid_bill_participant_block_data(),
            sum: Sum::new_sat(500).expect("sat works"),
            payment_address: VALID_PAYMENT_ADDRESS_TESTNET.into(),
            signatory: Some(valid_bill_signatory_block_data()),
            signing_timestamp: 1731593928,
            signing_address: Some(valid_address()),
            buying_deadline_timestamp: 1731593928 + 2 * DAY_IN_SECS,
        }
    }

    #[test]
    fn test_valid_offer_to_sell_block_data() {
        let accept = valid_offer_to_sell_block_data();
        assert_eq!(accept.validate(), Ok(()));
    }

    #[rstest]
    #[case::invalid_payment_address(BillOfferToSellBlockData { payment_address: "invalidaddress".into(), ..valid_offer_to_sell_block_data() }, ValidationError::InvalidPaymentAddress)]
    fn test_invalid_offer_to_sell_block_data(
        #[case] block: BillOfferToSellBlockData,
        #[case] expected_error: ValidationError,
    ) {
        assert_eq!(block.validate(), Err(expected_error));
    }

    fn valid_sell_block_data() -> BillSellBlockData {
        BillSellBlockData {
            seller: valid_bill_participant_block_data(),
            buyer: other_valid_bill_participant_block_data(),
            sum: Sum::new_sat(500).expect("sat works"),
            payment_address: VALID_PAYMENT_ADDRESS_TESTNET.into(),
            signatory: Some(valid_bill_signatory_block_data()),
            signing_timestamp: 1731593928,
            signing_address: Some(valid_address()),
        }
    }

    #[test]
    fn test_valid_sell_block_data() {
        let accept = valid_sell_block_data();
        assert_eq!(accept.validate(), Ok(()));
    }

    #[rstest]
    #[case::invalid_payment_address(BillSellBlockData { payment_address: "invalidaddress".into(), ..valid_sell_block_data() }, ValidationError::InvalidPaymentAddress)]
    fn test_invalid_sell_block_data(
        #[case] block: BillSellBlockData,
        #[case] expected_error: ValidationError,
    ) {
        assert_eq!(block.validate(), Err(expected_error));
    }

    fn valid_endorse_block_data() -> BillEndorseBlockData {
        BillEndorseBlockData {
            endorser: valid_bill_participant_block_data(),
            endorsee: other_valid_bill_participant_block_data(),
            signatory: Some(valid_bill_signatory_block_data()),
            signing_timestamp: 1731593928,
            signing_address: Some(valid_address()),
        }
    }

    #[test]
    fn test_valid_endorse_block_data() {
        let accept = valid_endorse_block_data();
        assert_eq!(accept.validate(), Ok(()));
    }

    fn valid_req_to_recourse_block_data() -> BillRequestRecourseBlockData {
        BillRequestRecourseBlockData {
            recourser: valid_bill_participant_block_data(),
            recoursee: other_valid_bill_identity_block_data(),
            sum: Sum::new_sat(500).expect("sat works"),
            recourse_reason: BillRecourseReasonBlockData::Pay,
            signatory: Some(valid_bill_signatory_block_data()),
            signing_timestamp: 1731593928,
            signing_address: Some(valid_address()),
            recourse_deadline_timestamp: 1731593928 + 2 * RECOURSE_DEADLINE_SECONDS,
        }
    }

    #[test]
    fn test_valid_req_to_recourse_block_data() {
        let accept = valid_req_to_recourse_block_data();
        assert_eq!(accept.validate(), Ok(()));
    }

    fn valid_recourse_block_data() -> BillRecourseBlockData {
        BillRecourseBlockData {
            recourser: BillParticipantBlockData::Ident(valid_bill_identity_block_data()),
            recoursee: other_valid_bill_identity_block_data(),
            sum: Sum::new_sat(500).expect("sat works"),
            recourse_reason: BillRecourseReasonBlockData::Pay,
            signatory: Some(valid_bill_signatory_block_data()),
            signing_timestamp: 1731593928,
            signing_address: Some(valid_address()),
        }
    }

    #[test]
    fn test_valid_recourse_block_data() {
        let accept = valid_recourse_block_data();
        assert_eq!(accept.validate(), Ok(()));
    }

    fn valid_reject_block_data() -> BillRejectBlockData {
        BillRejectBlockData {
            rejecter: valid_bill_identity_block_data(),
            signatory: Some(valid_bill_signatory_block_data()),
            signing_timestamp: 1731593928,
            signing_address: valid_address(),
        }
    }

    #[test]
    fn test_valid_reject_block_data() {
        let accept = valid_reject_block_data();
        assert_eq!(accept.validate(), Ok(()));
    }
}
