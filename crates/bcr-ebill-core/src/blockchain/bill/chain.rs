use super::super::Result;
use super::PaymentInfo;
use super::block::{
    BillAcceptBlockData, BillBlock, BillEndorseBlockData, BillIdentParticipantBlockData,
    BillIssueBlockData, BillMintBlockData, BillOfferToSellBlockData, BillParticipantBlockData,
    BillRecourseBlockData, BillRejectBlockData, BillRequestRecourseBlockData,
    BillRequestToAcceptBlockData, BillRequestToPayBlockData, BillSellBlockData, HolderFromBlock,
};
use super::{BillOpCode, RecourseWaitingForPayment};
use super::{OfferToSellWaitingForPayment, RecoursePaymentInfo};
use crate::NodeId;
use crate::bill::{BillKeys, Endorsement, LightSignedBy, PastEndorsee, PastPaymentStatus};
use crate::blockchain::{Block, Blockchain, Error};
use crate::constants::{PAYMENT_DEADLINE_SECONDS, RECOURSE_DEADLINE_SECONDS};
use crate::contact::{
    BillParticipant, ContactType, LightBillIdentParticipant, LightBillParticipant,
};
use crate::util::{self, BcrKeys};
use borsh_derive::{BorshDeserialize, BorshSerialize};
use log::error;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BillParties {
    pub drawee: BillIdentParticipantBlockData,
    pub drawer: BillIdentParticipantBlockData,
    pub payee: BillParticipantBlockData,
    pub endorsee: Option<BillParticipantBlockData>,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone)]
pub struct BillBlockPlaintextWrapper {
    pub block: BillBlock,
    pub plaintext_data_bytes: Vec<u8>,
}

impl BillBlockPlaintextWrapper {
    pub fn get_bill_data(&self) -> Result<BillIssueBlockData> {
        if matches!(self.block.op_code(), BillOpCode::Issue) {
            let issue_data: BillIssueBlockData = borsh::from_slice(&self.plaintext_data_bytes)?;
            Ok(issue_data)
        } else {
            Err(Error::BlockInvalid)
        }
    }

    pub fn get_holder(&self) -> Result<Option<HolderFromBlock>> {
        match self.block.op_code() {
            BillOpCode::Issue => {
                let bill: BillIssueBlockData = borsh::from_slice(&self.plaintext_data_bytes)?;
                Ok(Some(HolderFromBlock {
                    holder: bill.payee,
                    signer: BillParticipantBlockData::Ident(bill.drawer),
                    signatory: bill.signatory,
                }))
            }
            BillOpCode::Endorse => {
                let block: BillEndorseBlockData = borsh::from_slice(&self.plaintext_data_bytes)?;
                Ok(Some(HolderFromBlock {
                    holder: block.endorsee,
                    signer: block.endorser,
                    signatory: block.signatory,
                }))
            }
            BillOpCode::Mint => {
                let block: BillMintBlockData = borsh::from_slice(&self.plaintext_data_bytes)?;
                Ok(Some(HolderFromBlock {
                    holder: block.endorsee,
                    signer: block.endorser,
                    signatory: block.signatory,
                }))
            }
            BillOpCode::Sell => {
                let block: BillSellBlockData = borsh::from_slice(&self.plaintext_data_bytes)?;
                Ok(Some(HolderFromBlock {
                    holder: block.buyer,
                    signer: block.seller,
                    signatory: block.signatory,
                }))
            }
            BillOpCode::Recourse => {
                let block: BillRecourseBlockData = borsh::from_slice(&self.plaintext_data_bytes)?;
                Ok(Some(HolderFromBlock {
                    holder: BillParticipantBlockData::Ident(block.recoursee),
                    signer: BillParticipantBlockData::Ident(block.recourser),
                    signatory: block.signatory,
                }))
            }
            _ => Ok(None),
        }
    }
}

/// Gets bill parties from blocks with their plaintext data
pub fn get_bill_parties_from_chain_with_plaintext(
    chain_with_plaintext: &[BillBlockPlaintextWrapper],
) -> Result<BillParties> {
    let chain = BillBlockchain::new_from_blocks(
        chain_with_plaintext
            .iter()
            .map(|wrapper| wrapper.block.to_owned())
            .collect::<Vec<BillBlock>>(),
    )?;

    let bill_first_version = chain_with_plaintext
        .first()
        .ok_or(Error::BlockchainInvalid)?
        .get_bill_data()?;

    let last_version_block_endorse = if let Some(endorse_block_encrypted) =
        chain.get_last_version_block_with_op_code(BillOpCode::Endorse)
    {
        let block_id = endorse_block_encrypted.id;
        let endorse_plaintext_wrapper = chain_with_plaintext
            .iter()
            .find(|wrapper| wrapper.block.id() == block_id)
            .ok_or(Error::BlockInvalid)?;
        Some((
            block_id,
            borsh::from_slice::<BillEndorseBlockData>(
                &endorse_plaintext_wrapper.plaintext_data_bytes,
            )?
            .endorsee,
        ))
    } else {
        None
    };
    let last_version_block_mint = if let Some(mint_block_encrypted) =
        chain.get_last_version_block_with_op_code(BillOpCode::Mint)
    {
        let block_id = mint_block_encrypted.id;
        let mint_plaintext_wrapper = chain_with_plaintext
            .iter()
            .find(|wrapper| wrapper.block.id() == block_id)
            .ok_or(Error::BlockInvalid)?;
        Some((
            block_id,
            borsh::from_slice::<BillMintBlockData>(&mint_plaintext_wrapper.plaintext_data_bytes)?
                .endorsee,
        ))
    } else {
        None
    };
    let last_version_block_sell = if let Some(sell_block_encrypted) =
        chain.get_last_version_block_with_op_code(BillOpCode::Sell)
    {
        let block_id = sell_block_encrypted.id;
        let sell_plaintext_wrapper = chain_with_plaintext
            .iter()
            .find(|wrapper| wrapper.block.id() == block_id)
            .ok_or(Error::BlockInvalid)?;
        Some((
            block_id,
            borsh::from_slice::<BillSellBlockData>(&sell_plaintext_wrapper.plaintext_data_bytes)?
                .buyer,
        ))
    } else {
        None
    };
    let last_version_block_recourse = if let Some(recourse_block_encrypted) =
        chain.get_last_version_block_with_op_code(BillOpCode::Recourse)
    {
        let block_id = recourse_block_encrypted.id;
        let recourse_plaintext_wrapper = chain_with_plaintext
            .iter()
            .find(|wrapper| wrapper.block.id() == block_id)
            .ok_or(Error::BlockInvalid)?;
        Some((
            block_id,
            BillParticipantBlockData::Ident(
                borsh::from_slice::<BillRecourseBlockData>(
                    &recourse_plaintext_wrapper.plaintext_data_bytes,
                )?
                .recoursee,
            ),
        ))
    } else {
        None
    };

    let last_endorsee = vec![
        last_version_block_endorse,
        last_version_block_mint,
        last_version_block_sell,
        last_version_block_recourse,
    ]
    .into_iter()
    .flatten()
    .max_by_key(|(id, _)| *id)
    .map(|b| b.1);

    Ok(BillParties {
        drawee: bill_first_version.drawee.to_owned(),
        drawer: bill_first_version.drawer.to_owned(),
        payee: bill_first_version.payee.to_owned(),
        endorsee: last_endorsee,
    })
}

/// Gets endorsees from blocks with their plaintext data
pub fn get_endorsees_from_chain_with_plaintext(
    chain_with_plaintext: &[BillBlockPlaintextWrapper],
) -> Vec<BillParticipant> {
    let mut result: Vec<BillParticipant> = vec![];
    // iterate from the front to the back, collecting all endorsement blocks
    for block_wrapper in chain_with_plaintext.iter() {
        // we ignore issue blocks, since we are only interested in endorsements
        if block_wrapper.block.op_code == BillOpCode::Issue {
            continue;
        }
        if let Ok(Some(holder_from_block)) = block_wrapper.get_holder() {
            let holder = holder_from_block.holder;
            result.push(holder.into());
        }
    }

    result
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone)]
pub struct BillBlockchain {
    blocks: Vec<BillBlock>,
}

impl Blockchain for BillBlockchain {
    type Block = BillBlock;

    fn blocks(&self) -> &Vec<Self::Block> {
        &self.blocks
    }

    fn blocks_mut(&mut self) -> &mut Vec<Self::Block> {
        &mut self.blocks
    }
}

impl BillBlockchain {
    /// Creates a new blockchain for the given bill, encrypting the metadata using the bill's public
    /// key
    pub fn new(
        bill: &BillIssueBlockData,
        drawer_key_pair: BcrKeys,
        drawer_company_key_pair: Option<BcrKeys>,
        bill_keys: BcrKeys,
        timestamp: u64,
    ) -> Result<Self> {
        let genesis_hash = util::base58_encode(bill.id.to_string().as_bytes());

        let first_block = BillBlock::create_block_for_issue(
            bill.id.clone(),
            genesis_hash,
            bill,
            &drawer_key_pair,
            drawer_company_key_pair.as_ref(),
            &bill_keys,
            timestamp,
        )?;

        Ok(Self {
            blocks: vec![first_block],
        })
    }

    /// Creates a bill chain from a vec of blocks
    pub fn new_from_blocks(blocks_to_add: Vec<BillBlock>) -> Result<Self> {
        match blocks_to_add.first() {
            None => Err(Error::BlockchainInvalid),
            Some(first) => {
                if !first.verify() || !first.validate_hash() {
                    return Err(Error::BlockchainInvalid);
                }

                let chain = Self {
                    blocks: blocks_to_add,
                };

                if !chain.is_chain_valid() {
                    return Err(Error::BlockchainInvalid);
                }

                Ok(chain)
            }
        }
    }

    /// Gets the past payment information for the given node id regarding sell operations (offer to sell, reject to buy,
    /// / sell), where the node id is the beneficiary (seller)
    pub fn get_past_sell_payments_for_node_id(
        &self,
        bill_keys: &BillKeys,
        node_id: &NodeId,
        timestamp: u64,
    ) -> Result<Vec<(PaymentInfo, PastPaymentStatus, u64)>> {
        let mut result = vec![];
        let blocks = self.blocks();
        let mut sell_pairs: Vec<(BillBlock, Option<BillBlock>)> = vec![];

        let mut current_offer_to_sell: Option<BillBlock> = None;
        // collect offer to sell / (sell / reject to buy) block pairs
        for block in blocks {
            match block.op_code() {
                BillOpCode::OfferToSell => {
                    if let Some(offer_to_sell_block) = current_offer_to_sell {
                        // offer to sell after offer to sell - push current without sell and set new
                        sell_pairs.push((offer_to_sell_block.clone(), None));
                        current_offer_to_sell = Some(block.clone());
                    } else {
                        // no offer to sell found yet - set it
                        current_offer_to_sell = Some(block.clone());
                    }
                }
                BillOpCode::RejectToBuy => {
                    if let Some(offer_to_sell_block) = current_offer_to_sell {
                        // reject after offer to sell - push both, reset offer to sell
                        sell_pairs.push((offer_to_sell_block.clone(), Some(block.clone())));
                        current_offer_to_sell = None;
                    } else {
                        error!("RejectToBuy block without Offer to Sell block detected");
                        return Err(Error::BlockchainInvalid);
                    }
                }
                BillOpCode::Sell => {
                    if let Some(offer_to_sell_block) = current_offer_to_sell {
                        // sell after offer to sell - push both, reset offer to sell
                        sell_pairs.push((offer_to_sell_block.clone(), Some(block.clone())));
                        current_offer_to_sell = None;
                    } else {
                        error!("Sell block without Offer to Sell block detected");
                        return Err(Error::BlockchainInvalid);
                    }
                }
                _ => (),
            };
        }

        if let Some(leftover_offer_to_sell_block) = current_offer_to_sell {
            sell_pairs.push((leftover_offer_to_sell_block.clone(), None));
        }

        for sell_pair in sell_pairs {
            let offer_to_sell_block = sell_pair.0;
            let block_data_decrypted: BillOfferToSellBlockData =
                offer_to_sell_block.get_decrypted_block(bill_keys)?;

            if *node_id != block_data_decrypted.seller.node_id() {
                // node id is not beneficiary - skip
                continue;
            }

            let payment_info = PaymentInfo {
                buyer: block_data_decrypted.buyer.into(),
                seller: block_data_decrypted.seller.into(),
                sum: block_data_decrypted.sum,
                currency: block_data_decrypted.currency,
                payment_address: block_data_decrypted.payment_address,
                block_id: offer_to_sell_block.id(),
            };

            match sell_pair.1 {
                Some(reject_or_sell_block) => match reject_or_sell_block.op_code() {
                    BillOpCode::RejectToBuy => {
                        result.push((
                            payment_info,
                            PastPaymentStatus::Rejected(reject_or_sell_block.timestamp),
                            offer_to_sell_block.timestamp,
                        ));
                    }
                    BillOpCode::Sell => {
                        result.push((
                            payment_info,
                            PastPaymentStatus::Paid(reject_or_sell_block.timestamp),
                            offer_to_sell_block.timestamp,
                        ));
                    }
                    _ => (),
                },
                None => {
                    // check if deadline expired, if not, ignore, otherwise add as expired
                    if util::date::check_if_deadline_has_passed(
                        offer_to_sell_block.timestamp,
                        timestamp,
                        PAYMENT_DEADLINE_SECONDS,
                    ) {
                        result.push((
                            payment_info,
                            PastPaymentStatus::Expired(
                                offer_to_sell_block.timestamp + PAYMENT_DEADLINE_SECONDS,
                            ),
                            offer_to_sell_block.timestamp,
                        ));
                    }
                }
            }
        }
        Ok(result)
    }

    /// Gets the past payment information for the given node id regarding recourse operations (req
    /// to recourse, reject recourse, recourse where the node id is the beneficiary (seller)
    pub fn get_past_recourse_payments_for_node_id(
        &self,
        bill_keys: &BillKeys,
        node_id: &NodeId,
        timestamp: u64,
    ) -> Result<Vec<(RecoursePaymentInfo, PastPaymentStatus, u64)>> {
        let mut result = vec![];
        let blocks = self.blocks();
        let mut recourse_pairs: Vec<(BillBlock, Option<BillBlock>)> = vec![];

        let mut current_req_to_recourse: Option<BillBlock> = None;
        // collect req to recourse / (reject recourse / recourse) block pairs
        for block in blocks {
            match block.op_code() {
                BillOpCode::RequestRecourse => {
                    if let Some(req_to_recourse_block) = current_req_to_recourse {
                        // req to recourse after req_to_recourse_block - push current without recourse and set new
                        recourse_pairs.push((req_to_recourse_block.clone(), None));
                        current_req_to_recourse = Some(block.clone());
                    } else {
                        // no offer to sell found yet - set it
                        current_req_to_recourse = Some(block.clone());
                    }
                }
                BillOpCode::RejectToPayRecourse => {
                    if let Some(req_to_recourse_block) = current_req_to_recourse {
                        // reject after offer to sell - push both, reset offer to sell
                        recourse_pairs.push((req_to_recourse_block.clone(), Some(block.clone())));
                        current_req_to_recourse = None;
                    } else {
                        error!("RejectToPayRecourse block without Req to Recourse block detected");
                        return Err(Error::BlockchainInvalid);
                    }
                }
                BillOpCode::Recourse => {
                    if let Some(req_to_recourse_block) = current_req_to_recourse {
                        // recourse after req to recourse- push both, reset req to recourse
                        recourse_pairs.push((req_to_recourse_block.clone(), Some(block.clone())));
                        current_req_to_recourse = None;
                    } else {
                        error!("Recourse block without Req to Recourse block detected");
                        return Err(Error::BlockchainInvalid);
                    }
                }
                _ => (),
            };
        }

        if let Some(leftover_req_to_recourse_block) = current_req_to_recourse {
            recourse_pairs.push((leftover_req_to_recourse_block.clone(), None));
        }

        for recourse_pair in recourse_pairs {
            let request_to_recourse_block = recourse_pair.0;
            let block_data_decrypted: BillRequestRecourseBlockData =
                request_to_recourse_block.get_decrypted_block(bill_keys)?;

            if *node_id != block_data_decrypted.recourser.node_id {
                // node id is not beneficiary - skip
                continue;
            }

            let payment_info = RecoursePaymentInfo {
                recoursee: block_data_decrypted.recoursee,
                recourser: block_data_decrypted.recourser,
                sum: block_data_decrypted.sum,
                currency: block_data_decrypted.currency,
                reason: block_data_decrypted.recourse_reason,
                block_id: request_to_recourse_block.id(),
            };

            match recourse_pair.1 {
                Some(reject_or_recourse_block) => match reject_or_recourse_block.op_code() {
                    BillOpCode::RejectToPayRecourse => {
                        result.push((
                            payment_info,
                            PastPaymentStatus::Rejected(reject_or_recourse_block.timestamp),
                            request_to_recourse_block.timestamp,
                        ));
                    }
                    BillOpCode::Recourse => {
                        result.push((
                            payment_info,
                            PastPaymentStatus::Paid(reject_or_recourse_block.timestamp),
                            request_to_recourse_block.timestamp,
                        ));
                    }
                    _ => (),
                },
                None => {
                    // check if deadline expired, if not, ignore, otherwise add as expired
                    if util::date::check_if_deadline_has_passed(
                        request_to_recourse_block.timestamp,
                        timestamp,
                        RECOURSE_DEADLINE_SECONDS,
                    ) {
                        result.push((
                            payment_info,
                            PastPaymentStatus::Expired(
                                request_to_recourse_block.timestamp + PAYMENT_DEADLINE_SECONDS,
                            ),
                            request_to_recourse_block.timestamp,
                        ));
                    }
                }
            }
        }
        Ok(result)
    }

    /// Checks if the given node_id is a beneficiary of a holder-changing block with a financial
    /// beneficiary (sell, recourse)
    pub fn is_beneficiary_from_a_block(&self, bill_keys: &BillKeys, node_id: &NodeId) -> bool {
        self.blocks()
            .iter()
            .filter_map(|b| b.get_beneficiary_from_block(bill_keys).ok())
            .flatten()
            .any(|s| s == *node_id)
    }

    /// Checks if the given node_id is a beneficiary of a request block with a financial
    /// beneficiary (offer to sell, req to recourse, req to pay)
    pub fn is_beneficiary_from_a_request_funds_block(
        &self,
        bill_keys: &BillKeys,
        node_id: &NodeId,
    ) -> bool {
        self.blocks()
            .iter()
            .filter_map(|b| b.get_beneficiary_from_request_funds_block(bill_keys).ok())
            .flatten()
            .any(|s| s == *node_id)
    }

    /// Checks if the the chain has Endorse, Mint, or Sell blocks in it
    pub fn has_been_endorsed_sold_or_minted(&self) -> bool {
        self.blocks.iter().any(|block| {
            matches!(
                block.op_code,
                BillOpCode::Mint | BillOpCode::Sell | BillOpCode::Endorse
            )
        })
    }

    /// Checks if the the chain has Endorse, or Sell blocks in it
    pub fn has_been_endorsed_or_sold(&self) -> bool {
        self.blocks
            .iter()
            .any(|block| matches!(block.op_code, BillOpCode::Sell | BillOpCode::Endorse))
    }

    /// Checks if the last block is a request to recourse block, if it's deadline is still active and if so,
    /// returns the recoursee, recourser and sum
    pub fn is_last_request_to_recourse_block_waiting_for_payment(
        &self,
        bill_keys: &BillKeys,
        current_timestamp: u64,
    ) -> Result<RecourseWaitingForPayment> {
        let last_block = self.get_latest_block();
        if let Some(last_version_block) =
            self.get_last_version_block_with_op_code(BillOpCode::RequestRecourse)
        {
            // we only wait for payment, if the last block is a Request to Recourse block
            if last_block.id == last_version_block.id {
                // if the deadline is up, we're not waiting for payment anymore
                if util::date::check_if_deadline_has_passed(
                    last_version_block.timestamp,
                    current_timestamp,
                    RECOURSE_DEADLINE_SECONDS,
                ) {
                    return Ok(RecourseWaitingForPayment::No);
                }

                let block_data_decrypted: BillRequestRecourseBlockData =
                    last_version_block.get_decrypted_block(bill_keys)?;
                return Ok(RecourseWaitingForPayment::Yes(Box::new(
                    RecoursePaymentInfo {
                        recoursee: block_data_decrypted.recoursee,
                        recourser: block_data_decrypted.recourser,
                        sum: block_data_decrypted.sum,
                        currency: block_data_decrypted.currency,
                        reason: block_data_decrypted.recourse_reason,
                        block_id: last_version_block.id(),
                    },
                )));
            }
        }
        Ok(RecourseWaitingForPayment::No)
    }

    /// Checks if the last block is an offer to sell block, if it's deadline is still active and if so,
    /// returns the buyer, seller and sum
    pub fn is_last_offer_to_sell_block_waiting_for_payment(
        &self,
        bill_keys: &BillKeys,
        current_timestamp: u64,
    ) -> Result<OfferToSellWaitingForPayment> {
        let last_block = self.get_latest_block();
        if let Some(last_version_block_offer_to_sell) =
            self.get_last_version_block_with_op_code(BillOpCode::OfferToSell)
        {
            // we only wait for payment, if the last block is an Offer to Sell block
            if last_block.id == last_version_block_offer_to_sell.id {
                // if the deadline is up, we're not waiting for payment anymore
                if util::date::check_if_deadline_has_passed(
                    last_version_block_offer_to_sell.timestamp,
                    current_timestamp,
                    PAYMENT_DEADLINE_SECONDS,
                ) {
                    return Ok(OfferToSellWaitingForPayment::No);
                }

                let block_data_decrypted: BillOfferToSellBlockData =
                    last_version_block_offer_to_sell.get_decrypted_block(bill_keys)?;
                return Ok(OfferToSellWaitingForPayment::Yes(Box::new(PaymentInfo {
                    buyer: block_data_decrypted.buyer.into(),
                    seller: block_data_decrypted.seller.into(),
                    sum: block_data_decrypted.sum,
                    currency: block_data_decrypted.currency,
                    payment_address: block_data_decrypted.payment_address,
                    block_id: last_version_block_offer_to_sell.id(),
                })));
            }
        }
        Ok(OfferToSellWaitingForPayment::No)
    }

    /// This function extracts the first block's data, decrypts it using the private key
    /// associated with the bill, and then deserializes the decrypted data into a `BitcreditBill`
    /// object.
    ///
    /// # Arguments
    /// * `bill_keys` - The keys for the bill.
    ///
    /// # Returns
    ///
    /// * `BitcreditBill` - The first version of the bill
    ///
    pub fn get_first_version_bill(&self, bill_keys: &BillKeys) -> Result<BillIssueBlockData> {
        let first_block_data = &self.get_first_block();
        let bill_first_version: BillIssueBlockData =
            first_block_data.get_decrypted_block(bill_keys)?;
        Ok(bill_first_version)
    }

    /// This function iterates over all the blocks in the blockchain, extracts the nodes
    /// from each block, and compiles a unique list of nodes.
    ///
    /// # Returns
    /// `Vec<String>`:
    /// - A vector containing the unique identifiers of nodes associated with the bill.
    ///
    pub fn get_all_nodes_from_bill(&self, bill_keys: &BillKeys) -> Result<Vec<NodeId>> {
        let node_map = self.get_all_nodes_with_added_block_height(bill_keys)?;
        Ok(node_map.keys().cloned().collect())
    }

    /// Returns all nodes that are part of this chain with the block height they were added.
    ///
    /// # Returns
    /// `HashMap<String, usize>`:
    /// - A map containing the unique identifiers of nodes and the block height they were added.
    pub fn get_all_nodes_with_added_block_height(
        &self,
        bill_keys: &BillKeys,
    ) -> Result<HashMap<NodeId, usize>> {
        let mut nodes: HashMap<NodeId, usize> = HashMap::new();
        for (height, block) in self.blocks.iter().enumerate() {
            let nodes_in_block = block.get_nodes_from_block(bill_keys)?;
            for node in nodes_in_block {
                nodes.entry(node).or_insert_with(|| height + 1);
            }
        }
        Ok(nodes)
    }

    pub fn get_endorsements_for_bill(&self, bill_keys: &BillKeys) -> Vec<Endorsement> {
        let mut result: Vec<Endorsement> = vec![];
        // iterate from the back to the front, collecting all endorsement blocks
        for block in self.blocks().iter().rev() {
            // we ignore issue blocks, since we are only interested in endorsements
            if block.op_code == BillOpCode::Issue {
                continue;
            }
            if let Ok(Some(holder_from_block)) = block.get_holder_from_block(bill_keys) {
                // we ignore blocks with an anonymous holder
                if let BillParticipantBlockData::Ident(holder_data) = holder_from_block.holder {
                    result.push(Endorsement {
                        pay_to_the_order_of: holder_data.clone().into(),
                        signed: LightSignedBy {
                            data: holder_from_block.signer.clone().into(),
                            signatory: holder_from_block.signatory.map(|s| {
                                LightBillIdentParticipant {
                                    // signatories are always identified people
                                    t: ContactType::Person,
                                    name: s.name,
                                    node_id: s.node_id,
                                }
                            }),
                        },
                        signing_timestamp: block.timestamp,
                        signing_address: match holder_from_block.signer {
                            BillParticipantBlockData::Anon(_) => None,
                            BillParticipantBlockData::Ident(data) => Some(data.postal_address),
                        },
                    });
                }
            }
        }

        result
    }

    /// Returns all endorsees from front to back (current holder is the last one in the list)
    pub fn get_endorsees_for_bill(&self, bill_keys: &BillKeys) -> Vec<BillParticipant> {
        let mut result: Vec<BillParticipant> = vec![];
        // iterate from the front to the back, collecting all endorsement blocks
        for block in self.blocks().iter() {
            // we ignore issue blocks, since we are only interested in endorsements
            if block.op_code == BillOpCode::Issue {
                continue;
            }
            if let Ok(Some(holder_from_block)) = block.get_holder_from_block(bill_keys) {
                let holder = holder_from_block.holder;
                result.push(holder.into());
            }
        }

        result
    }

    pub fn get_past_endorsees_for_bill(
        &self,
        bill_keys: &BillKeys,
        current_identity_node_id: &NodeId,
    ) -> Result<Vec<PastEndorsee>> {
        let mut result: HashMap<NodeId, PastEndorsee> = HashMap::new();

        let mut found_last_endorsing_block_for_node = false;
        // we ignore recourse blocks, since we're only interested in previous endorsees before
        // recourse
        let holders = self
            .blocks()
            .iter()
            .rev()
            .filter(|block| block.op_code != BillOpCode::Recourse)
            .filter_map(|block| {
                block
                    .get_holder_from_block(bill_keys)
                    .unwrap_or(None)
                    .map(|holder| (block.timestamp, holder))
            });
        for (timestamp, holder) in holders {
            // first, we search for the last non-recourse block in which we became holder
            if holder.holder.node_id() == *current_identity_node_id
                && !found_last_endorsing_block_for_node
            {
                found_last_endorsing_block_for_node = true;
                continue;
            }

            // if the holder is anonymous, we don't add them, because they can't be recoursed against
            if let BillParticipantBlockData::Ident(holder_data) = holder.holder {
                // we add the holders before ourselves, if they're not in the list already
                if found_last_endorsing_block_for_node
                    && holder_data.node_id() != *current_identity_node_id
                {
                    result
                        .entry(holder_data.node_id().clone())
                        .or_insert(PastEndorsee {
                            pay_to_the_order_of: holder_data.clone().into(),
                            signed: LightSignedBy {
                                data: holder.signer.clone().into(),
                                signatory: holder.signatory.map(|s| LightBillIdentParticipant {
                                    t: ContactType::Person,
                                    name: s.name,
                                    node_id: s.node_id,
                                }),
                            },
                            signing_timestamp: timestamp,
                            signing_address: match holder.signer {
                                BillParticipantBlockData::Anon(_) => None,
                                BillParticipantBlockData::Ident(data) => Some(data.postal_address),
                            },
                        });
                }
            }
        }

        let first_version_bill = self.get_first_version_bill(bill_keys)?;
        // If the drawer is not the drawee, the drawer is the first holder, if the drawer is the
        // payee, they are already in the list
        if first_version_bill.drawer.node_id != first_version_bill.drawee.node_id {
            result
                .entry(first_version_bill.drawer.node_id.clone())
                .or_insert(PastEndorsee {
                    pay_to_the_order_of: first_version_bill.drawer.clone().into(),
                    signed: LightSignedBy {
                        data: LightBillParticipant::Ident(first_version_bill.drawer.clone().into()),
                        signatory: first_version_bill.signatory.map(|s| {
                            LightBillIdentParticipant {
                                t: ContactType::Person,
                                name: s.name,
                                node_id: s.node_id,
                            }
                        }),
                    },
                    signing_timestamp: first_version_bill.signing_timestamp,
                    signing_address: Some(first_version_bill.drawer.postal_address),
                });
        }

        // remove ourselves from the list
        result.remove(current_identity_node_id);

        // sort by signing timestamp descending
        let mut list: Vec<PastEndorsee> = result.into_values().collect();
        list.sort_by(|a, b| b.signing_timestamp.cmp(&a.signing_timestamp));

        Ok(list)
    }

    /// Returns the latest bill parties (drawer, drawee, payee, endorsee)
    pub fn get_bill_parties(
        &self,
        bill_keys: &BillKeys,
        bill_first_version: &BillIssueBlockData,
    ) -> Result<BillParties> {
        // check endorsing blocks
        let last_version_block_endorse = if let Some(endorse_block_encrypted) =
            self.get_last_version_block_with_op_code(BillOpCode::Endorse)
        {
            Some((
                endorse_block_encrypted.id,
                endorse_block_encrypted
                    .get_decrypted_block::<BillEndorseBlockData>(bill_keys)?
                    .endorsee,
            ))
        } else {
            None
        };
        let last_version_block_mint = if let Some(mint_block_encrypted) =
            self.get_last_version_block_with_op_code(BillOpCode::Mint)
        {
            Some((
                mint_block_encrypted.id,
                mint_block_encrypted
                    .get_decrypted_block::<BillMintBlockData>(bill_keys)?
                    .endorsee,
            ))
        } else {
            None
        };
        let last_version_block_sell = if let Some(sell_block_encrypted) =
            self.get_last_version_block_with_op_code(BillOpCode::Sell)
        {
            Some((
                sell_block_encrypted.id,
                sell_block_encrypted
                    .get_decrypted_block::<BillSellBlockData>(bill_keys)?
                    .buyer,
            ))
        } else {
            None
        };
        let last_version_block_recourse = if let Some(recourse_block_encrypted) =
            self.get_last_version_block_with_op_code(BillOpCode::Recourse)
        {
            Some((
                recourse_block_encrypted.id,
                BillParticipantBlockData::Ident(
                    recourse_block_encrypted
                        .get_decrypted_block::<BillRecourseBlockData>(bill_keys)?
                        .recoursee,
                ),
            ))
        } else {
            None
        };

        let last_endorsee = vec![
            last_version_block_endorse,
            last_version_block_mint,
            last_version_block_sell,
            last_version_block_recourse,
        ]
        .into_iter()
        .flatten()
        .max_by_key(|(id, _)| *id)
        .map(|b| b.1);

        Ok(BillParties {
            drawee: bill_first_version.drawee.to_owned(),
            drawer: bill_first_version.drawer.to_owned(),
            payee: bill_first_version.payee.to_owned(),
            endorsee: last_endorsee,
        })
    }

    /// For each block, adds the decrypted and serialized plaintext data next to it
    /// This is an expensive operation, since it deserialized, decrypts and reserializes the block data
    /// validating the integrity of the data at the end
    pub fn get_chain_with_plaintext_block_data(
        &self,
        bill_keys: &BillKeys,
    ) -> Result<Vec<BillBlockPlaintextWrapper>> {
        let mut result = Vec::with_capacity(self.blocks().len());
        for block in self.blocks.iter() {
            let plaintext_data_bytes = match block.op_code() {
                BillOpCode::Issue => {
                    borsh::to_vec(&block.get_decrypted_block::<BillIssueBlockData>(bill_keys)?)?
                }
                BillOpCode::Accept => {
                    borsh::to_vec(&block.get_decrypted_block::<BillAcceptBlockData>(bill_keys)?)?
                }
                BillOpCode::Endorse => {
                    borsh::to_vec(&block.get_decrypted_block::<BillEndorseBlockData>(bill_keys)?)?
                }
                BillOpCode::RequestToAccept => borsh::to_vec(
                    &block.get_decrypted_block::<BillRequestToAcceptBlockData>(bill_keys)?,
                )?,
                BillOpCode::RequestToPay => borsh::to_vec(
                    &block.get_decrypted_block::<BillRequestToPayBlockData>(bill_keys)?,
                )?,
                BillOpCode::OfferToSell => borsh::to_vec(
                    &block.get_decrypted_block::<BillOfferToSellBlockData>(bill_keys)?,
                )?,
                BillOpCode::Sell => {
                    borsh::to_vec(&block.get_decrypted_block::<BillSellBlockData>(bill_keys)?)?
                }
                BillOpCode::Mint => {
                    borsh::to_vec(&block.get_decrypted_block::<BillMintBlockData>(bill_keys)?)?
                }
                BillOpCode::RejectToAccept => {
                    borsh::to_vec(&block.get_decrypted_block::<BillRejectBlockData>(bill_keys)?)?
                }
                BillOpCode::RejectToPay => {
                    borsh::to_vec(&block.get_decrypted_block::<BillRejectBlockData>(bill_keys)?)?
                }
                BillOpCode::RejectToBuy => {
                    borsh::to_vec(&block.get_decrypted_block::<BillRejectBlockData>(bill_keys)?)?
                }
                BillOpCode::RejectToPayRecourse => {
                    borsh::to_vec(&block.get_decrypted_block::<BillRejectBlockData>(bill_keys)?)?
                }
                BillOpCode::RequestRecourse => borsh::to_vec(
                    &block.get_decrypted_block::<BillRequestRecourseBlockData>(bill_keys)?,
                )?,
                BillOpCode::Recourse => {
                    borsh::to_vec(&block.get_decrypted_block::<BillRecourseBlockData>(bill_keys)?)?
                }
            };

            if block.plaintext_hash != util::sha256_hash(&plaintext_data_bytes) {
                return Err(Error::BlockInvalid);
            }

            result.push(BillBlockPlaintextWrapper {
                block: block.clone(),
                plaintext_data_bytes,
            });
        }

        // Validate the chain from the wrapper
        BillBlockchain::new_from_blocks(
            result
                .iter()
                .map(|wrapper| wrapper.block.to_owned())
                .collect::<Vec<BillBlock>>(),
        )?;

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        blockchain::bill::{
            block::{BillOfferToSellBlockData, BillRecourseReasonBlockData},
            tests::get_baseline_identity,
        },
        contact::BillIdentParticipant,
        tests::tests::{
            VALID_PAYMENT_ADDRESS_TESTNET, bill_id_test, bill_identified_participant_only_node_id,
            bill_participant_only_node_id, empty_bitcredit_bill, get_bill_keys, private_key_test,
            valid_address,
        },
    };

    fn get_offer_to_sell_block(
        buyer_node_id: NodeId,
        seller_node_id: NodeId,
        previous_block: &BillBlock,
    ) -> BillBlock {
        let buyer = bill_participant_only_node_id(buyer_node_id);
        let seller = bill_participant_only_node_id(seller_node_id);

        BillBlock::create_block_for_offer_to_sell(
            bill_id_test(),
            previous_block,
            &BillOfferToSellBlockData {
                buyer: buyer.clone().into(),
                seller: seller.clone().into(),
                sum: 5000,
                currency: "sat".to_string(),
                payment_address: "1234".to_string(),
                signatory: None,
                signing_timestamp: 1731593928,
                signing_address: Some(valid_address()),
            },
            &get_baseline_identity().key_pair,
            None,
            &BcrKeys::from_private_key(&private_key_test()).unwrap(),
            1731593928,
        )
        .unwrap()
    }

    #[test]
    fn validity_check_1_block_always_valid() {
        let bill = empty_bitcredit_bill();
        let identity = get_baseline_identity();

        let chain = BillBlockchain::new(
            &BillIssueBlockData::from(bill, None, 1731593928),
            identity.key_pair,
            None,
            BcrKeys::from_private_key(&private_key_test()).unwrap(),
            1731593928,
        )
        .unwrap();

        assert!(chain.is_chain_valid());
    }

    #[test]
    fn validity_check_2_blocks() {
        let bill = empty_bitcredit_bill();
        let identity = get_baseline_identity();

        let mut chain = BillBlockchain::new(
            &BillIssueBlockData::from(bill, None, 1731593928),
            identity.key_pair,
            None,
            BcrKeys::from_private_key(&private_key_test()).unwrap(),
            1731593928,
        )
        .unwrap();
        assert!(chain.try_add_block(get_offer_to_sell_block(
            NodeId::new(BcrKeys::new().pub_key(), bitcoin::Network::Testnet),
            identity.identity.node_id,
            chain.get_first_block()
        ),));
        assert!(chain.is_chain_valid());
    }

    #[test]
    fn is_last_sell_block_waiting_for_payment_deadline_passed() {
        let bill = empty_bitcredit_bill();
        let identity = get_baseline_identity();

        let mut chain = BillBlockchain::new(
            &BillIssueBlockData::from(bill, None, 1731593928),
            identity.key_pair,
            None,
            BcrKeys::from_private_key(&private_key_test()).unwrap(),
            1731593928,
        )
        .unwrap();
        let node_id_last_endorsee =
            NodeId::new(BcrKeys::new().pub_key(), bitcoin::Network::Testnet);
        assert!(chain.try_add_block(get_offer_to_sell_block(
            node_id_last_endorsee.clone(),
            identity.identity.node_id,
            chain.get_first_block()
        ),));

        let keys = get_bill_keys();
        let result = chain.is_last_offer_to_sell_block_waiting_for_payment(&keys, 1751293728); // deadline
        // passed
        assert!(result.is_ok());
        assert_eq!(result.as_ref().unwrap(), &OfferToSellWaitingForPayment::No);
    }

    #[test]
    fn is_last_sell_block_waiting_for_payment_baseline() {
        let bill = empty_bitcredit_bill();
        let identity = get_baseline_identity();

        let mut chain = BillBlockchain::new(
            &BillIssueBlockData::from(bill, None, 1731593928),
            identity.key_pair,
            None,
            BcrKeys::from_private_key(&private_key_test()).unwrap(),
            1731593928,
        )
        .unwrap();
        let node_id_last_endorsee =
            NodeId::new(BcrKeys::new().pub_key(), bitcoin::Network::Testnet);
        assert!(chain.try_add_block(get_offer_to_sell_block(
            node_id_last_endorsee.clone(),
            identity.identity.node_id,
            chain.get_first_block()
        ),));

        let keys = get_bill_keys();
        let result = chain.is_last_offer_to_sell_block_waiting_for_payment(&keys, 1731593928);

        assert!(result.is_ok());
        if let OfferToSellWaitingForPayment::Yes(info) = result.unwrap() {
            assert_eq!(info.sum, 5000);
            assert_eq!(info.buyer.node_id(), node_id_last_endorsee);
        } else {
            panic!("wrong result");
        }
    }

    #[test]
    fn get_all_nodes_from_bill_baseline() {
        let mut bill = empty_bitcredit_bill();
        let identity = get_baseline_identity();
        bill.drawer = BillIdentParticipant::new(identity.identity.clone()).unwrap();
        bill.drawee = BillIdentParticipant::new(identity.identity.clone()).unwrap();
        bill.payee = bill_participant_only_node_id(NodeId::new(
            BcrKeys::new().pub_key(),
            bitcoin::Network::Testnet,
        ));

        let mut chain = BillBlockchain::new(
            &BillIssueBlockData::from(bill, None, 1731593928),
            identity.key_pair,
            None,
            BcrKeys::from_private_key(&private_key_test()).unwrap(),
            1731593928,
        )
        .unwrap();
        let node_id_last_endorsee =
            NodeId::new(BcrKeys::new().pub_key(), bitcoin::Network::Testnet);
        assert!(chain.try_add_block(get_offer_to_sell_block(
            node_id_last_endorsee.clone(),
            identity.identity.node_id.to_owned(),
            chain.get_first_block()
        )));

        let keys = get_bill_keys();
        let result = chain.get_all_nodes_from_bill(&keys);

        let with_blocks = chain.get_all_nodes_with_added_block_height(&keys).unwrap();
        assert_eq!(
            with_blocks[&identity.identity.node_id], 1,
            "Block 1 should have added drawer node_id"
        );
        assert_eq!(
            with_blocks[&node_id_last_endorsee], 2,
            "Block 2 should have added the new node_id"
        );

        assert!(result.is_ok());
        assert_eq!(result.as_ref().unwrap().len(), 3); // drawer, buyer, seller
    }

    #[test]
    fn get_blocks_to_add_from_other_chain_no_changes() {
        let bill = empty_bitcredit_bill();
        let identity = get_baseline_identity();

        let mut chain = BillBlockchain::new(
            &BillIssueBlockData::from(bill, None, 1731593928),
            identity.key_pair,
            None,
            BcrKeys::from_private_key(&private_key_test()).unwrap(),
            1731593928,
        )
        .unwrap();
        let chain2 = chain.clone();
        let node_id_last_endorsee =
            NodeId::new(BcrKeys::new().pub_key(), bitcoin::Network::Testnet);
        assert!(chain.try_add_block(get_offer_to_sell_block(
            node_id_last_endorsee.clone(),
            identity.identity.node_id,
            chain.get_first_block()
        ),));

        let result = chain.get_blocks_to_add_from_other_chain(&chain2);

        assert!(result.is_empty());
    }

    #[test]
    fn get_blocks_to_add_from_other_chain_changes() {
        let bill = empty_bitcredit_bill();
        let identity = get_baseline_identity();

        let mut chain = BillBlockchain::new(
            &BillIssueBlockData::from(bill, None, 1731593928),
            identity.key_pair,
            None,
            BcrKeys::from_private_key(&private_key_test()).unwrap(),
            1731593928,
        )
        .unwrap();
        let mut chain2 = chain.clone();
        let node_id_last_endorsee =
            NodeId::new(BcrKeys::new().pub_key(), bitcoin::Network::Testnet);
        assert!(chain.try_add_block(get_offer_to_sell_block(
            node_id_last_endorsee.clone(),
            identity.identity.node_id,
            chain.get_first_block()
        ),));

        let result = chain2.get_blocks_to_add_from_other_chain(&chain);

        assert!(!result.is_empty());
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, 2);
    }

    #[test]
    fn test_get_serialized_chain_with_plaintext() {
        let bill = empty_bitcredit_bill();
        let bill_maturity_date = bill.maturity_date.clone();
        let bill_sum = bill.sum;
        let bill_id = bill.id.clone();
        let bill_keys = get_bill_keys();
        let identity = get_baseline_identity();
        let mut chain = BillBlockchain::new(
            &BillIssueBlockData::from(bill, None, 1731593928),
            identity.key_pair.clone(),
            None,
            BcrKeys::from_private_key(&bill_keys.private_key).unwrap(),
            1731593928,
        )
        .unwrap();
        let signer = bill_identified_participant_only_node_id(NodeId::new(
            identity.key_pair.pub_key(),
            bitcoin::Network::Testnet,
        ));
        let other_party = bill_identified_participant_only_node_id(NodeId::new(
            BcrKeys::new().pub_key(),
            bitcoin::Network::Testnet,
        ));
        let offer_to_sell = get_offer_to_sell_block(
            other_party.node_id.clone(),
            identity.identity.node_id.to_owned(),
            chain.get_first_block(),
        );
        assert!(chain.try_add_block(offer_to_sell.clone()));
        assert_eq!(
            chain
                .get_bill_parties(
                    &bill_keys,
                    &chain.get_first_version_bill(&bill_keys).unwrap(),
                )
                .unwrap(),
            get_bill_parties_from_chain_with_plaintext(
                chain
                    .get_chain_with_plaintext_block_data(&bill_keys)
                    .as_ref()
                    .unwrap()
            )
            .unwrap()
        );
        let sell = BillBlock::create_block_for_sell(
            bill_id.clone(),
            &offer_to_sell,
            &BillSellBlockData {
                seller: BillParticipant::Ident(signer.clone()).into(),
                buyer: BillParticipant::Ident(other_party.clone()).into(),
                sum: 5000,
                currency: "sat".to_string(),
                payment_address: VALID_PAYMENT_ADDRESS_TESTNET.to_string(),
                signatory: None,
                signing_timestamp: 1731593929,
                signing_address: Some(signer.postal_address.clone()),
            },
            &identity.key_pair,
            None,
            &BcrKeys::from_private_key(&bill_keys.private_key).unwrap(),
            1731593929,
        )
        .unwrap();
        assert!(chain.try_add_block(sell.clone()));
        assert_eq!(
            chain
                .get_bill_parties(
                    &bill_keys,
                    &chain.get_first_version_bill(&bill_keys).unwrap(),
                )
                .unwrap(),
            get_bill_parties_from_chain_with_plaintext(
                chain
                    .get_chain_with_plaintext_block_data(&bill_keys)
                    .as_ref()
                    .unwrap()
            )
            .unwrap()
        );
        let endorse = BillBlock::create_block_for_endorse(
            bill_id.clone(),
            &sell,
            &BillEndorseBlockData {
                endorser: BillParticipant::Ident(other_party.clone()).into(),
                endorsee: BillParticipant::Ident(signer.clone()).into(),
                signatory: None,
                signing_timestamp: 1731593930,
                signing_address: Some(signer.postal_address.clone()),
            },
            &identity.key_pair,
            None,
            &BcrKeys::from_private_key(&bill_keys.private_key).unwrap(),
            1731593930,
        )
        .unwrap();
        assert!(chain.try_add_block(endorse.clone()));
        assert_eq!(
            chain
                .get_bill_parties(
                    &bill_keys,
                    &chain.get_first_version_bill(&bill_keys).unwrap(),
                )
                .unwrap(),
            get_bill_parties_from_chain_with_plaintext(
                chain
                    .get_chain_with_plaintext_block_data(&bill_keys)
                    .as_ref()
                    .unwrap()
            )
            .unwrap()
        );
        let mint = BillBlock::create_block_for_mint(
            bill_id.clone(),
            &endorse,
            &BillMintBlockData {
                endorser: BillParticipant::Ident(signer.clone()).into(),
                endorsee: BillParticipant::Ident(other_party.clone()).into(),
                sum: 5000,
                currency: "sat".to_string(),
                signatory: None,
                signing_timestamp: 1731593931,
                signing_address: Some(signer.postal_address.clone()),
            },
            &identity.key_pair,
            None,
            &BcrKeys::from_private_key(&bill_keys.private_key).unwrap(),
            1731593931,
        )
        .unwrap();
        assert!(chain.try_add_block(mint.clone()));
        assert_eq!(
            chain
                .get_bill_parties(
                    &bill_keys,
                    &chain.get_first_version_bill(&bill_keys).unwrap(),
                )
                .unwrap(),
            get_bill_parties_from_chain_with_plaintext(
                chain
                    .get_chain_with_plaintext_block_data(&bill_keys)
                    .as_ref()
                    .unwrap()
            )
            .unwrap()
        );
        let recourse = BillBlock::create_block_for_recourse(
            bill_id.clone(),
            &mint,
            &BillRecourseBlockData {
                recourser: other_party.clone().into(),
                recoursee: signer.clone().into(),
                sum: 15000,
                currency: "sat".to_string(),
                recourse_reason: BillRecourseReasonBlockData::Pay,
                signatory: None,
                signing_timestamp: 1731593932,
                signing_address: signer.postal_address.clone(),
            },
            &identity.key_pair,
            None,
            &BcrKeys::from_private_key(&bill_keys.private_key).unwrap(),
            1731593932,
        )
        .unwrap();
        assert!(chain.try_add_block(recourse.clone()));

        let chain_with_plaintext = chain.get_chain_with_plaintext_block_data(&bill_keys);
        assert!(chain_with_plaintext.is_ok());
        assert_eq!(chain_with_plaintext.as_ref().unwrap().len(), 6);

        let first = chain_with_plaintext.as_ref().unwrap()[0].clone();
        let decrypted_block_data: BillIssueBlockData =
            borsh::from_slice(&first.plaintext_data_bytes).unwrap();
        assert_eq!(decrypted_block_data.id, bill_id);
        let bill_data = chain_with_plaintext.as_ref().unwrap()[0]
            .clone()
            .get_bill_data()
            .unwrap();
        assert_eq!(bill_data.id, bill_id);
        assert_eq!(bill_data.sum, bill_sum);
        assert_eq!(bill_data.maturity_date, bill_maturity_date);

        let second = chain_with_plaintext.as_ref().unwrap()[1].clone();
        let decrypted_block_data: BillOfferToSellBlockData =
            borsh::from_slice(&second.plaintext_data_bytes).unwrap();
        assert_eq!(decrypted_block_data.buyer.node_id(), other_party.node_id);

        assert_eq!(
            chain
                .get_bill_parties(
                    &bill_keys,
                    &chain.get_first_version_bill(&bill_keys).unwrap(),
                )
                .unwrap(),
            get_bill_parties_from_chain_with_plaintext(
                chain
                    .get_chain_with_plaintext_block_data(&bill_keys)
                    .as_ref()
                    .unwrap()
            )
            .unwrap()
        );

        assert_eq!(
            chain.get_endorsees_for_bill(&bill_keys),
            get_endorsees_from_chain_with_plaintext(
                chain
                    .get_chain_with_plaintext_block_data(&bill_keys)
                    .as_ref()
                    .unwrap()
            )
        )
    }
}
