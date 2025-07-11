use bcr_ebill_core::{
    NodeId, Validate, ValidationError,
    bill::{BillId, BillKeys, BitcreditBill, RecourseReason},
    blockchain::{
        self, Blockchain,
        bill::{
            BillBlock, BillBlockchain,
            block::{
                BillAcceptBlockData, BillEndorseBlockData, BillMintBlockData,
                BillOfferToSellBlockData, BillRecourseBlockData, BillRecourseReasonBlockData,
                BillRejectBlockData, BillRejectToBuyBlockData, BillRequestRecourseBlockData,
                BillRequestToAcceptBlockData, BillRequestToPayBlockData, BillSellBlockData,
            },
        },
        company::{CompanyBlock, CompanySignCompanyBillBlockData},
        identity::{
            IdentityBlock, IdentitySignCompanyBillBlockData, IdentitySignPersonBillBlockData,
        },
    },
    company::CompanyKeys,
    contact::{BillParticipant, ContactType},
    identity::IdentityWithAll,
    util::BcrKeys,
};

use crate::data::validate_node_id_network;

use super::{BillAction, Result, error::Error, service::BillService};

impl BillService {
    pub(super) async fn create_blocks_for_bill_action(
        &self,
        bill: &BitcreditBill,
        blockchain: &mut BillBlockchain,
        bill_keys: &BillKeys,
        bill_action: &BillAction,
        signer_public_data: &BillParticipant,
        signer_keys: &BcrKeys,
        identity: &IdentityWithAll,
        timestamp: u64,
    ) -> Result<()> {
        let bill_id = bill.id.clone();
        let signing_keys = self.get_bill_signing_keys(signer_public_data, signer_keys, identity)?;
        let previous_block = blockchain.get_latest_block();

        let holder = match bill.endorsee {
            None => bill.payee.clone(),
            Some(ref endorsee) => endorsee.clone(),
        };

        let holder_is_anon = match holder {
            BillParticipant::Anon(_) => true,
            BillParticipant::Ident(_) => false,
        };

        let block = match bill_action {
            // has to be ident to accept
            BillAction::Accept => {
                if let BillParticipant::Ident(signer) = signer_public_data {
                    let block_data = BillAcceptBlockData {
                        accepter: signer.clone().into(),
                        signatory: signing_keys.signatory_identity,
                        signing_timestamp: timestamp,
                        signing_address: signer.postal_address.clone(),
                    };
                    block_data.validate()?;
                    BillBlock::create_block_for_accept(
                        bill_id.to_owned(),
                        previous_block,
                        &block_data,
                        &signing_keys.signatory_keys,
                        signing_keys.company_keys.as_ref(), // company keys
                        &BcrKeys::from_private_key(&bill_keys.private_key)?,
                        timestamp,
                    )?
                } else {
                    return Err(Error::Validation(ValidationError::SignerCantBeAnon));
                }
            }
            // can req to accept as anon
            BillAction::RequestAcceptance => {
                let block_data = BillRequestToAcceptBlockData {
                    requester: if holder_is_anon {
                        // if holder is anon, we need to continue as anon
                        signer_public_data.as_anon().into()
                    } else {
                        signer_public_data.clone().into()
                    },
                    signatory: signing_keys.signatory_identity,
                    signing_timestamp: timestamp,
                    signing_address: signer_public_data.postal_address(),
                };
                block_data.validate()?;
                BillBlock::create_block_for_request_to_accept(
                    bill_id.to_owned(),
                    previous_block,
                    &block_data,
                    &signing_keys.signatory_keys,
                    signing_keys.company_keys.as_ref(),
                    &BcrKeys::from_private_key(&bill_keys.private_key)?,
                    timestamp,
                )?
            }
            // can req to pay as anon
            BillAction::RequestToPay(currency) => {
                let block_data = BillRequestToPayBlockData {
                    requester: if holder_is_anon {
                        // if holder is anon, we need to continue as anon
                        signer_public_data.as_anon().into()
                    } else {
                        signer_public_data.clone().into()
                    },
                    currency: currency.to_owned(),
                    signatory: signing_keys.signatory_identity,
                    signing_timestamp: timestamp,
                    signing_address: signer_public_data.postal_address(),
                };
                block_data.validate()?;
                BillBlock::create_block_for_request_to_pay(
                    bill_id.to_owned(),
                    previous_block,
                    &block_data,
                    &signing_keys.signatory_keys,
                    signing_keys.company_keys.as_ref(),
                    &BcrKeys::from_private_key(&bill_keys.private_key)?,
                    timestamp,
                )?
            }
            // has to be ident to req recourse
            BillAction::RequestRecourse(recoursee, recourse_reason) => {
                validate_node_id_network(&recoursee.node_id)?;
                if let BillParticipant::Ident(signer) = signer_public_data {
                    let (sum, currency, reason) = match *recourse_reason {
                        RecourseReason::Accept => (
                            bill.sum,
                            bill.currency.clone(),
                            BillRecourseReasonBlockData::Accept,
                        ),
                        RecourseReason::Pay(sum, ref currency) => {
                            (sum, currency.to_owned(), BillRecourseReasonBlockData::Pay)
                        }
                    };
                    let block_data = BillRequestRecourseBlockData {
                        recourser: signer.clone().into(),
                        recoursee: recoursee.clone().into(),
                        sum,
                        currency: currency.to_owned(),
                        recourse_reason: reason,
                        signatory: signing_keys.signatory_identity,
                        signing_timestamp: timestamp,
                        signing_address: signer.postal_address.clone(),
                    };
                    block_data.validate()?;
                    BillBlock::create_block_for_request_recourse(
                        bill_id.to_owned(),
                        previous_block,
                        &block_data,
                        &signing_keys.signatory_keys,
                        signing_keys.company_keys.as_ref(),
                        &BcrKeys::from_private_key(&bill_keys.private_key)?,
                        timestamp,
                    )?
                } else {
                    return Err(Error::Validation(ValidationError::SignerCantBeAnon));
                }
            }
            // has to be ident to recourse
            BillAction::Recourse(recoursee, sum, currency, recourse_reason) => {
                validate_node_id_network(&recoursee.node_id)?;
                if let BillParticipant::Ident(signer) = signer_public_data {
                    let reason = match *recourse_reason {
                        RecourseReason::Accept => BillRecourseReasonBlockData::Accept,
                        RecourseReason::Pay(_, _) => BillRecourseReasonBlockData::Pay,
                    };
                    let block_data = BillRecourseBlockData {
                        recourser: signer.clone().into(),
                        recoursee: recoursee.clone().into(),
                        sum: *sum,
                        currency: currency.to_owned(),
                        recourse_reason: reason,
                        signatory: signing_keys.signatory_identity,
                        signing_timestamp: timestamp,
                        signing_address: signer.postal_address.clone(),
                    };
                    block_data.validate()?;
                    BillBlock::create_block_for_recourse(
                        bill_id.to_owned(),
                        previous_block,
                        &block_data,
                        &signing_keys.signatory_keys,
                        signing_keys.company_keys.as_ref(),
                        &BcrKeys::from_private_key(&bill_keys.private_key)?,
                        timestamp,
                    )?
                } else {
                    return Err(Error::Validation(ValidationError::SignerCantBeAnon));
                }
            }
            // can be anon to mint
            BillAction::Mint(mint, sum, currency) => {
                validate_node_id_network(&mint.node_id())?;
                let block_data = BillMintBlockData {
                    endorser: if holder_is_anon {
                        // if holder is anon, we need to continue as anon
                        signer_public_data.as_anon().into()
                    } else {
                        signer_public_data.clone().into()
                    },
                    endorsee: mint.clone().into(),
                    currency: currency.to_owned(),
                    sum: *sum,
                    signatory: signing_keys.signatory_identity,
                    signing_timestamp: timestamp,
                    signing_address: signer_public_data.postal_address(),
                };
                block_data.validate()?;
                BillBlock::create_block_for_mint(
                    bill_id.to_owned(),
                    previous_block,
                    &block_data,
                    &signing_keys.signatory_keys,
                    signing_keys.company_keys.as_ref(),
                    &BcrKeys::from_private_key(&bill_keys.private_key)?,
                    timestamp,
                )?
            }
            // can be anon to offer to sell
            BillAction::OfferToSell(buyer, sum, currency) => {
                validate_node_id_network(&buyer.node_id())?;
                let address_to_pay = self.bitcoin_client.get_address_to_pay(
                    &bill_keys.public_key,
                    &signer_public_data.node_id().pub_key(),
                )?;
                let block_data = BillOfferToSellBlockData {
                    seller: if holder_is_anon {
                        // if holder is anon, we need to continue as anon
                        signer_public_data.as_anon().into()
                    } else {
                        signer_public_data.clone().into()
                    },
                    buyer: buyer.clone().into(),
                    currency: currency.to_owned(),
                    sum: *sum,
                    payment_address: address_to_pay,
                    signatory: signing_keys.signatory_identity,
                    signing_timestamp: timestamp,
                    signing_address: signer_public_data.postal_address(),
                };
                block_data.validate()?;
                BillBlock::create_block_for_offer_to_sell(
                    bill_id.to_owned(),
                    previous_block,
                    &block_data,
                    &signing_keys.signatory_keys,
                    signing_keys.company_keys.as_ref(),
                    &BcrKeys::from_private_key(&bill_keys.private_key)?,
                    timestamp,
                )?
            }
            // can be anon to sell
            BillAction::Sell(buyer, sum, currency, payment_address) => {
                validate_node_id_network(&buyer.node_id())?;
                let block_data = BillSellBlockData {
                    seller: if holder_is_anon {
                        // if holder is anon, we need to continue as anon
                        signer_public_data.as_anon().into()
                    } else {
                        signer_public_data.clone().into()
                    },
                    buyer: buyer.clone().into(),
                    currency: currency.to_owned(),
                    sum: *sum,
                    payment_address: payment_address.to_owned(),
                    signatory: signing_keys.signatory_identity,
                    signing_timestamp: timestamp,
                    signing_address: signer_public_data.postal_address(),
                };
                block_data.validate()?;
                BillBlock::create_block_for_sell(
                    bill_id.to_owned(),
                    previous_block,
                    &block_data,
                    &signing_keys.signatory_keys,
                    signing_keys.company_keys.as_ref(),
                    &BcrKeys::from_private_key(&bill_keys.private_key)?,
                    timestamp,
                )?
            }
            // can be anon to endorse
            BillAction::Endorse(endorsee) => {
                validate_node_id_network(&endorsee.node_id())?;
                let block_data = BillEndorseBlockData {
                    endorser: if holder_is_anon {
                        // if holder is anon, we need to continue as anon
                        signer_public_data.as_anon().into()
                    } else {
                        signer_public_data.clone().into()
                    },
                    endorsee: endorsee.clone().into(),
                    signatory: signing_keys.signatory_identity,
                    signing_timestamp: timestamp,
                    signing_address: signer_public_data.postal_address(),
                };
                block_data.validate()?;
                BillBlock::create_block_for_endorse(
                    bill_id.to_owned(),
                    previous_block,
                    &block_data,
                    &signing_keys.signatory_keys,
                    signing_keys.company_keys.as_ref(),
                    &BcrKeys::from_private_key(&bill_keys.private_key)?,
                    timestamp,
                )?
            }
            // has to be ident to reject acceptance
            BillAction::RejectAcceptance => {
                if let BillParticipant::Ident(signer) = signer_public_data {
                    let block_data = BillRejectBlockData {
                        rejecter: signer.clone().into(),
                        signatory: signing_keys.signatory_identity,
                        signing_timestamp: timestamp,
                        signing_address: signer.postal_address.clone(),
                    };
                    block_data.validate()?;
                    BillBlock::create_block_for_reject_to_accept(
                        bill_id.to_owned(),
                        previous_block,
                        &block_data,
                        &signing_keys.signatory_keys,
                        signing_keys.company_keys.as_ref(),
                        &BcrKeys::from_private_key(&bill_keys.private_key)?,
                        timestamp,
                    )?
                } else {
                    return Err(Error::Validation(ValidationError::SignerCantBeAnon));
                }
            }
            // can be anon to reject buying
            BillAction::RejectBuying => {
                let block_data = BillRejectToBuyBlockData {
                    rejecter: if holder_is_anon {
                        // if holder is anon, we need to continue as anon
                        signer_public_data.as_anon().into()
                    } else {
                        signer_public_data.clone().into()
                    },
                    signatory: signing_keys.signatory_identity,
                    signing_timestamp: timestamp,
                    signing_address: signer_public_data.postal_address(),
                };
                block_data.validate()?;
                BillBlock::create_block_for_reject_to_buy(
                    bill_id.to_owned(),
                    previous_block,
                    &block_data,
                    &signing_keys.signatory_keys,
                    signing_keys.company_keys.as_ref(),
                    &BcrKeys::from_private_key(&bill_keys.private_key)?,
                    timestamp,
                )?
            }
            // has to be ident to reject payment
            BillAction::RejectPayment => {
                if let BillParticipant::Ident(signer) = signer_public_data {
                    let block_data = BillRejectBlockData {
                        rejecter: signer.clone().into(),
                        signatory: signing_keys.signatory_identity,
                        signing_timestamp: timestamp,
                        signing_address: signer.postal_address.clone(),
                    };
                    block_data.validate()?;
                    BillBlock::create_block_for_reject_to_pay(
                        bill_id.to_owned(),
                        previous_block,
                        &block_data,
                        &signing_keys.signatory_keys,
                        signing_keys.company_keys.as_ref(),
                        &BcrKeys::from_private_key(&bill_keys.private_key)?,
                        timestamp,
                    )?
                } else {
                    return Err(Error::Validation(ValidationError::SignerCantBeAnon));
                }
            }
            // has to be ident to reject recourse
            BillAction::RejectPaymentForRecourse => {
                if let BillParticipant::Ident(signer) = signer_public_data {
                    let block_data = BillRejectBlockData {
                        rejecter: signer.clone().into(),
                        signatory: signing_keys.signatory_identity,
                        signing_timestamp: timestamp,
                        signing_address: signer.postal_address.clone(),
                    };
                    block_data.validate()?;
                    BillBlock::create_block_for_reject_to_pay_recourse(
                        bill_id.to_owned(),
                        previous_block,
                        &block_data,
                        &signing_keys.signatory_keys,
                        signing_keys.company_keys.as_ref(),
                        &BcrKeys::from_private_key(&bill_keys.private_key)?,
                        timestamp,
                    )?
                } else {
                    return Err(Error::Validation(ValidationError::SignerCantBeAnon));
                }
            }
        };

        self.validate_and_add_block(&bill_id, blockchain, block.clone())
            .await?;

        self.add_identity_and_company_chain_blocks_for_signed_bill_action(
            signer_public_data,
            &bill_id,
            &block,
            &identity.key_pair,
            signer_keys,
            timestamp,
        )
        .await?;

        Ok(())
    }

    pub(super) async fn validate_and_add_block(
        &self,
        bill_id: &BillId,
        blockchain: &mut BillBlockchain,
        new_block: BillBlock,
    ) -> Result<()> {
        let try_add_block = blockchain.try_add_block(new_block.clone());
        if try_add_block && blockchain.is_chain_valid() {
            self.blockchain_store.add_block(bill_id, &new_block).await?;
            Ok(())
        } else {
            Err(Error::Blockchain(blockchain::Error::BlockchainInvalid))
        }
    }

    pub(super) async fn add_identity_and_company_chain_blocks_for_signed_bill_action(
        &self,
        signer_public_data: &BillParticipant,
        bill_id: &BillId,
        block: &BillBlock,
        identity_keys: &BcrKeys,
        signer_keys: &BcrKeys,
        timestamp: u64,
    ) -> Result<()> {
        match signer_public_data {
            BillParticipant::Ident(identified) => {
                match identified.t {
                    ContactType::Person | ContactType::Anon => {
                        self.add_block_to_identity_chain_for_signed_bill_action(
                            bill_id,
                            block,
                            identity_keys,
                            timestamp,
                        )
                        .await?;
                    }
                    ContactType::Company => {
                        self.add_block_to_company_chain_for_signed_bill_action(
                            &identified.node_id, // company id
                            bill_id,
                            block,
                            identity_keys,
                            &CompanyKeys {
                                private_key: signer_keys.get_private_key(),
                                public_key: signer_keys.pub_key(),
                            },
                            timestamp,
                        )
                        .await?;

                        self.add_block_to_identity_chain_for_signed_company_bill_action(
                            &identified.node_id, // company id
                            bill_id,
                            block,
                            identity_keys,
                            timestamp,
                        )
                        .await?;
                    }
                };
            }
            // for anon, we only add to our identity chain, since we're no company
            BillParticipant::Anon(_) => {
                self.add_block_to_identity_chain_for_signed_bill_action(
                    bill_id,
                    block,
                    identity_keys,
                    timestamp,
                )
                .await?;
            }
        }
        Ok(())
    }

    pub(super) async fn add_block_to_identity_chain_for_signed_bill_action(
        &self,
        bill_id: &BillId,
        block: &BillBlock,
        keys: &BcrKeys,
        timestamp: u64,
    ) -> Result<()> {
        let previous_block = self.identity_blockchain_store.get_latest_block().await?;
        let new_block = IdentityBlock::create_block_for_sign_person_bill(
            &previous_block,
            &IdentitySignPersonBillBlockData {
                bill_id: bill_id.to_owned(),
                block_id: block.id,
                block_hash: block.hash.to_owned(),
                operation: block.op_code.clone(),
            },
            keys,
            timestamp,
        )?;
        self.identity_blockchain_store.add_block(&new_block).await?;
        Ok(())
    }

    pub(super) async fn add_block_to_identity_chain_for_signed_company_bill_action(
        &self,
        company_id: &NodeId,
        bill_id: &BillId,
        block: &BillBlock,
        keys: &BcrKeys,
        timestamp: u64,
    ) -> Result<()> {
        let previous_block = self.identity_blockchain_store.get_latest_block().await?;
        let new_block = IdentityBlock::create_block_for_sign_company_bill(
            &previous_block,
            &IdentitySignCompanyBillBlockData {
                bill_id: bill_id.to_owned(),
                block_id: block.id,
                block_hash: block.hash.to_owned(),
                company_id: company_id.to_owned(),
                operation: block.op_code.clone(),
            },
            keys,
            timestamp,
        )?;
        self.identity_blockchain_store.add_block(&new_block).await?;
        Ok(())
    }

    pub(super) async fn add_block_to_company_chain_for_signed_bill_action(
        &self,
        company_id: &NodeId,
        bill_id: &BillId,
        block: &BillBlock,
        signatory_keys: &BcrKeys,
        company_keys: &CompanyKeys,
        timestamp: u64,
    ) -> Result<()> {
        let previous_block = self
            .company_blockchain_store
            .get_latest_block(company_id)
            .await?;
        let new_block = CompanyBlock::create_block_for_sign_company_bill(
            company_id.to_owned(),
            &previous_block,
            &CompanySignCompanyBillBlockData {
                bill_id: bill_id.to_owned(),
                block_id: block.id,
                block_hash: block.hash.to_owned(),
                operation: block.op_code.clone(),
            },
            signatory_keys,
            company_keys,
            timestamp,
        )?;
        self.company_blockchain_store
            .add_block(company_id, &new_block)
            .await?;
        Ok(())
    }
}
