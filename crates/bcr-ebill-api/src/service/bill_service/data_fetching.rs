use crate::util;

use super::service::BillService;
use super::{Error, Result};
use bcr_ebill_core::ValidationError;
use bcr_ebill_core::bill::BillMintStatus;
use bcr_ebill_core::bill::validation::get_expiration_deadline_base_for_req_to_pay;
use bcr_ebill_core::blockchain::bill::block::NodeId;
use bcr_ebill_core::constants::RECOURSE_DEADLINE_SECONDS;
use bcr_ebill_core::contact::{BillParticipant, Contact};
use bcr_ebill_core::identity::IdentityType;
use bcr_ebill_core::{
    bill::{
        BillAcceptanceStatus, BillCurrentWaitingState, BillData, BillKeys, BillParticipants,
        BillPaymentStatus, BillRecourseStatus, BillSellStatus, BillStatus,
        BillWaitingForPaymentState, BillWaitingForRecourseState, BillWaitingForSellState,
        BitcreditBill, BitcreditBillResult,
    },
    blockchain::{
        Blockchain,
        bill::{
            BillBlockchain, BillOpCode, OfferToSellWaitingForPayment, RecourseWaitingForPayment,
            block::BillSignatoryBlockData,
        },
    },
    constants::{ACCEPT_DEADLINE_SECONDS, PAYMENT_DEADLINE_SECONDS},
    contact::ContactType,
    identity::{Identity, IdentityWithAll},
    util::{BcrKeys, currency},
};
use log::{debug, error};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub(super) struct BillSigningKeys {
    pub signatory_keys: BcrKeys,
    pub company_keys: Option<BcrKeys>,
    pub signatory_identity: Option<BillSignatoryBlockData>,
}

impl BillService {
    pub(super) async fn get_last_version_bill(
        &self,
        chain: &BillBlockchain,
        bill_keys: &BillKeys,
        identity: &Identity,
        contacts: &HashMap<String, Contact>,
    ) -> Result<BitcreditBill> {
        let bill_first_version = chain.get_first_version_bill(bill_keys)?;
        let bill_parties = chain.get_bill_parties(bill_keys, &bill_first_version)?;

        let payee = bill_parties.payee;
        let drawee_contact = self
            .extend_bill_chain_identity_data_from_contacts_or_identity(
                bill_parties.drawee,
                identity,
                contacts,
            )
            .await;
        let drawer_contact = self
            .extend_bill_chain_identity_data_from_contacts_or_identity(
                bill_parties.drawer,
                identity,
                contacts,
            )
            .await;
        let payee_contact = self
            .extend_bill_chain_participant_data_from_contacts_or_identity(payee, identity, contacts)
            .await;
        let endorsee_contact = match bill_parties.endorsee {
            Some(endorsee) => {
                let endorsee_contact = self
                    .extend_bill_chain_participant_data_from_contacts_or_identity(
                        endorsee, identity, contacts,
                    )
                    .await;
                Some(endorsee_contact)
            }
            None => None,
        };

        Ok(BitcreditBill {
            id: bill_first_version.id,
            country_of_issuing: bill_first_version.country_of_issuing,
            city_of_issuing: bill_first_version.city_of_issuing,
            drawee: drawee_contact,
            drawer: drawer_contact,
            payee: payee_contact,
            endorsee: endorsee_contact,
            currency: bill_first_version.currency,
            sum: bill_first_version.sum,
            maturity_date: bill_first_version.maturity_date,
            issue_date: bill_first_version.issue_date,
            country_of_payment: bill_first_version.country_of_payment,
            city_of_payment: bill_first_version.city_of_payment,
            language: bill_first_version.language,
            files: bill_first_version.files,
        })
    }

    pub(super) fn get_bill_signing_keys(
        &self,
        signer_public_data: &BillParticipant,
        signer_keys: &BcrKeys,
        signatory_identity: &IdentityWithAll,
    ) -> Result<BillSigningKeys> {
        match signer_public_data {
            BillParticipant::Ident(identified) => {
                let (signatory_keys, company_keys, signatory_identity) = match identified.t {
                    ContactType::Person | ContactType::Anon => (signer_keys.clone(), None, None),
                    ContactType::Company => {
                        if signatory_identity.identity.t == IdentityType::Anon {
                            return Err(Error::Validation(ValidationError::IdentityCantBeAnon));
                        }
                        (
                            signatory_identity.key_pair.clone(),
                            Some(signer_keys.clone()),
                            Some(signatory_identity.identity.clone().into()),
                        )
                    }
                };
                Ok(BillSigningKeys {
                    signatory_keys,
                    company_keys,
                    signatory_identity,
                })
            }
            BillParticipant::Anon(_) => Ok(BillSigningKeys {
                signatory_keys: signer_keys.clone(),
                company_keys: None,
                signatory_identity: None,
            }),
        }
    }

    pub(super) async fn calculate_full_bill(
        &self,
        chain: &BillBlockchain,
        bill_keys: &BillKeys,
        local_identity: &Identity,
        current_identity_node_id: &str,
        current_timestamp: u64,
    ) -> Result<BitcreditBillResult> {
        // fetch contacts to get current contact data for participants
        let contacts = self.contact_store.get_map().await?;

        let bill = self
            .get_last_version_bill(chain, bill_keys, local_identity, &contacts)
            .await?;
        let first_version_bill = chain.get_first_version_bill(bill_keys)?;
        let time_of_drawing = first_version_bill.signing_timestamp;

        let bill_participants = chain.get_all_nodes_from_bill(bill_keys)?;
        let endorsements_count = chain.get_endorsements_for_bill(bill_keys).len() as u64;

        let holder = match bill.endorsee {
            None => &bill.payee,
            Some(ref endorsee) => endorsee,
        };

        let has_mint_requests = self
            .mint_store
            .exists_for_bill(current_identity_node_id, &bill.id)
            .await?;
        let mut paid = false;
        let mut requested_to_pay = false;
        let mut rejected_to_pay = false;
        let mut request_to_pay_timed_out = false;
        let mut time_of_request_to_pay = None;
        if let Some(req_to_pay_block) =
            chain.get_last_version_block_with_op_code(BillOpCode::RequestToPay)
        {
            requested_to_pay = true;
            time_of_request_to_pay = Some(req_to_pay_block.timestamp);
            paid = self.store.is_paid(&bill.id).await?;
            rejected_to_pay = chain.block_with_operation_code_exists(BillOpCode::RejectToPay);
            let deadline_base = get_expiration_deadline_base_for_req_to_pay(
                req_to_pay_block.timestamp,
                &bill.maturity_date,
            )?;
            if !paid
                && !rejected_to_pay
                && util::date::check_if_deadline_has_passed(
                    deadline_base,
                    current_timestamp,
                    PAYMENT_DEADLINE_SECONDS,
                )
            {
                // this is true, if the payment is expired (after maturity date)
                request_to_pay_timed_out = true;
            }
        }

        // calculate, if the caller has received funds at any point in the bill
        let mut redeemed_funds_available =
            chain.is_beneficiary_from_a_block(bill_keys, current_identity_node_id);
        if holder.node_id() == current_identity_node_id && paid {
            redeemed_funds_available = true;
        }

        let has_requested_funds =
            chain.is_beneficiary_from_a_request_funds_block(bill_keys, current_identity_node_id);

        let mut offered_to_sell = false;
        let mut rejected_offer_to_sell = false;
        let mut offer_to_sell_timed_out = false;
        let mut sold = false;
        let mut time_of_last_offer_to_sell = None;
        if let Some(last_offer_to_sell_block) =
            chain.get_last_version_block_with_op_code(BillOpCode::OfferToSell)
        {
            time_of_last_offer_to_sell = Some(last_offer_to_sell_block.timestamp);
            offered_to_sell = true;
            if let Some(last_reject_offer_to_sell_block) =
                chain.get_last_version_block_with_op_code(BillOpCode::RejectToBuy)
            {
                if last_reject_offer_to_sell_block.id > last_offer_to_sell_block.id {
                    rejected_offer_to_sell = true;
                }
            }
            if let Some(last_sell_block) =
                chain.get_last_version_block_with_op_code(BillOpCode::Sell)
            {
                if last_sell_block.id > last_offer_to_sell_block.id {
                    // last offer to sell was sold
                    sold = true;
                }
            }
            if !sold
                && !rejected_offer_to_sell
                && util::date::check_if_deadline_has_passed(
                    last_offer_to_sell_block.timestamp,
                    current_timestamp,
                    PAYMENT_DEADLINE_SECONDS,
                )
            {
                offer_to_sell_timed_out = true;
            }
        }

        let mut requested_to_recourse = false;
        let mut request_to_recourse_timed_out = false;
        let mut time_of_last_request_to_recourse = None;
        let mut rejected_request_to_recourse = false;
        let mut recoursed = false;
        if let Some(last_req_to_recourse_block) =
            chain.get_last_version_block_with_op_code(BillOpCode::RequestRecourse)
        {
            requested_to_recourse = true;
            time_of_last_request_to_recourse = Some(last_req_to_recourse_block.timestamp);
            if let Some(last_reject_to_pay_recourse_block) =
                chain.get_last_version_block_with_op_code(BillOpCode::RejectToPayRecourse)
            {
                if last_reject_to_pay_recourse_block.id > last_req_to_recourse_block.id {
                    rejected_request_to_recourse = true;
                }
            }
            if let Some(last_recourse_block) =
                chain.get_last_version_block_with_op_code(BillOpCode::Recourse)
            {
                if last_recourse_block.id > last_req_to_recourse_block.id {
                    recoursed = true
                }
            }
            if !recoursed
                && !rejected_request_to_recourse
                && util::date::check_if_deadline_has_passed(
                    last_req_to_recourse_block.timestamp,
                    current_timestamp,
                    RECOURSE_DEADLINE_SECONDS,
                )
            {
                request_to_recourse_timed_out = true;
            }
        }

        let mut request_to_accept_timed_out = false;
        let rejected_to_accept = chain.block_with_operation_code_exists(BillOpCode::RejectToAccept);
        let accepted = chain.block_with_operation_code_exists(BillOpCode::Accept);
        let mut time_of_request_to_accept = None;
        let mut requested_to_accept = false;
        if let Some(req_to_accept_block) =
            chain.get_last_version_block_with_op_code(BillOpCode::RequestToAccept)
        {
            requested_to_accept = true;
            time_of_request_to_accept = Some(req_to_accept_block.timestamp);

            if !accepted
                && !rejected_to_accept
                && util::date::check_if_deadline_has_passed(
                    req_to_accept_block.timestamp,
                    current_timestamp,
                    ACCEPT_DEADLINE_SECONDS,
                )
            {
                request_to_accept_timed_out = true;
            }
        }

        let last_block = chain.get_latest_block();
        let current_waiting_state = match last_block.op_code {
            BillOpCode::OfferToSell => {
                if let OfferToSellWaitingForPayment::Yes(payment_info) = chain
                    .is_last_offer_to_sell_block_waiting_for_payment(bill_keys, current_timestamp)?
                {
                    // we're waiting, collect data
                    let buyer = self
                        .extend_bill_chain_participant_data_from_contacts_or_identity(
                            payment_info.buyer.clone().into(),
                            local_identity,
                            &contacts,
                        )
                        .await;
                    let seller = self
                        .extend_bill_chain_participant_data_from_contacts_or_identity(
                            payment_info.seller.clone().into(),
                            local_identity,
                            &contacts,
                        )
                        .await;

                    let address_to_pay = payment_info.payment_address;

                    let link_to_pay = self.bitcoin_client.generate_link_to_pay(
                        &address_to_pay,
                        payment_info.sum,
                        &format!("Payment in relation to a bill {}", &bill.id),
                    );

                    let mempool_link_for_address_to_pay = self
                        .bitcoin_client
                        .get_mempool_link_for_address(&address_to_pay);

                    Some(BillCurrentWaitingState::Sell(BillWaitingForSellState {
                        time_of_request: last_block.timestamp,
                        seller,
                        buyer,
                        currency: payment_info.currency,
                        sum: currency::sum_to_string(payment_info.sum),
                        link_to_pay,
                        address_to_pay,
                        mempool_link_for_address_to_pay,
                    }))
                } else {
                    None
                }
            }
            BillOpCode::RequestToPay => {
                if paid {
                    // it's paid - we're not waiting anymore
                    None
                } else if request_to_pay_timed_out {
                    // payment expired, we're not waiting anymore
                    None
                } else if util::date::check_if_deadline_has_passed(
                    last_block.timestamp,
                    current_timestamp,
                    PAYMENT_DEADLINE_SECONDS,
                ) {
                    // the request timed out, we're not waiting anymore, but the payment isn't expired
                    None
                } else {
                    // we're waiting, collect data
                    let address_to_pay = self
                        .bitcoin_client
                        .get_address_to_pay(&bill_keys.public_key, &holder.node_id())?;

                    let link_to_pay = self.bitcoin_client.generate_link_to_pay(
                        &address_to_pay,
                        bill.sum,
                        &format!("Payment in relation to a bill {}", bill.id.clone()),
                    );

                    let mempool_link_for_address_to_pay = self
                        .bitcoin_client
                        .get_mempool_link_for_address(&address_to_pay);

                    Some(BillCurrentWaitingState::Payment(
                        BillWaitingForPaymentState {
                            time_of_request: last_block.timestamp,
                            payer: bill.drawee.clone(),
                            payee: holder.clone(),
                            currency: bill.currency.clone(),
                            sum: currency::sum_to_string(bill.sum),
                            link_to_pay,
                            address_to_pay,
                            mempool_link_for_address_to_pay,
                        },
                    ))
                }
            }
            BillOpCode::RequestRecourse => {
                if let RecourseWaitingForPayment::Yes(payment_info) = chain
                    .is_last_request_to_recourse_block_waiting_for_payment(
                        bill_keys,
                        current_timestamp,
                    )?
                {
                    // we're waiting, collect data
                    let recourser = self
                        .extend_bill_chain_identity_data_from_contacts_or_identity(
                            payment_info.recourser.clone(),
                            local_identity,
                            &contacts,
                        )
                        .await;
                    let recoursee = self
                        .extend_bill_chain_identity_data_from_contacts_or_identity(
                            payment_info.recoursee.clone(),
                            local_identity,
                            &contacts,
                        )
                        .await;

                    let address_to_pay = self.bitcoin_client.get_address_to_pay(
                        &bill_keys.public_key,
                        &payment_info.recourser.node_id,
                    )?;

                    let link_to_pay = self.bitcoin_client.generate_link_to_pay(
                        &address_to_pay,
                        payment_info.sum,
                        &format!("Payment in relation to a bill {}", &bill.id),
                    );

                    let mempool_link_for_address_to_pay = self
                        .bitcoin_client
                        .get_mempool_link_for_address(&address_to_pay);

                    Some(BillCurrentWaitingState::Recourse(
                        BillWaitingForRecourseState {
                            time_of_request: last_block.timestamp,
                            recourser,
                            recoursee,
                            currency: payment_info.currency,
                            sum: currency::sum_to_string(payment_info.sum),
                            link_to_pay,
                            address_to_pay,
                            mempool_link_for_address_to_pay,
                        },
                    ))
                } else {
                    // it timed out, we're not waiting anymore
                    request_to_recourse_timed_out = true;
                    requested_to_recourse = true;
                    None
                }
            }
            _ => None,
        };

        let status = BillStatus {
            acceptance: BillAcceptanceStatus {
                time_of_request_to_accept,
                requested_to_accept,
                accepted,
                request_to_accept_timed_out,
                rejected_to_accept,
            },
            payment: BillPaymentStatus {
                time_of_request_to_pay,
                requested_to_pay,
                paid,
                request_to_pay_timed_out,
                rejected_to_pay,
            },
            sell: BillSellStatus {
                time_of_last_offer_to_sell,
                sold,
                offered_to_sell,
                offer_to_sell_timed_out,
                rejected_offer_to_sell,
            },
            recourse: BillRecourseStatus {
                time_of_last_request_to_recourse,
                recoursed,
                requested_to_recourse,
                request_to_recourse_timed_out,
                rejected_request_to_recourse,
            },
            mint: BillMintStatus { has_mint_requests },
            redeemed_funds_available,
            has_requested_funds,
        };

        let participants = BillParticipants {
            drawee: bill.drawee,
            drawer: bill.drawer,
            payee: bill.payee,
            endorsee: bill.endorsee,
            endorsements_count,
            all_participant_node_ids: bill_participants,
        };

        let bill_data = BillData {
            language: bill.language,
            time_of_drawing,
            issue_date: bill.issue_date,
            time_of_maturity: util::date::date_string_to_timestamp(&bill.maturity_date, None)
                .unwrap_or(0) as u64,
            maturity_date: bill.maturity_date,
            country_of_issuing: bill.country_of_issuing,
            city_of_issuing: bill.city_of_issuing,
            country_of_payment: bill.country_of_payment,
            city_of_payment: bill.city_of_payment,
            currency: bill.currency,
            sum: currency::sum_to_string(bill.sum),
            files: bill.files,
            active_notification: None,
        };

        Ok(BitcreditBillResult {
            id: bill.id,
            participants,
            data: bill_data,
            status,
            current_waiting_state,
        })
    }

    pub(super) fn check_requests_for_expiration(
        &self,
        bill: &BitcreditBillResult,
        current_timestamp: u64,
    ) -> Result<bool> {
        let mut invalidate_and_recalculate = false;
        let acceptance = &bill.status.acceptance;
        // if it was requested, but not "finished" (accepted, rejected, or expired), we have to
        // check if the deadline expired and recalculate
        if acceptance.requested_to_accept
            && !acceptance.accepted
            && !acceptance.rejected_to_accept
            && !acceptance.request_to_accept_timed_out
        {
            if let Some(time_of_request_to_accept) = acceptance.time_of_request_to_accept {
                if util::date::check_if_deadline_has_passed(
                    time_of_request_to_accept,
                    current_timestamp,
                    ACCEPT_DEADLINE_SECONDS,
                ) {
                    invalidate_and_recalculate = true;
                }
            }
        }

        // if it was requested, but not "finished" (paid, rejected, or expired), we have to
        // check if the deadline expired and recalculate
        let payment = &bill.status.payment;
        if payment.requested_to_pay
            && !payment.paid
            && !payment.rejected_to_pay
            && !payment.request_to_pay_timed_out
        {
            if let Some(time_of_request_to_pay) = payment.time_of_request_to_pay {
                let deadline_base = get_expiration_deadline_base_for_req_to_pay(
                    time_of_request_to_pay,
                    &bill.data.maturity_date,
                )?;
                // payment has expired (after maturity date)
                if util::date::check_if_deadline_has_passed(
                    deadline_base,
                    current_timestamp,
                    PAYMENT_DEADLINE_SECONDS,
                ) {
                    invalidate_and_recalculate = true;
                }
                // if it was req to pay and is currently waiting, we have to check, if it's expired
                // once it's expired, we don't have to check this anymore
                if let Some(BillCurrentWaitingState::Payment(_)) = bill.current_waiting_state {
                    // req to pay has expired (before maturity date)
                    if util::date::check_if_deadline_has_passed(
                        time_of_request_to_pay,
                        current_timestamp,
                        PAYMENT_DEADLINE_SECONDS,
                    ) {
                        invalidate_and_recalculate = true;
                    }
                }
            }
        }

        let sell = &bill.status.sell;
        // if it was requested, but not "finished" (sold, rejected, or expired), we have to
        // check if the deadline expired and recalculate
        if sell.offered_to_sell
            && !sell.sold
            && !sell.rejected_offer_to_sell
            && !sell.offer_to_sell_timed_out
        {
            if let Some(time_of_last_offer_to_sell) = sell.time_of_last_offer_to_sell {
                if util::date::check_if_deadline_has_passed(
                    time_of_last_offer_to_sell,
                    current_timestamp,
                    PAYMENT_DEADLINE_SECONDS,
                ) {
                    invalidate_and_recalculate = true;
                }
            }
        }

        let recourse = &bill.status.recourse;
        // if it was requested, but not "finished" (recoursed, rejected, or expired), we have to
        // check if the deadline expired and recalculate
        if recourse.requested_to_recourse
            && !recourse.recoursed
            && !recourse.rejected_request_to_recourse
            && !recourse.request_to_recourse_timed_out
        {
            if let Some(time_of_last_request_to_recourse) =
                recourse.time_of_last_request_to_recourse
            {
                if util::date::check_if_deadline_has_passed(
                    time_of_last_request_to_recourse,
                    current_timestamp,
                    RECOURSE_DEADLINE_SECONDS,
                ) {
                    invalidate_and_recalculate = true;
                }
            }
        }
        Ok(invalidate_and_recalculate)
    }

    pub(super) async fn extend_bill_identities_from_contacts_or_identity(
        &self,
        bill: &mut BitcreditBillResult,
        identity: &Identity,
        contacts: &HashMap<String, Contact>,
    ) {
        bill.participants.payee = self
            .extend_bill_chain_participant_data_from_contacts_or_identity(
                bill.participants.payee.clone().into(),
                identity,
                contacts,
            )
            .await;
        bill.participants.drawee = self
            .extend_bill_chain_identity_data_from_contacts_or_identity(
                bill.participants.drawee.clone().into(),
                identity,
                contacts,
            )
            .await;
        bill.participants.drawer = self
            .extend_bill_chain_identity_data_from_contacts_or_identity(
                bill.participants.drawer.clone().into(),
                identity,
                contacts,
            )
            .await;
        if let Some(endorsee) = bill.participants.endorsee.as_mut() {
            *endorsee = self
                .extend_bill_chain_participant_data_from_contacts_or_identity(
                    endorsee.clone().into(),
                    identity,
                    contacts,
                )
                .await;
        }
        match bill.current_waiting_state.as_mut() {
            None => (),
            Some(BillCurrentWaitingState::Sell(state)) => {
                state.buyer = self
                    .extend_bill_chain_participant_data_from_contacts_or_identity(
                        state.buyer.clone().into(),
                        identity,
                        contacts,
                    )
                    .await;
                state.seller = self
                    .extend_bill_chain_participant_data_from_contacts_or_identity(
                        state.seller.clone().into(),
                        identity,
                        contacts,
                    )
                    .await;
            }
            Some(BillCurrentWaitingState::Payment(state)) => {
                state.payer = self
                    .extend_bill_chain_identity_data_from_contacts_or_identity(
                        state.payer.clone().into(),
                        identity,
                        contacts,
                    )
                    .await;
                state.payee = self
                    .extend_bill_chain_participant_data_from_contacts_or_identity(
                        state.payee.clone().into(),
                        identity,
                        contacts,
                    )
                    .await;
            }
            Some(BillCurrentWaitingState::Recourse(state)) => {
                state.recourser = self
                    .extend_bill_chain_identity_data_from_contacts_or_identity(
                        state.recourser.clone().into(),
                        identity,
                        contacts,
                    )
                    .await;
                state.recoursee = self
                    .extend_bill_chain_identity_data_from_contacts_or_identity(
                        state.recoursee.clone().into(),
                        identity,
                        contacts,
                    )
                    .await;
            }
        };
    }

    pub(super) async fn recalculate_and_cache_bill(
        &self,
        bill_id: &str,
        local_identity: &Identity,
        current_identity_node_id: &str,
        current_timestamp: u64,
    ) -> Result<BitcreditBillResult> {
        let chain = self.blockchain_store.get_chain(bill_id).await?;
        let bill_keys = self.store.get_keys(bill_id).await?;
        let calculated_bill = self
            .calculate_full_bill(
                &chain,
                &bill_keys,
                local_identity,
                current_identity_node_id,
                current_timestamp,
            )
            .await?;
        if let Err(e) = self
            .store
            .save_bill_to_cache(bill_id, &calculated_bill)
            .await
        {
            error!("Error saving calculated bill {bill_id} to cache: {e}");
        }
        Ok(calculated_bill)
    }

    pub(super) async fn get_full_bill(
        &self,
        bill_id: &str,
        local_identity: &Identity,
        current_identity_node_id: &str,
        current_timestamp: u64,
    ) -> Result<BitcreditBillResult> {
        // if there is no such bill, we return an error
        match self.store.exists(bill_id).await {
            Ok(true) => (),
            _ => {
                return Err(Error::NotFound);
            }
        };

        // fetch contacts to get current contact data for participants
        let contacts = self.contact_store.get_map().await?;

        // check if the bill is in the cache
        let bill_cache_result = self.store.get_bill_from_cache(bill_id).await;
        let mut bill = match bill_cache_result {
            Ok(Some(mut bill)) => {
                // update contact data from contact store
                self.extend_bill_identities_from_contacts_or_identity(
                    &mut bill,
                    local_identity,
                    &contacts,
                )
                .await;

                // check requests for being expired - if an active req to
                // accept/pay/recourse/sell is expired, we need to recalculate the bill
                if self.check_requests_for_expiration(&bill, current_timestamp)? {
                    debug!(
                        "Bill cache hit, but needs to recalculate because of request deadline {bill_id} - recalculating"
                    );
                    self.recalculate_and_cache_bill(
                        bill_id,
                        local_identity,
                        current_identity_node_id,
                        current_timestamp,
                    )
                    .await?
                } else {
                    bill
                }
            }
            Ok(None) | Err(_) => {
                // No cache, or error fetching it - recalculate the bill, cache it and return it
                if let Err(e) = bill_cache_result {
                    error!("Error fetching bill {bill_id} from cache: {e}");
                }
                debug!("Bill cache miss for {bill_id} - recalculating");
                self.recalculate_and_cache_bill(
                    bill_id,
                    local_identity,
                    current_identity_node_id,
                    current_timestamp,
                )
                .await?
            }
        };

        // fetch active notification
        let active_notification = self
            .notification_service
            .get_active_bill_notification(&bill.id)
            .await;

        bill.data.active_notification = active_notification;
        Ok(bill)
    }
}
