use crate::util;

use super::service::BillService;
use super::{Error, Result};
use bcr_ebill_core::bill::validation::get_expiration_deadline_base_for_req_to_pay;
use bcr_ebill_core::bill::{
    BillCallerActions, BillCallerBillAction, BillMintStatus, BillShallowValidationData,
    BillValidateActionData, BillValidationActionMode, BillWaitingStatePaymentData, PastEndorsee,
    PaymentState, RecourseReason,
};
use bcr_ebill_core::blockchain::Block;
use bcr_ebill_core::contact::{BillParticipant, Contact};
use bcr_ebill_core::date::Date;
use bcr_ebill_core::identity::IdentityType;
use bcr_ebill_core::{NodeId, Validate, ValidationError};
use bcr_ebill_core::{
    bill::{
        BillAcceptanceStatus, BillCurrentWaitingState, BillData, BillId, BillKeys,
        BillParticipants, BillPaymentStatus, BillRecourseStatus, BillSellStatus, BillStatus,
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
    contact::ContactType,
    identity::{Identity, IdentityWithAll},
    util::{BcrKeys, currency},
};
use log::{debug, error};
use std::collections::HashMap;
use strum::{EnumCount, IntoEnumIterator};

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
        contacts: &HashMap<NodeId, Contact>,
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
        current_identity_node_id: &NodeId,
        current_timestamp: u64,
    ) -> Result<BitcreditBillResult> {
        // fetch contacts to get current contact data for participants
        let contacts = self.contact_store.get_map().await?;

        let bill = self
            .get_last_version_bill(chain, bill_keys, local_identity, &contacts)
            .await?;
        let first_version_bill = chain.get_first_version_bill(bill_keys)?;
        let time_of_drawing = first_version_bill.signing_timestamp;

        let past_endorsees =
            chain.get_past_endorsees_for_bill(bill_keys, current_identity_node_id)?;
        let bill_participants = chain.get_all_nodes_from_bill(bill_keys)?;
        let bill_history = chain.get_bill_history(bill_keys)?;
        let endorsements = bill_history.get_endorsements();
        let endorsements_count = endorsements.len() as u64;

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
        let mut payment_deadline_timestamp = None;
        let mut is_waiting_for_req_to_pay = false;
        if let Some(req_to_pay_block) =
            chain.get_last_version_block_with_op_code(BillOpCode::RequestToPay)
        {
            requested_to_pay = true;
            time_of_request_to_pay = Some(req_to_pay_block.timestamp);
            paid = self.store.is_paid(&bill.id).await?;
            rejected_to_pay = chain.block_with_operation_code_exists(BillOpCode::RejectToPay);
            let (is_expired, payment_deadline) = chain.is_req_to_pay_block_payment_expired(
                req_to_pay_block,
                bill_keys,
                current_timestamp,
                Some(&bill.maturity_date),
            )?;
            payment_deadline_timestamp = Some(payment_deadline);
            if !paid && !rejected_to_pay && is_expired {
                // this is true, if the payment is expired (after maturity date)
                request_to_pay_timed_out = true;
            }
        }

        // calculate, if the caller has received funds at any point in the bill
        let mut redeemed_funds_available =
            chain.is_beneficiary_from_a_block(bill_keys, current_identity_node_id);
        if holder.node_id() == *current_identity_node_id && paid {
            redeemed_funds_available = true;
        }

        let has_requested_funds =
            chain.is_beneficiary_from_a_request_funds_block(bill_keys, current_identity_node_id);

        let mut offered_to_sell = false;
        let mut rejected_offer_to_sell = false;
        let mut offer_to_sell_timed_out = false;
        let mut sold = false;
        let mut time_of_last_offer_to_sell = None;
        let mut buying_deadline_timestamp = None;
        let mut offer_to_sell_waiting_for_payment_state = OfferToSellWaitingForPayment::No;
        if let Some(last_offer_to_sell_block) =
            chain.get_last_version_block_with_op_code(BillOpCode::OfferToSell)
        {
            time_of_last_offer_to_sell = Some(last_offer_to_sell_block.timestamp);
            offered_to_sell = true;
            if let Some(last_reject_offer_to_sell_block) =
                chain.get_last_version_block_with_op_code(BillOpCode::RejectToBuy)
                && last_reject_offer_to_sell_block.id > last_offer_to_sell_block.id
            {
                rejected_offer_to_sell = true;
            }
            if let Some(last_sell_block) =
                chain.get_last_version_block_with_op_code(BillOpCode::Sell)
                && last_sell_block.id > last_offer_to_sell_block.id
            {
                // last offer to sell was sold
                sold = true;
            }
            let (is_expired, buying_deadline) = chain.is_offer_to_sell_block_payment_expired(
                last_offer_to_sell_block,
                bill_keys,
                current_timestamp,
            )?;
            buying_deadline_timestamp = Some(buying_deadline);
            if !sold && !rejected_offer_to_sell && is_expired {
                offer_to_sell_timed_out = true;
            }
        }

        let mut requested_to_recourse = false;
        let mut request_to_recourse_timed_out = false;
        let mut time_of_last_request_to_recourse = None;
        let mut rejected_request_to_recourse = false;
        let mut recoursed = false;
        let mut recourse_deadline_timestamp = None;
        let mut recourse_waiting_for_payment_state = RecourseWaitingForPayment::No;
        if let Some(last_req_to_recourse_block) =
            chain.get_last_version_block_with_op_code(BillOpCode::RequestRecourse)
        {
            requested_to_recourse = true;
            time_of_last_request_to_recourse = Some(last_req_to_recourse_block.timestamp);
            if let Some(last_reject_to_pay_recourse_block) =
                chain.get_last_version_block_with_op_code(BillOpCode::RejectToPayRecourse)
                && last_reject_to_pay_recourse_block.id > last_req_to_recourse_block.id
            {
                rejected_request_to_recourse = true;
            }
            if let Some(last_recourse_block) =
                chain.get_last_version_block_with_op_code(BillOpCode::Recourse)
                && last_recourse_block.id > last_req_to_recourse_block.id
            {
                recoursed = true
            }
            let (is_expired, recourse_deadline) = chain.is_req_to_recourse_block_payment_expired(
                last_req_to_recourse_block,
                bill_keys,
                current_timestamp,
            )?;
            recourse_deadline_timestamp = Some(recourse_deadline);
            if !recoursed && !rejected_request_to_recourse && is_expired {
                request_to_recourse_timed_out = true;
            }
        }

        let mut request_to_accept_timed_out = false;
        let rejected_to_accept = chain.block_with_operation_code_exists(BillOpCode::RejectToAccept);
        let accepted = chain.block_with_operation_code_exists(BillOpCode::Accept);
        let mut time_of_request_to_accept = None;
        let mut requested_to_accept = false;
        let mut acceptance_deadline_timestamp = None;
        if let Some(req_to_accept_block) =
            chain.get_last_version_block_with_op_code(BillOpCode::RequestToAccept)
        {
            requested_to_accept = true;
            time_of_request_to_accept = Some(req_to_accept_block.timestamp);

            let (is_expired, acceptance_deadline) = chain.is_req_to_accept_block_expired(
                req_to_accept_block,
                bill_keys,
                current_timestamp,
            )?;
            acceptance_deadline_timestamp = Some(acceptance_deadline);
            if !accepted && !rejected_to_accept && is_expired {
                request_to_accept_timed_out = true;
            }
        }

        let last_block = chain.get_latest_block();
        let last_block_time = last_block.timestamp();
        let current_waiting_state = match last_block.op_code {
            BillOpCode::OfferToSell => {
                offer_to_sell_waiting_for_payment_state = chain
                    .is_last_offer_to_sell_block_waiting_for_payment(
                        bill_keys,
                        current_timestamp,
                    )?;
                if let OfferToSellWaitingForPayment::Yes(ref payment_info) =
                    offer_to_sell_waiting_for_payment_state
                {
                    // we're waiting, collect data
                    let payment_state = self
                        .store
                        .get_offer_to_sell_payment_state(&bill.id, payment_info.block_id)
                        .await?;

                    let mut tx_id = None;
                    let mut in_mempool = false;
                    let mut confirmations = 0;

                    if let Some(ps) = payment_state {
                        match ps {
                            PaymentState::PaidConfirmed(paid_data)
                            | PaymentState::PaidUnconfirmed(paid_data) => {
                                tx_id = Some(paid_data.tx_id);
                                confirmations = paid_data.confirmations;
                            }
                            PaymentState::InMempool(in_mempool_data) => {
                                tx_id = Some(in_mempool_data.tx_id);
                                in_mempool = true;
                            }
                            PaymentState::NotFound => (),
                        }
                    }

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

                    let address_to_pay = payment_info.payment_address.clone();

                    let link_to_pay = self.bitcoin_client.generate_link_to_pay(
                        &address_to_pay,
                        payment_info.sum,
                        &format!("Payment in relation to a bill {}", &bill.id),
                    );

                    let mempool_link_for_address_to_pay = self
                        .bitcoin_client
                        .get_mempool_link_for_address(&address_to_pay);

                    Some(BillCurrentWaitingState::Sell(BillWaitingForSellState {
                        seller,
                        buyer,
                        payment_data: BillWaitingStatePaymentData {
                            time_of_request: last_block.timestamp,
                            currency: payment_info.currency.clone(),
                            sum: currency::sum_to_string(payment_info.sum),
                            link_to_pay,
                            address_to_pay,
                            mempool_link_for_address_to_pay,
                            tx_id,
                            in_mempool,
                            confirmations,
                            payment_deadline: buying_deadline_timestamp,
                        },
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
                } else if let Some(payment_deadline) = payment_deadline_timestamp
                    && util::date::check_if_deadline_has_passed(payment_deadline, current_timestamp)
                {
                    // the request timed out, we're not waiting anymore, but the payment isn't expired
                    None
                } else {
                    // we're waiting, collect data
                    is_waiting_for_req_to_pay = true;
                    let payment_state = self.store.get_payment_state(&bill.id).await?;

                    let mut tx_id = None;
                    let mut in_mempool = false;
                    let mut confirmations = 0;

                    if let Some(ps) = payment_state {
                        match ps {
                            PaymentState::PaidConfirmed(paid_data)
                            | PaymentState::PaidUnconfirmed(paid_data) => {
                                tx_id = Some(paid_data.tx_id);
                                confirmations = paid_data.confirmations;
                            }
                            PaymentState::InMempool(in_mempool_data) => {
                                tx_id = Some(in_mempool_data.tx_id);
                                in_mempool = true;
                            }
                            PaymentState::NotFound => (),
                        }
                    }
                    let address_to_pay = self
                        .bitcoin_client
                        .get_address_to_pay(&bill_keys.public_key, &holder.node_id().pub_key())?;

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
                            payer: bill.drawee.clone(),
                            payee: holder.clone(),
                            payment_data: BillWaitingStatePaymentData {
                                time_of_request: last_block.timestamp,
                                currency: bill.currency.clone(),
                                sum: currency::sum_to_string(bill.sum),
                                link_to_pay,
                                address_to_pay,
                                mempool_link_for_address_to_pay,
                                tx_id,
                                in_mempool,
                                confirmations,
                                payment_deadline: payment_deadline_timestamp,
                            },
                        },
                    ))
                }
            }
            BillOpCode::RequestRecourse => {
                recourse_waiting_for_payment_state = chain
                    .is_last_request_to_recourse_block_waiting_for_payment(
                        bill_keys,
                        current_timestamp,
                    )?;
                if let RecourseWaitingForPayment::Yes(ref payment_info) =
                    recourse_waiting_for_payment_state
                {
                    // we're waiting, collect data
                    let payment_state = self
                        .store
                        .get_recourse_payment_state(&bill.id, payment_info.block_id)
                        .await?;

                    let mut tx_id = None;
                    let mut in_mempool = false;
                    let mut confirmations = 0;

                    if let Some(ps) = payment_state {
                        match ps {
                            PaymentState::PaidConfirmed(paid_data)
                            | PaymentState::PaidUnconfirmed(paid_data) => {
                                tx_id = Some(paid_data.tx_id);
                                confirmations = paid_data.confirmations;
                            }
                            PaymentState::InMempool(in_mempool_data) => {
                                tx_id = Some(in_mempool_data.tx_id);
                                in_mempool = true;
                            }
                            PaymentState::NotFound => (),
                        }
                    }

                    let recourser = self
                        .extend_bill_chain_participant_data_from_contacts_or_identity(
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
                        &payment_info.recourser.node_id().pub_key(),
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
                            recourser,
                            recoursee,
                            payment_data: BillWaitingStatePaymentData {
                                time_of_request: last_block.timestamp,
                                currency: payment_info.currency.clone(),
                                sum: currency::sum_to_string(payment_info.sum),
                                link_to_pay,
                                address_to_pay,
                                mempool_link_for_address_to_pay,
                                tx_id,
                                in_mempool,
                                confirmations,
                                payment_deadline: recourse_deadline_timestamp,
                            },
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
                acceptance_deadline_timestamp,
            },
            payment: BillPaymentStatus {
                time_of_request_to_pay,
                requested_to_pay,
                paid,
                request_to_pay_timed_out,
                rejected_to_pay,
                payment_deadline_timestamp,
            },
            sell: BillSellStatus {
                time_of_last_offer_to_sell,
                sold,
                offered_to_sell,
                offer_to_sell_timed_out,
                rejected_offer_to_sell,
                buying_deadline_timestamp,
            },
            recourse: BillRecourseStatus {
                time_of_last_request_to_recourse,
                recoursed,
                requested_to_recourse,
                request_to_recourse_timed_out,
                rejected_request_to_recourse,
                recourse_deadline_timestamp,
            },
            mint: BillMintStatus { has_mint_requests },
            redeemed_funds_available,
            has_requested_funds,
            last_block_time,
        };

        let participants = BillParticipants {
            drawee: bill.drawee,
            drawer: bill.drawer,
            payee: bill.payee,
            endorsee: bill.endorsee,
            endorsements,
            endorsements_count,
            all_participant_node_ids: bill_participants,
        };

        let bill_data = BillData {
            time_of_drawing,
            issue_date: bill.issue_date,
            time_of_maturity: bill.maturity_date.to_timestamp(),
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

        let bill_caller_actions = BillCallerActions {
            bill_actions: calculate_possible_bill_actions_for_caller(
                chain.to_owned(),
                participants.drawee.node_id.clone(),
                participants.payee.node_id(),
                participants
                    .endorsee
                    .as_ref()
                    .map(|e| e.node_id())
                    .to_owned(),
                bill_data.maturity_date.clone(),
                bill_keys.to_owned(),
                current_timestamp,
                current_identity_node_id.to_owned(),
                paid,
                is_waiting_for_req_to_pay,
                recourse_waiting_for_payment_state,
                offer_to_sell_waiting_for_payment_state,
                request_to_pay_timed_out,
                request_to_accept_timed_out,
                past_endorsees,
            )?,
        };

        Ok(BitcreditBillResult {
            id: bill.id,
            participants,
            data: bill_data,
            status,
            current_waiting_state,
            history: bill_history,
            actions: bill_caller_actions,
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
            && let Some(acceptance_deadline) = acceptance.acceptance_deadline_timestamp
            && util::date::check_if_deadline_has_passed(acceptance_deadline, current_timestamp)
        {
            invalidate_and_recalculate = true;
        }

        // if it was requested, but not "finished" (paid, rejected, or expired), we have to
        // check if the deadline expired and recalculate
        let payment = &bill.status.payment;
        if payment.requested_to_pay
            && !payment.paid
            && !payment.rejected_to_pay
            && !payment.request_to_pay_timed_out
            && let Some(payment_deadline) = payment.payment_deadline_timestamp
        {
            let deadline_base = get_expiration_deadline_base_for_req_to_pay(
                payment_deadline,
                &bill.data.maturity_date,
            )?;
            // payment has expired (after maturity date)
            if util::date::check_if_deadline_has_passed(deadline_base, current_timestamp) {
                invalidate_and_recalculate = true;
            }
            // if it was req to pay and is currently waiting, we have to check, if it's expired
            // once it's expired, we don't have to check this anymore
            if let Some(BillCurrentWaitingState::Payment(_)) = bill.current_waiting_state {
                // req to pay has expired (before maturity date)
                if util::date::check_if_deadline_has_passed(payment_deadline, current_timestamp) {
                    invalidate_and_recalculate = true;
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
            && let Some(buying_deadline) = sell.buying_deadline_timestamp
            && util::date::check_if_deadline_has_passed(buying_deadline, current_timestamp)
        {
            invalidate_and_recalculate = true;
        }

        let recourse = &bill.status.recourse;
        // if it was requested, but not "finished" (recoursed, rejected, or expired), we have to
        // check if the deadline expired and recalculate
        if recourse.requested_to_recourse
            && !recourse.recoursed
            && !recourse.rejected_request_to_recourse
            && !recourse.request_to_recourse_timed_out
            && let Some(recourse_deadline) = recourse.recourse_deadline_timestamp
            && util::date::check_if_deadline_has_passed(recourse_deadline, current_timestamp)
        {
            invalidate_and_recalculate = true;
        }
        Ok(invalidate_and_recalculate)
    }

    pub(super) async fn extend_bill_identities_from_contacts_or_identity(
        &self,
        bill: &mut BitcreditBillResult,
        identity: &Identity,
        contacts: &HashMap<NodeId, Contact>,
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
                    .extend_bill_chain_participant_data_from_contacts_or_identity(
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
        bill_id: &BillId,
        local_identity: &Identity,
        current_identity_node_id: &NodeId,
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
            .save_bill_to_cache(bill_id, current_identity_node_id, &calculated_bill)
            .await
        {
            error!("Error saving calculated bill {bill_id} to cache: {e}");
        }
        Ok(calculated_bill)
    }

    pub(super) async fn get_full_bill(
        &self,
        bill_id: &BillId,
        local_identity: &Identity,
        current_identity_node_id: &NodeId,
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
        let bill_cache_result = self
            .store
            .get_bill_from_cache(bill_id, current_identity_node_id)
            .await;
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

/// For all possible bill actions, attempt validation
/// If it succeeds -> it's a possible action
/// If it fails -> it's not a possible action
fn calculate_possible_bill_actions_for_caller(
    blockchain: BillBlockchain,
    drawee_node_id: NodeId,
    payee_node_id: NodeId,
    endorsee_node_id: Option<NodeId>,
    maturity_date: Date,
    bill_keys: BillKeys,
    timestamp: u64,
    signer_node_id: NodeId,
    is_paid: bool,
    is_waiting_for_req_to_pay: bool,
    waiting_for_recourse_payment: RecourseWaitingForPayment,
    waiting_for_offer_to_sell: OfferToSellWaitingForPayment,
    is_req_to_pay_expired: bool,
    is_req_to_accept_expired: bool,
    past_endorsees: Vec<PastEndorsee>,
) -> Result<Vec<BillCallerBillAction>> {
    let mut res = Vec::with_capacity(BillCallerBillAction::COUNT);
    // create data once to re-use
    let mut data = BillValidateActionData {
        blockchain,
        drawee_node_id,
        payee_node_id,
        endorsee_node_id,
        maturity_date,
        bill_keys,
        timestamp,
        signer_node_id,
        is_paid,
        mode: BillValidationActionMode::Shallow(BillShallowValidationData {
            bill_action: BillOpCode::Issue, // temp value - overridden in the loop
            is_waiting_for_req_to_pay,
            waiting_for_recourse_payment,
            waiting_for_offer_to_sell,
            is_req_to_pay_expired,
            is_req_to_accept_expired,
            past_endorsees,
            recourse_reason: None,
        }),
    };

    // iterate all actions, modifying the validation data for each action and validating the possible action
    for action in BillCallerBillAction::iter() {
        let recourse_reason: Option<RecourseReason> = match action {
            BillCallerBillAction::RequestRecourseForPayment => {
                // These default values are not used
                Some(RecourseReason::Pay(u64::default(), String::default()))
            }
            BillCallerBillAction::RequestRecourseForAcceptance => Some(RecourseReason::Accept),
            _ => None,
        };
        // always true - needed to access the data in the enum
        if let BillValidationActionMode::Shallow(ref mut validation_data) = data.mode {
            validation_data.bill_action = action.op_code();
            validation_data.recourse_reason = recourse_reason;
        }
        // if it validates successfully, add the action to the list of possible actions
        if let Ok(()) = data.validate() {
            res.push(action.to_owned());
        }
    }
    Ok(res)
}

#[cfg(test)]
pub mod tests {
    use bcr_ebill_core::{
        blockchain::bill::{
            BillBlock,
            block::{BillParticipantBlockData, BillRejectBlockData, BillRequestToAcceptBlockData},
        },
        constants::ACCEPT_DEADLINE_SECONDS,
    };

    use crate::{
        service::bill_service::test_utils::{bill_keys, get_baseline_bill, get_genesis_chain},
        tests::tests::{
            bill_id_test, bill_identified_participant_only_node_id, empty_address, private_key_test,
        },
    };

    use super::*;

    #[test]
    fn test_calculate_possible_bill_actions_for_caller() {
        let bill = get_baseline_bill(&bill_id_test());
        let mut chain = get_genesis_chain(None);
        let drawee = bill.drawee.node_id.clone();
        let payee = bill.payee.node_id().clone();
        let endorsee: Option<NodeId> = None;
        let maturity_date = bill.maturity_date.clone();
        let bill_keys = bill_keys();
        let timestamp = 1731593928;

        let is_paid = false;
        let is_waiting_for_req_to_pay = false;
        let waiting_for_recourse_payment = RecourseWaitingForPayment::No;
        let waiting_for_offer_to_sell = OfferToSellWaitingForPayment::No;
        let is_req_to_pay_expired = false;
        let is_req_to_accept_expired = false;
        let past_endorsees: Vec<PastEndorsee> = vec![];

        // initial bill, called by payee
        let res = calculate_possible_bill_actions_for_caller(
            chain.clone(),
            drawee.clone(),
            payee.clone(),
            endorsee.clone(),
            maturity_date.clone(),
            bill_keys.clone(),
            timestamp,
            payee.clone(), // caller is payee
            is_paid,
            is_waiting_for_req_to_pay,
            waiting_for_recourse_payment.clone(),
            waiting_for_offer_to_sell.clone(),
            is_req_to_pay_expired,
            is_req_to_accept_expired,
            past_endorsees.clone(),
        )
        .expect("to work");

        // holder can OfferToSell, Endorse, Req to Pay, Req to Accept
        assert_eq!(res.len(), 4);
        assert!(res.contains(&BillCallerBillAction::OfferToSell));
        assert!(res.contains(&BillCallerBillAction::Endorse));
        assert!(res.contains(&BillCallerBillAction::RequestToPay));
        assert!(res.contains(&BillCallerBillAction::RequestAcceptance));

        // initial bill, called by drawee
        let res = calculate_possible_bill_actions_for_caller(
            chain.clone(),
            drawee.clone(),
            payee.clone(),
            endorsee.clone(),
            maturity_date.clone(),
            bill_keys.clone(),
            timestamp,
            drawee.clone(), // caller is drawee
            is_paid,
            is_waiting_for_req_to_pay,
            waiting_for_recourse_payment.clone(),
            waiting_for_offer_to_sell.clone(),
            is_req_to_pay_expired,
            is_req_to_accept_expired,
            past_endorsees.clone(),
        )
        .expect("to work");

        // drawee can Reject to Accept, Accept
        assert_eq!(res.len(), 2);
        assert!(res.contains(&BillCallerBillAction::Accept));
        assert!(res.contains(&BillCallerBillAction::RejectAcceptance));

        let latest_block = chain.get_latest_block();
        // add req to accept block
        let req_to_accept = BillBlock::create_block_for_request_to_accept(
            bill_id_test(),
            &latest_block.clone(),
            &BillRequestToAcceptBlockData {
                requester: BillParticipantBlockData::Ident(
                    bill_identified_participant_only_node_id(payee.clone()).into(),
                ),
                signatory: None,
                signing_timestamp: latest_block.timestamp + 1,
                signing_address: Some(empty_address()),
                acceptance_deadline_timestamp: latest_block.timestamp
                    + 1
                    + 2 * ACCEPT_DEADLINE_SECONDS,
            },
            &BcrKeys::from_private_key(&private_key_test()).unwrap(),
            Some(&BcrKeys::from_private_key(&private_key_test()).unwrap()),
            &BcrKeys::from_private_key(&private_key_test()).unwrap(),
            latest_block.timestamp + 1,
        )
        .unwrap();
        assert!(chain.try_add_block(req_to_accept));

        // req to accept bill, called by payee
        let res = calculate_possible_bill_actions_for_caller(
            chain.clone(),
            drawee.clone(),
            payee.clone(),
            endorsee.clone(),
            maturity_date.clone(),
            bill_keys.clone(),
            timestamp,
            payee.clone(), // caller is payee
            is_paid,
            is_waiting_for_req_to_pay,
            waiting_for_recourse_payment.clone(),
            waiting_for_offer_to_sell.clone(),
            is_req_to_pay_expired,
            is_req_to_accept_expired,
            past_endorsees.clone(),
        )
        .expect("to work");

        // holder can OfferToSell, Endorse, Req to Pay
        assert_eq!(res.len(), 3);
        assert!(res.contains(&BillCallerBillAction::OfferToSell));
        assert!(res.contains(&BillCallerBillAction::Endorse));
        assert!(res.contains(&BillCallerBillAction::RequestToPay));

        // req to accept  bill, called by drawee
        let res = calculate_possible_bill_actions_for_caller(
            chain.clone(),
            drawee.clone(),
            payee.clone(),
            endorsee.clone(),
            maturity_date.clone(),
            bill_keys.clone(),
            timestamp,
            drawee.clone(), // caller is drawee
            is_paid,
            is_waiting_for_req_to_pay,
            waiting_for_recourse_payment.clone(),
            waiting_for_offer_to_sell.clone(),
            is_req_to_pay_expired,
            is_req_to_accept_expired,
            past_endorsees.clone(),
        )
        .expect("to work");

        // drawee can Reject to Accept, Accept
        assert_eq!(res.len(), 2);
        assert!(res.contains(&BillCallerBillAction::Accept));
        assert!(res.contains(&BillCallerBillAction::RejectAcceptance));

        let latest_block = chain.get_latest_block();
        // add reject to accept block
        let reject_accept = BillBlock::create_block_for_reject_to_accept(
            bill_id_test(),
            latest_block,
            &BillRejectBlockData {
                rejecter: bill_identified_participant_only_node_id(drawee.clone()).into(),
                signatory: None,
                signing_timestamp: latest_block.timestamp + 1,
                signing_address: empty_address(),
            },
            &BcrKeys::new(),
            None,
            &BcrKeys::from_private_key(&private_key_test()).unwrap(),
            latest_block.timestamp + 1,
        )
        .unwrap();
        chain.try_add_block(reject_accept);

        // reject to accept bill, called by payee
        let res = calculate_possible_bill_actions_for_caller(
            chain.clone(),
            drawee.clone(),
            payee.clone(),
            endorsee.clone(),
            maturity_date.clone(),
            bill_keys.clone(),
            timestamp,
            payee.clone(), // caller is payee
            is_paid,
            is_waiting_for_req_to_pay,
            waiting_for_recourse_payment.clone(),
            waiting_for_offer_to_sell.clone(),
            is_req_to_pay_expired,
            is_req_to_accept_expired,
            past_endorsees.clone(),
        )
        .expect("to work");

        // holder can Request to Recourse for Acceptance
        assert_eq!(res.len(), 1);
        assert!(res.contains(&BillCallerBillAction::RequestRecourseForAcceptance));

        // req to accept  bill, called by drawee
        let res = calculate_possible_bill_actions_for_caller(
            chain.clone(),
            drawee.clone(),
            payee.clone(),
            endorsee.clone(),
            maturity_date.clone(),
            bill_keys.clone(),
            timestamp,
            drawee.clone(), // caller is drawee
            is_paid,
            is_waiting_for_req_to_pay,
            waiting_for_recourse_payment.clone(),
            waiting_for_offer_to_sell.clone(),
            is_req_to_pay_expired,
            is_req_to_accept_expired,
            past_endorsees.clone(),
        )
        .expect("to work");

        // drawee can't do anything
        assert_eq!(res.len(), 0);
    }
}
