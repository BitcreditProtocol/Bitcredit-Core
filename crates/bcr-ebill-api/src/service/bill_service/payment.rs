use super::Result;
use super::service::BillService;
use crate::service::bill_service::{BillAction, BillServiceApi};
use bcr_common::core::{BillId, NodeId};
use bcr_ebill_core::{
    application::bill::PaymentState,
    application::company::Company,
    application::identity::{Identity, IdentityWithAll},
    protocol::Timestamp,
    protocol::blockchain::{
        Blockchain,
        bill::{
            BillBlockchain, BillOpCode, BitcreditBill, OfferToSellWaitingForPayment,
            RecourseReason, RecourseWaitingForPayment,
            block::BillRecourseReasonBlockData,
            participant::{BillAnonParticipant, BillIdentParticipant, BillParticipant},
        },
        identity::IdentityType,
    },
    protocol::crypto::BcrKeys,
    protocol::event::BillChainEvent,
};
use log::{debug, info};
use std::collections::HashMap;

impl BillService {
    pub(super) async fn check_bill_payment(
        &self,
        bill_id: &BillId,
        identity: &Identity,
    ) -> Result<()> {
        info!("Checking bill payment for {bill_id}");
        let chain = self.blockchain_store.get_chain(bill_id).await?;
        let bill_keys = self.store.get_keys(bill_id).await?;
        let contacts = self.contact_store.get_map().await?;
        let bill = self
            .get_last_version_bill(&chain, &bill_keys, identity, &contacts)
            .await?;

        if chain.block_with_operation_code_exists(BillOpCode::RequestRecourse) {
            // if the bill is in recourse, we don't have to check payment anymore
            debug!("bill {bill_id} is in recourse - not checking for payment");
            return Ok(());
        }

        let holder_public_key = match bill.endorsee {
            None => &bill.payee.node_id(),
            Some(ref endorsee) => &endorsee.node_id(),
        };
        let address_to_pay = self
            .bitcoin_client
            .get_address_to_pay(&bill_keys.pub_key(), &holder_public_key.pub_key())?;
        match self
            .bitcoin_client
            .check_payment_for_address(&address_to_pay, bill.sum.as_sat())
            .await
        {
            Ok(payment_state) => {
                let should_update = match self
                    .store
                    .get_payment_state(bill_id)
                    .await {
                        // only update if have a different state
                        Ok(Some(prev_payment_state)) => prev_payment_state != payment_state
                        ,
                        // if we don't have a previous payment state, we set the one we got
                        _ => true
                    };

                if should_update {
                    debug!(
                        "Updating bill payment state for {bill_id} to {payment_state:?} and invalidating cache"
                    );
                    self.store
                        .set_payment_state(bill_id, &payment_state)
                        .await?;
                    // invalidate bill cache, so payment state is updated on next fetch
                    self.store.invalidate_bill_in_cache(bill_id).await?;
                    // the bill is paid now - trigger notification
                    if let PaymentState::PaidConfirmed(_) = payment_state
                        && let Err(e) = self
                            .trigger_is_paid_notification(identity, &chain, &bill_keys, &bill)
                            .await
                    {
                        log::error!("Could not send is-paid notification for {bill_id}: {e}");
                    }
                }
            }
            Err(e) => {
                log::error!("Error checking payment for {bill_id}: {e}");
            }
        };
        Ok(())
    }

    async fn trigger_is_paid_notification(
        &self,
        identity: &Identity,
        blockchain: &BillBlockchain,
        bill_keys: &BcrKeys,
        last_version_bill: &BitcreditBill,
    ) -> Result<()> {
        let chain_event = BillChainEvent::new(
            last_version_bill,
            blockchain,
            bill_keys,
            true,
            &identity.node_id, // TODO(company-notifications): how to handle jobs as company participant?
        )?;
        self.transport_service
            .send_bill_is_paid_event(&chain_event)
            .await?;
        Ok(())
    }

    pub(super) async fn check_bill_in_recourse_payment(
        &self,
        bill_id: &BillId,
        identity: &IdentityWithAll,
        now: Timestamp,
    ) -> Result<()> {
        info!("Checking bill recourse payment for {bill_id}");
        let bill_keys = self.store.get_keys(bill_id).await?;
        let chain = self.blockchain_store.get_chain(bill_id).await?;
        let contacts = self.contact_store.get_map().await?;
        if let Ok(RecourseWaitingForPayment::Yes(payment_info)) =
            chain.is_last_request_to_recourse_block_waiting_for_payment(&bill_keys, now)
        {
            // calculate payment address
            let payment_address = self.bitcoin_client.get_address_to_pay(
                &bill_keys.pub_key(),
                &payment_info.recourser.node_id().pub_key(),
            )?;
            // check if paid
            if let Ok(payment_state) = self
                .bitcoin_client
                .check_payment_for_address(&payment_address, payment_info.sum.as_sat())
                .await
            {
                let should_update = match self
                    .store
                    .get_recourse_payment_state(bill_id, payment_info.block_id)
                    .await {
                        // only update if have a different state
                        Ok(Some(prev_payment_state)) => prev_payment_state != payment_state
                        ,
                        // if we don't have a previous payment state, we set the one we got
                        _ => true
                    };

                if should_update {
                    debug!(
                        "Updating bill recourse payment state for {bill_id} to {payment_state:?} and invalidating cache"
                    );
                    self.store
                        .set_recourse_payment_state(bill_id, payment_info.block_id, &payment_state)
                        .await?;
                    // invalidate bill cache, so recourse payment state is updated on next fetch
                    self.store.invalidate_bill_in_cache(bill_id).await?;
                }

                // if recourse was paid, attempt to create recourse block
                if matches!(payment_state, PaymentState::PaidConfirmed(..)) {
                    debug!(
                        "bill {bill_id} is recourse-paid - creating recourse block if we're recourser"
                    );
                    // If we are the recourser and it's paid, we add a Recourse block
                    if payment_info.recourser.node_id() == identity.identity.node_id {
                        let signer_identity = match identity.identity.t {
                            IdentityType::Ident => {
                                if let Ok(signer_identity) =
                                    BillIdentParticipant::new(identity.identity.clone())
                                {
                                    BillParticipant::Ident(signer_identity)
                                } else {
                                    log::error!(
                                        "Signer {} for bill {bill_id} is not a valid signer",
                                        &identity.identity.node_id
                                    );
                                    return Ok(()); // return early
                                }
                            }
                            IdentityType::Anon => BillParticipant::Anon(BillAnonParticipant::new(
                                identity.identity.clone(),
                            )),
                        };
                        let reason = match payment_info.reason {
                            BillRecourseReasonBlockData::Pay => {
                                RecourseReason::Pay(payment_info.sum.clone())
                            }
                            BillRecourseReasonBlockData::Accept => RecourseReason::Accept,
                        };
                        let _ = self
                            .execute_bill_action(
                                bill_id,
                                BillAction::Recourse(
                                    self.extend_bill_chain_identity_data_from_contacts_or_identity(
                                        payment_info.recoursee.clone(),
                                        &identity.identity,
                                        &contacts,
                                    )
                                    .await,
                                    payment_info.sum.clone(),
                                    reason,
                                ),
                                &signer_identity,
                                &identity.key_pair,
                                now,
                            )
                            .await?;
                        return Ok(()); // return early
                    }

                    let local_companies: HashMap<NodeId, (Company, BcrKeys)> =
                        self.company_store.get_all().await?;
                    // If a local company is the recourser, create the recourse block as that company
                    if let Some(recourser_company) =
                        local_companies.get(&payment_info.recourser.node_id())
                        && recourser_company
                            .0
                            .signatories
                            .iter()
                            .any(|s| s == &identity.identity.node_id)
                    {
                        let reason = match payment_info.reason {
                            BillRecourseReasonBlockData::Pay => {
                                RecourseReason::Pay(payment_info.sum.clone())
                            }
                            BillRecourseReasonBlockData::Accept => RecourseReason::Accept,
                        };
                        let _ = self
                            .execute_bill_action(
                                bill_id,
                                BillAction::Recourse(
                                    self.extend_bill_chain_identity_data_from_contacts_or_identity(
                                        payment_info.recoursee.clone(),
                                        &identity.identity,
                                        &contacts,
                                    )
                                    .await,
                                    payment_info.sum.clone(),
                                    reason,
                                ),
                                // signer identity (company)
                                &BillParticipant::Ident(BillIdentParticipant::from(
                                    recourser_company.0.clone(),
                                )),
                                // signer keys (company keys)
                                &BcrKeys::from_private_key(&recourser_company.1.get_private_key()),
                                now,
                            )
                            .await?;
                    }
                }
            }
        }
        Ok(())
    }

    pub(super) async fn check_bill_offer_to_sell_payment(
        &self,
        bill_id: &BillId,
        identity: &IdentityWithAll,
        now: Timestamp,
    ) -> Result<()> {
        info!("Checking bill offer to sell payment for {bill_id}");
        let bill_keys = self.store.get_keys(bill_id).await?;
        let chain = self.blockchain_store.get_chain(bill_id).await?;
        let contacts = self.contact_store.get_map().await?;
        if let Ok(OfferToSellWaitingForPayment::Yes(payment_info)) =
            chain.is_last_offer_to_sell_block_waiting_for_payment(&bill_keys, now)
        {
            // check if paid
            if let Ok(payment_state) = self
                .bitcoin_client
                .check_payment_for_address(&payment_info.payment_address, payment_info.sum.as_sat())
                .await
            {
                let should_update = match self
                    .store
                    .get_offer_to_sell_payment_state(bill_id, payment_info.block_id)
                    .await {
                        // only update if have a different state
                        Ok(Some(prev_payment_state)) => prev_payment_state != payment_state
                        ,
                        // if we don't have a previous payment state, we set the one we got
                        _ => true
                    };
                if should_update {
                    debug!(
                        "Updating bill offer to sell payment state for {bill_id} to {payment_state:?} and invalidating cache"
                    );
                    self.store
                        .set_offer_to_sell_payment_state(
                            bill_id,
                            payment_info.block_id,
                            &payment_state,
                        )
                        .await?;
                    // invalidate bill cache, so offer to sell payment state is updated on next fetch
                    self.store.invalidate_bill_in_cache(bill_id).await?;
                }

                // if offer to sell was paid, attempt to create sell block
                if matches!(payment_state, PaymentState::PaidConfirmed(..)) {
                    debug!("bill {bill_id} got bought - creating sell block if we're seller");
                    // If we are the seller and it's paid, we add a Sell block
                    if payment_info.seller.node_id() == identity.identity.node_id {
                        let signer_identity = match identity.identity.t {
                            IdentityType::Ident => {
                                if let Ok(signer_identity) =
                                    BillIdentParticipant::new(identity.identity.clone())
                                {
                                    BillParticipant::Ident(signer_identity)
                                } else {
                                    log::error!(
                                        "Signer {} for bill {bill_id} is not a valid signer",
                                        &identity.identity.node_id
                                    );
                                    return Ok(()); // return early
                                }
                            }
                            IdentityType::Anon => BillParticipant::Anon(BillAnonParticipant::new(
                                identity.identity.clone(),
                            )),
                        };
                        let _ = self
                        .execute_bill_action(
                            bill_id,
                            BillAction::Sell(
                                self.extend_bill_chain_participant_data_from_contacts_or_identity(
                                    payment_info.buyer.clone().into(),
                                    &identity.identity,
                                    &contacts,
                                )
                                .await,
                                payment_info.sum.clone(),
                                payment_info.payment_address,
                            ),
                            &signer_identity,
                            &identity.key_pair,
                            now,
                        )
                        .await?;
                        return Ok(()); // return early
                    }

                    let local_companies: HashMap<NodeId, (Company, BcrKeys)> =
                        self.company_store.get_all().await?;
                    // If a local company is the seller, create the sell block as that company
                    if let Some(seller_company) =
                        local_companies.get(&payment_info.seller.node_id())
                        && seller_company
                            .0
                            .signatories
                            .iter()
                            .any(|s| s == &identity.identity.node_id)
                    {
                        let _ = self
                                .execute_bill_action(
                                    bill_id,
                                    BillAction::Sell(
                                    self.extend_bill_chain_participant_data_from_contacts_or_identity(
                                        payment_info.buyer.clone().into(),
                                        &identity.identity,
                                        &contacts
                                    )
                                    .await,
                                    payment_info.sum.clone(),
                                    payment_info.payment_address),
                                    // signer identity (company)
                                    &BillParticipant::Ident(BillIdentParticipant::from(seller_company.0.clone())),
                                    // signer keys (company keys)
                                    &BcrKeys::from_private_key(&seller_company.1.get_private_key()),
                                    now,
                                )
                                .await?;
                    }
                }
            }
        }
        Ok(())
    }
}
