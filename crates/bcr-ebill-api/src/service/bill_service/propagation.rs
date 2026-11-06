use super::blocks::PreparedSignerBlocks;
use super::{BillAction, Result, error::Error, service::BillService};
use bcr_common::core::{BillId, NodeId};
use bcr_ebill_core::protocol::blockchain::bill::RecourseReason;
use bcr_ebill_core::{
    application::identity::IdentityWithAll,
    protocol::{
        Timestamp,
        event::{
            ActionType, BillChainEvent, BillChainEventPayload, BillEventType, CompanyChainEvent,
            Event, EventType, IdentityChainEvent,
        },
    },
};
use bcr_ebill_persistence::traits::{
    nostr::NostrChainEvent,
    propagation::{PreparedPropagation, PreparedPropagationMessage, PropagationSubjectType},
};
use log::warn;
use std::collections::HashMap;
use uuid::Uuid;

impl BillService {
    pub(super) async fn prepare_bill_propagation(
        &self,
        bill_id: &BillId,
        identity: &IdentityWithAll,
        signer_steps: &[&PreparedSignerBlocks],
        bill_steps: &[BillChainEvent],
    ) -> Result<PreparedBillPropagation> {
        if signer_steps.is_empty() || signer_steps.len() != bill_steps.len() {
            return Err(Error::Internal(
                "Bill and signer propagation steps do not match".into(),
            ));
        }
        let transport = self.transport_service.block_transport();
        // snapshot of relays to publish to
        let relays = self.transport_service.writable_relay_urls().await?;
        // every bill block has one corresponding identity block
        let identity_events = signer_steps
            .iter()
            .map(|signer| {
                IdentityChainEvent::new(
                    &identity.identity.node_id,
                    &signer.identity_block,
                    &identity.key_pair,
                )
            })
            .collect::<Vec<_>>();

        // a company signer also adds a company block
        // each stored chain is the snapshot after that block
        let company_events = signer_steps
            .iter()
            .filter_map(|signer| {
                signer.company_block.as_ref().map(|company| {
                    CompanyChainEvent::new(
                        &company.company_id,
                        &company.chain,
                        &company.company_keys,
                        None,
                        true,
                    )
                })
            })
            .collect::<Vec<_>>();

        if !company_events.is_empty() && company_events.len() != signer_steps.len() {
            return Err(Error::Internal("Inconsistent company signing steps".into()));
        }
        // prepare chains in order. All events are signed before the transaction, nothing is sent or persisted yet
        let identity_chain_events = transport
            .prepare_identity_chain_events(&identity_events)
            .await?;
        let company_chain_events = transport
            .prepare_company_chain_events(&company_events)
            .await?;
        let bill_chain_events = transport.prepare_bill_chain_events(bill_steps).await?;

        let mut chain_events = Vec::new();
        let mut messages = Vec::new();
        for event in identity_chain_events {
            messages.push(public_message(&event, EventType::IdentityChain, &relays));
            chain_events.push(event);
        }
        for event in company_chain_events {
            messages.push(public_message(&event, EventType::CompanyChain, &relays));
            chain_events.push(event);
        }
        for event in bill_chain_events {
            messages.push(public_message(&event, EventType::BillChain, &relays));
            chain_events.push(event);
        }

        // chain invites
        for event in &company_events {
            messages.extend(transport.prepare_company_chain_invites(event).await?);
        }
        for event in bill_steps {
            messages.extend(transport.prepare_bill_chain_invites(event).await?);
        }

        let propagation = PreparedPropagation {
            id: Uuid::new_v4().to_string(),
            subject_type: PropagationSubjectType::Bill,
            subject_id: bill_id.to_string(),
            created_at: Timestamp::now(),
            messages,
        };
        propagation.validate()?;

        Ok(PreparedBillPropagation {
            propagation,
            chain_events,
            email_notifications: Vec::new(),
        })
    }

    /// add notifications to a propagation, but don't fail on them
    pub(super) async fn add_bill_notifications(
        &self,
        prepared: &mut PreparedBillPropagation,
        bill_event: &BillChainEvent,
        notifications: HashMap<NodeId, Event<BillChainEventPayload>>,
        email_recipients: &[NodeId],
    ) {
        let sender = bill_event.sender();
        match self
            .transport_service
            .prepare_bill_private_messages(&sender, &notifications)
            .await
        {
            Ok(messages) => {
                for message in messages {
                    let mut candidate = prepared.propagation.clone();
                    candidate.messages.push(message.clone());
                    // remove invalid notifications so we don't fail on these later
                    match candidate.validate() {
                        Ok(()) => {
                            prepared.propagation.messages.push(message);
                        }
                        Err(e) => {
                            warn!("Skipping invalid optional Nostr notification: {e}");
                        }
                    }
                }
            }
            Err(e) => {
                warn!("Optional bill notification preparation failed: {e}");
            }
        }
        for recipient in email_recipients {
            if let Some(message) = notifications.get(recipient) {
                prepared.email_notifications.push((
                    sender.clone(),
                    recipient.clone(),
                    message.clone(),
                ));
            }
        }
    }
}

pub(super) struct PreparedBillPropagation {
    pub propagation: PreparedPropagation,
    pub chain_events: Vec<NostrChainEvent>,
    pub email_notifications: Vec<(NodeId, NodeId, Event<BillChainEventPayload>)>,
}

fn public_message(
    event: &NostrChainEvent,
    event_type: EventType,
    relays: &[url::Url],
) -> PreparedPropagationMessage {
    PreparedPropagationMessage {
        id: Uuid::new_v4().to_string(),
        event_type,
        recipient_id: None,
        chain_id: Some(event.chain_id.clone()),
        block_hash: Some(event.block_hash.clone()),
        event: event.payload.clone(),
        target_relays: relays.to_vec(),
    }
}

/// prepare notifications for a given chain event and action
pub(super) fn notifications_for_bill_action(
    event: &BillChainEvent,
    action: &BillAction,
) -> HashMap<NodeId, Event<BillChainEventPayload>> {
    match action {
        BillAction::Accept => event.generate_messages(BillEventType::BillAccepted),
        BillAction::RequestAcceptance(_) => {
            event.generate_messages(BillEventType::BillAcceptanceRequested)
        }
        BillAction::RequestToPay(_, _, _) => {
            event.generate_messages(BillEventType::BillPaymentRequested)
        }
        BillAction::Mint(_, _) | BillAction::Endorse(_) => {
            event.generate_messages(BillEventType::BillEndorsed)
        }
        BillAction::OfferToSell(buyer, _, _) => event.generate_offer_to_sell_messages(buyer),
        BillAction::Sell(buyer) => event.generate_bill_sold_messages(buyer),
        BillAction::RequestRecourse(recoursee, reason, _) => {
            let action = match reason {
                RecourseReason::Accept => ActionType::AcceptBill,
                RecourseReason::Pay(_) => ActionType::PayBill,
            };
            event.generate_recourse_messages(action, recoursee)
        }
        BillAction::Recourse(recoursee) => event.generate_action_messages(
            HashMap::from([(
                recoursee.node_id.clone(),
                (BillEventType::BillRecoursePaid, ActionType::CheckBill),
            )]),
            None,
            None,
        ),
        BillAction::RejectAcceptance => event.generate_rejected_messages(ActionType::AcceptBill),
        BillAction::RejectBuying => event.generate_rejected_messages(ActionType::BuyBill),
        BillAction::RejectPayment => event.generate_rejected_messages(ActionType::PayBill),
        BillAction::RejectPaymentForRecourse => {
            event.generate_rejected_messages(ActionType::RecourseBill)
        }
    }
}

/// calculate email recipients for a given chain event and action
pub(super) fn action_email_recipients(event: &BillChainEvent, action: &BillAction) -> Vec<NodeId> {
    let holder = || {
        event
            .bill
            .endorsee
            .as_ref()
            .map(|e| e.node_id())
            .unwrap_or_else(|| event.bill.payee.node_id())
    };
    let recipient = match action {
        BillAction::Accept
        | BillAction::RejectAcceptance
        | BillAction::RejectBuying
        | BillAction::RejectPayment
        | BillAction::RejectPaymentForRecourse => Some(holder()),
        BillAction::RequestAcceptance(_) | BillAction::RequestToPay(_, _, _) => {
            Some(event.bill.drawee.node_id.clone())
        }
        BillAction::RequestRecourse(recoursee, _, _) | BillAction::Recourse(recoursee) => {
            Some(recoursee.node_id.clone())
        }
        BillAction::Mint(_, _) | BillAction::Endorse(_) => {
            event.bill.endorsee.as_ref().map(|e| e.node_id())
        }
        BillAction::OfferToSell(buyer, _, _) | BillAction::Sell(buyer) => Some(buyer.node_id()),
    };
    recipient.into_iter().collect()
}

/// calculate email recipients for the bill issue
pub(super) fn issue_email_recipients(event: &BillChainEvent) -> Vec<NodeId> {
    let drawer = event.bill.drawer.node_id.clone();
    let drawee = event.bill.drawee.node_id.clone();
    let payee = event.bill.payee.node_id();
    let mut recipients = Vec::new();
    if drawer != payee || drawer == drawee {
        recipients.push(payee.clone());
    }
    if drawer != drawee || drawer == payee {
        recipients.push(drawee);
    }
    recipients
}
