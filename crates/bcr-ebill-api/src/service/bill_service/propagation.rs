use std::collections::HashMap;

use crate::service::bill_service::blocks::PreparedSignerBlocks;

use super::{BillAction, Result, service::BillService};
use bcr_common::core::NodeId;
use bcr_ebill_core::{
    application::{
        contact::Contact,
        identity::{Identity, IdentityWithAll},
    },
    protocol::{
        blockchain::bill::{BillBlockchain, RecourseReason},
        crypto::BcrKeys,
        event::{ActionType, BillChainEvent, CompanyChainEvent, IdentityChainEvent},
    },
};

impl BillService {
    pub(super) async fn propagate_prepared_signer_blocks(
        &self,
        prepared: &PreparedSignerBlocks,
        identity: &IdentityWithAll,
    ) -> Result<()> {
        if let Some(company) = &prepared.company_block {
            self.transport_service
                .block_transport()
                .send_company_chain_events(CompanyChainEvent::new(
                    &company.company_id,
                    &company.chain,
                    &company.company_keys,
                    None,
                    true,
                ))
                .await?;
        }

        self.transport_service
            .block_transport()
            .send_identity_chain_events(IdentityChainEvent::new(
                &identity.identity.node_id,
                &prepared.identity_block,
                &identity.key_pair,
            ))
            .await?;

        Ok(())
    }
    pub(super) async fn notify_for_block_action(
        &self,
        blockchain: &BillBlockchain,
        bill_keys: &BcrKeys,
        bill_action: &BillAction,
        identity: &Identity,
        contacts: &HashMap<NodeId, Contact>,
        signer_node_id: &NodeId,
    ) -> Result<()> {
        let last_version_bill = self
            .get_last_version_bill(blockchain, bill_keys, identity, contacts)
            .await?;

        let chain_event = BillChainEvent::new(
            &last_version_bill,
            blockchain,
            bill_keys,
            true,
            signer_node_id,
        )?;

        match bill_action {
            BillAction::Accept => {
                self.transport_service
                    .send_bill_is_accepted_event(&chain_event)
                    .await?;
            }
            BillAction::RequestAcceptance(_) => {
                self.transport_service
                    .send_request_to_accept_event(&chain_event)
                    .await?;
            }
            BillAction::RequestToPay(_, _, _) => {
                self.transport_service
                    .send_request_to_pay_event(&chain_event)
                    .await?;
            }
            BillAction::RequestRecourse(recoursee, recourse_reason, _) => {
                let action_type = match recourse_reason {
                    RecourseReason::Accept => ActionType::AcceptBill,
                    RecourseReason::Pay(_) => ActionType::PayBill,
                };
                self.transport_service
                    .send_recourse_action_event(&chain_event, action_type, recoursee)
                    .await?;
            }
            BillAction::Recourse(recoursee) => {
                self.transport_service
                    .send_bill_recourse_paid_event(&chain_event, recoursee)
                    .await?;
            }
            BillAction::Mint(_, _) => {
                self.transport_service
                    .send_bill_is_endorsed_event(&chain_event)
                    .await?;
            }
            BillAction::OfferToSell(buyer, _, _) => {
                self.transport_service
                    .send_offer_to_sell_event(&chain_event, buyer)
                    .await?;
            }
            BillAction::Sell(buyer) => {
                self.transport_service
                    .send_bill_is_sold_event(&chain_event, buyer)
                    .await?;
            }
            BillAction::Endorse(_) => {
                self.transport_service
                    .send_bill_is_endorsed_event(&chain_event)
                    .await?;
            }
            BillAction::RejectAcceptance => {
                self.transport_service
                    .send_request_to_action_rejected_event(&chain_event, ActionType::AcceptBill)
                    .await?;
            }
            BillAction::RejectBuying => {
                self.transport_service
                    .send_request_to_action_rejected_event(&chain_event, ActionType::BuyBill)
                    .await?;
            }
            BillAction::RejectPayment => {
                self.transport_service
                    .send_request_to_action_rejected_event(&chain_event, ActionType::PayBill)
                    .await?;
            }
            BillAction::RejectPaymentForRecourse => {
                self.transport_service
                    .send_request_to_action_rejected_event(&chain_event, ActionType::RecourseBill)
                    .await?;
            }
        };
        Ok(())
    }
}
