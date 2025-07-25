use std::collections::HashMap;

use crate::service::notification_service::event::BillChainEvent;

use super::{BillAction, Result, service::BillService};
use bcr_ebill_core::{
    NodeId,
    bill::{BillKeys, RecourseReason},
    blockchain::bill::BillBlockchain,
    contact::Contact,
    identity::Identity,
    notification::ActionType,
};

impl BillService {
    pub(super) async fn notify_for_block_action(
        &self,
        blockchain: &BillBlockchain,
        bill_keys: &BillKeys,
        bill_action: &BillAction,
        identity: &Identity,
        contacts: &HashMap<NodeId, Contact>,
    ) -> Result<()> {
        let last_version_bill = self
            .get_last_version_bill(blockchain, bill_keys, identity, contacts)
            .await?;

        let chain_event = BillChainEvent::new(
            &last_version_bill,
            blockchain,
            bill_keys,
            true,
            &identity.node_id,
        )?;

        match bill_action {
            BillAction::Accept => {
                self.notification_service
                    .send_bill_is_accepted_event(&chain_event)
                    .await?;
            }
            BillAction::RequestAcceptance => {
                self.notification_service
                    .send_request_to_accept_event(&chain_event)
                    .await?;
            }
            BillAction::RequestToPay(_) => {
                self.notification_service
                    .send_request_to_pay_event(&chain_event)
                    .await?;
            }
            BillAction::RequestRecourse(recoursee, recourse_reason) => {
                let action_type = match recourse_reason {
                    RecourseReason::Accept => ActionType::AcceptBill,
                    RecourseReason::Pay(_, _) => ActionType::PayBill,
                };
                self.notification_service
                    .send_recourse_action_event(&chain_event, action_type, recoursee)
                    .await?;
            }
            BillAction::Recourse(recoursee, _, _, _) => {
                self.notification_service
                    .send_bill_recourse_paid_event(&chain_event, recoursee)
                    .await?;
            }
            BillAction::Mint(_, _, _) => {
                self.notification_service
                    .send_bill_is_endorsed_event(&chain_event)
                    .await?;
            }
            BillAction::OfferToSell(buyer, _, _) => {
                self.notification_service
                    .send_offer_to_sell_event(&chain_event, buyer)
                    .await?;
            }
            BillAction::Sell(buyer, _, _, _) => {
                self.notification_service
                    .send_bill_is_sold_event(&chain_event, buyer)
                    .await?;
            }
            BillAction::Endorse(_) => {
                self.notification_service
                    .send_bill_is_endorsed_event(&chain_event)
                    .await?;
            }
            BillAction::RejectAcceptance => {
                self.notification_service
                    .send_request_to_action_rejected_event(&chain_event, ActionType::AcceptBill)
                    .await?;
            }
            BillAction::RejectBuying => {
                self.notification_service
                    .send_request_to_action_rejected_event(&chain_event, ActionType::BuyBill)
                    .await?;
            }
            BillAction::RejectPayment => {
                self.notification_service
                    .send_request_to_action_rejected_event(&chain_event, ActionType::PayBill)
                    .await?;
            }
            BillAction::RejectPaymentForRecourse => {
                self.notification_service
                    .send_request_to_action_rejected_event(&chain_event, ActionType::RecourseBill)
                    .await?;
            }
        };
        Ok(())
    }
}
