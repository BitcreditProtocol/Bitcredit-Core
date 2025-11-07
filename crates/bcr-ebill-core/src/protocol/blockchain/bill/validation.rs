use crate::protocol::blockchain::bill::BillValidationActionMode;
use crate::protocol::blockchain::bill::participant::{BillParticipant, PastEndorsee};
use crate::protocol::{
    Date, ProtocolValidationError, Timestamp, Validate,
    blockchain::{
        Block, Blockchain,
        bill::{
            BillOpCode, OfferToSellWaitingForPayment, RecourseWaitingForPayment,
            block::BillRecourseReasonBlockData,
        },
    },
    constants::PAYMENT_DEADLINE_SECONDS,
};

use super::{BillAction, BillIssueData, BillValidateActionData, RecourseReason};

pub fn validate_bill_issue(data: &BillIssueData) -> Result<(), ProtocolValidationError> {
    // anon users can't issue bill
    if let BillParticipant::Anon(_) = data.drawer_public_data {
        return Err(ProtocolValidationError::SignerCantBeAnon);
    }

    let issue_date_ts = data.issue_date.to_timestamp();
    let maturity_date_ts = data.maturity_date.to_timestamp();
    let start_of_day = data.timestamp.start_of_day();

    if maturity_date_ts < start_of_day {
        return Err(ProtocolValidationError::MaturityDateInThePast);
    }

    if issue_date_ts > maturity_date_ts {
        return Err(ProtocolValidationError::IssueDateAfterMaturityDate);
    }

    if data.drawee == data.payee {
        return Err(ProtocolValidationError::DraweeCantBePayee);
    }
    Ok(())
}

impl Validate for BillValidateActionData {
    fn validate(&self) -> Result<(), ProtocolValidationError> {
        let holder_node_id = match self.endorsee_node_id {
            None => self.payee_node_id.clone(),
            Some(ref endorsee) => endorsee.clone(),
        };

        // If the bill was paid, no further actions are allowed
        if self.is_paid {
            return Err(ProtocolValidationError::BillAlreadyPaid);
        }

        // if the bill was recoursed and there are no past endorsees to recourse against anymore,
        // no further actions are allowed.
        // There is a special case for rejecting recourse, because that's done by the recoursee and
        // if they are the last one in the chain, they don't have any past endorsees anymore.
        if self
            .blockchain
            .block_with_operation_code_exists(BillOpCode::Recourse)
            && !matches!(self.bill_action(), BillOpCode::RejectToPayRecourse)
        {
            let past_holders = self.past_endorsees()?;
            if past_holders.is_empty() {
                return Err(ProtocolValidationError::BillWasRecoursedToTheEnd);
            }
        }

        match self.bill_action() {
            BillOpCode::Accept => {
                self.bill_is_blocked()?;
                self.bill_can_only_be_recoursed()?;
                // not already accepted
                if self
                    .blockchain
                    .block_with_operation_code_exists(BillOpCode::Accept)
                {
                    return Err(ProtocolValidationError::BillAlreadyAccepted);
                }
                // signer is drawee
                if !self.drawee_node_id.eq(&self.signer_node_id) {
                    return Err(ProtocolValidationError::CallerIsNotDrawee);
                }
            }
            BillOpCode::RequestToAccept => {
                self.bill_is_blocked()?;
                self.bill_can_only_be_recoursed()?;
                // not already accepted
                if self
                    .blockchain
                    .block_with_operation_code_exists(BillOpCode::Accept)
                {
                    return Err(ProtocolValidationError::BillAlreadyAccepted);
                }
                // not already requested to accept
                if self
                    .blockchain
                    .block_with_operation_code_exists(BillOpCode::RequestToAccept)
                {
                    return Err(ProtocolValidationError::BillAlreadyRequestedToAccept);
                }
                // the caller has to be the bill holder
                if self.signer_node_id != holder_node_id {
                    return Err(ProtocolValidationError::CallerIsNotHolder);
                }
            }
            BillOpCode::RequestToPay => {
                self.bill_is_blocked()?;
                self.bill_can_only_be_recoursed()?;
                // not already requested to pay - checked above already
                // the caller has to be the bill holder
                if self.signer_node_id != holder_node_id {
                    return Err(ProtocolValidationError::CallerIsNotHolder);
                }
            }
            BillOpCode::RequestRecourse => {
                // not blocked
                self.bill_is_blocked()?;

                // the caller has to be the bill holder
                if self.signer_node_id != holder_node_id {
                    return Err(ProtocolValidationError::CallerIsNotHolder);
                }

                // only check action data for deep validation
                if let BillValidationActionMode::Deep(ref bill_action) = self.mode {
                    if let BillAction::RequestRecourse(recoursee, _, _) = bill_action {
                        // check if given recoursee is past holder for the caller
                        let past_holders = self.past_endorsees()?;

                        if !past_holders
                            .iter()
                            .any(|h| h.pay_to_the_order_of.node_id == recoursee.node_id)
                        {
                            return Err(ProtocolValidationError::RecourseeNotPastHolder);
                        }
                    } else {
                        return Err(ProtocolValidationError::InvalidBillAction);
                    }
                }

                // check that a recourse for the given reason is valid
                match self.req_to_recourse_reason() {
                    None => return Err(ProtocolValidationError::InvalidBillAction),
                    Some(RecourseReason::Accept) => {
                        if let Some(req_to_accept) = self
                            .blockchain
                            .get_last_version_block_with_op_code(BillOpCode::RequestToAccept)
                        {
                            let is_expired = match self.mode {
                                BillValidationActionMode::Deep(_) => {
                                    let (is_expired, _) = self
                                        .blockchain
                                        .is_req_to_accept_block_expired(
                                            req_to_accept,
                                            &self.bill_keys,
                                            self.timestamp,
                                        )
                                        .map_err(|e| {
                                            ProtocolValidationError::Blockchain(e.to_string())
                                        })?;
                                    is_expired
                                }
                                BillValidationActionMode::Shallow(
                                    ref bill_shallow_validation_data,
                                ) => bill_shallow_validation_data.is_req_to_accept_expired,
                            };
                            // only if the request to accept expired or was rejected
                            if !is_expired
                                && !self
                                    .blockchain
                                    .block_with_operation_code_exists(BillOpCode::RejectToAccept)
                            {
                                return Err(ProtocolValidationError::BillRequestToAcceptDidNotExpireAndWasNotRejected);
                            }
                        } else {
                            // if there was no request to accept, only if it was rejected
                            if !self
                                .blockchain
                                .block_with_operation_code_exists(BillOpCode::RejectToAccept)
                            {
                                return Err(ProtocolValidationError::BillRequestToAcceptDidNotExpireAndWasNotRejected);
                            }
                        }
                    }
                    Some(RecourseReason::Pay(_)) => {
                        if let Some(req_to_pay) = self
                            .blockchain
                            .get_last_version_block_with_op_code(BillOpCode::RequestToPay)
                        {
                            // only if the bill is not paid already - checked above
                            let is_expired = match self.mode {
                                BillValidationActionMode::Deep(_) => {
                                    let (is_expired, _) = self
                                        .blockchain
                                        .is_req_to_pay_block_payment_expired(
                                            req_to_pay,
                                            &self.bill_keys,
                                            self.timestamp,
                                            Some(&self.maturity_date),
                                        )
                                        .map_err(|e| {
                                            ProtocolValidationError::Blockchain(e.to_string())
                                        })?;
                                    is_expired
                                }
                                BillValidationActionMode::Shallow(
                                    ref bill_shallow_validation_data,
                                ) => bill_shallow_validation_data.is_req_to_pay_expired,
                            };

                            // only if the deadline to pay expired or was rejected
                            if !is_expired
                                && !self
                                    .blockchain
                                    .block_with_operation_code_exists(BillOpCode::RejectToPay)
                            {
                                return Err(
                                    ProtocolValidationError::BillRequestToPayDidNotExpireAndWasNotRejected,
                                );
                            }
                        } else {
                            return Err(ProtocolValidationError::BillWasNotRequestedToPay);
                        }
                    }
                };
            }
            BillOpCode::Recourse => {
                // not waiting for req to pay
                self.bill_waiting_for_req_to_pay()?;
                // not waiting for offer to sell
                self.bill_waiting_for_offer_to_sell()?;

                // the caller has to be the bill holder
                if self.signer_node_id != holder_node_id {
                    return Err(ProtocolValidationError::CallerIsNotHolder);
                }

                if let RecourseWaitingForPayment::Yes(payment_info) =
                    self.waiting_for_recourse_payment()?
                {
                    // only check action data for deep validation
                    if let BillValidationActionMode::Deep(ref bill_action) = self.mode {
                        if let BillAction::Recourse(recoursee, sum, reason) = bill_action {
                            let recourse_reason = match reason {
                                RecourseReason::Pay(_) => BillRecourseReasonBlockData::Pay,
                                RecourseReason::Accept => BillRecourseReasonBlockData::Accept,
                            };
                            if payment_info.sum != *sum
                                || payment_info.recoursee.node_id != recoursee.node_id
                                || payment_info.recourser.node_id() != self.signer_node_id
                                || payment_info.reason != recourse_reason
                            {
                                return Err(ProtocolValidationError::BillRecourseDataInvalid);
                            }
                        } else {
                            return Err(ProtocolValidationError::InvalidBillAction);
                        }
                    }
                } else {
                    return Err(
                        ProtocolValidationError::BillIsNotRequestedToRecourseAndWaitingForPayment,
                    );
                }
            }
            BillOpCode::Mint => {
                self.bill_is_blocked()?;
                self.bill_can_only_be_recoursed()?;
                // the bill has to have been accepted
                if !self
                    .blockchain
                    .block_with_operation_code_exists(BillOpCode::Accept)
                {
                    return Err(ProtocolValidationError::BillNotAccepted);
                }
                // the caller has to be the bill holder
                if self.signer_node_id != holder_node_id {
                    return Err(ProtocolValidationError::CallerIsNotHolder);
                }
            }
            BillOpCode::OfferToSell => {
                self.bill_is_blocked()?;
                self.bill_can_only_be_recoursed()?;
                // the caller has to be the bill holder
                if self.signer_node_id != holder_node_id {
                    return Err(ProtocolValidationError::CallerIsNotHolder);
                }
            }
            BillOpCode::Sell => {
                // not in recourse
                self.bill_waiting_for_recourse_payment()?;
                // not waiting for req to pay
                self.bill_waiting_for_req_to_pay()?;
                self.bill_can_only_be_recoursed()?;

                // the caller has to be the bill holder
                if self.signer_node_id != holder_node_id {
                    return Err(ProtocolValidationError::CallerIsNotHolder);
                }

                if let Ok(OfferToSellWaitingForPayment::Yes(payment_info)) =
                    self.waiting_for_offer_to_sell()
                {
                    // only check action data for deep validation
                    if let BillValidationActionMode::Deep(ref bill_action) = self.mode {
                        if let BillAction::Sell(buyer, sum, payment_address) = bill_action {
                            if payment_info.sum != *sum
                                || payment_info.payment_address != *payment_address
                                || payment_info.buyer.node_id() != buyer.node_id()
                                || payment_info.seller.node_id() != self.signer_node_id
                            {
                                return Err(ProtocolValidationError::BillSellDataInvalid);
                            }
                        } else {
                            return Err(ProtocolValidationError::InvalidBillAction);
                        }
                    }
                } else {
                    return Err(ProtocolValidationError::BillIsNotOfferToSellWaitingForPayment);
                }
            }
            BillOpCode::Endorse => {
                self.bill_is_blocked()?;
                self.bill_can_only_be_recoursed()?;
                // the caller has to be the bill holder
                if self.signer_node_id != holder_node_id {
                    return Err(ProtocolValidationError::CallerIsNotHolder);
                }
            }
            BillOpCode::RejectToAccept => {
                self.bill_is_blocked()?;
                self.bill_can_only_be_recoursed()?;
                // if the op was already rejected, can't reject again - checked above
                // caller has to be the drawee
                if self.signer_node_id != self.drawee_node_id {
                    return Err(ProtocolValidationError::CallerIsNotDrawee);
                }
                // there is not allowed to be an accept block
                if self
                    .blockchain
                    .block_with_operation_code_exists(BillOpCode::Accept)
                {
                    return Err(ProtocolValidationError::BillAlreadyAccepted);
                }
            }
            BillOpCode::RejectToBuy => {
                // not in recourse
                self.bill_waiting_for_recourse_payment()?;
                // not waiting for req to pay
                self.bill_waiting_for_req_to_pay()?;
                self.bill_can_only_be_recoursed()?;
                // if the op was already rejected, can't reject again
                if BillOpCode::RejectToBuy == *self.blockchain.get_latest_block().op_code() {
                    return Err(ProtocolValidationError::RequestAlreadyRejected);
                }
                // there has to be a offer to sell block that is not expired
                if let OfferToSellWaitingForPayment::Yes(payment_info) =
                    self.waiting_for_offer_to_sell()?
                {
                    // caller has to be buyer of the offer to sell
                    if self.signer_node_id != payment_info.buyer.node_id() {
                        return Err(ProtocolValidationError::CallerIsNotBuyer);
                    }
                } else {
                    return Err(ProtocolValidationError::BillWasNotOfferedToSell);
                }
            }
            BillOpCode::RejectToPay => {
                // not waiting for offer to sell
                self.bill_waiting_for_offer_to_sell()?;
                // not in recourse
                self.bill_waiting_for_recourse_payment()?;
                self.bill_can_only_be_recoursed()?;
                // if the op was already rejected, can't reject again - checked above
                // caller has to be the drawee
                if self.signer_node_id != self.drawee_node_id {
                    return Err(ProtocolValidationError::CallerIsNotDrawee);
                }
                // bill is not paid already - checked above

                // there has to be a request to pay block
                if !self
                    .blockchain
                    .block_with_operation_code_exists(BillOpCode::RequestToPay)
                {
                    return Err(ProtocolValidationError::BillWasNotRequestedToPay);
                }
                // that is not expired - checked above
            }
            BillOpCode::RejectToPayRecourse => {
                // not offered to sell
                self.bill_waiting_for_offer_to_sell()?;
                // not waiting for req to pay
                self.bill_waiting_for_req_to_pay()?;
                // if the op was already rejected, can't reject again
                if BillOpCode::RejectToPayRecourse == *self.blockchain.get_latest_block().op_code()
                {
                    return Err(ProtocolValidationError::RequestAlreadyRejected);
                }
                // there has to be a request to recourse that is not expired
                if let RecourseWaitingForPayment::Yes(payment_info) =
                    self.waiting_for_recourse_payment()?
                {
                    if self.signer_node_id != payment_info.recoursee.node_id {
                        return Err(ProtocolValidationError::CallerIsNotRecoursee);
                    }
                } else {
                    return Err(ProtocolValidationError::BillWasNotRequestedToRecourse);
                }
            }
            _ => return Err(ProtocolValidationError::InvalidBillAction),
        };
        Ok(())
    }
}

/// calculates the expiration deadline of a request to pay - if the deadline was before the
/// maturity date, we take the end of the day of the maturity date, otherwise the end of
/// day of the req to pay deadline
pub fn get_expiration_deadline_base_for_req_to_pay(
    req_to_pay_deadline: Timestamp,
    bill_maturity_date: &Date,
) -> Result<Timestamp, ProtocolValidationError> {
    let maturity_date_plus_min_deadline =
        bill_maturity_date.to_timestamp() + PAYMENT_DEADLINE_SECONDS;
    // we calculate from the end of the day
    let maturity_date_end_of_day = maturity_date_plus_min_deadline.end_of_day();
    // we calculate from the end of the day of the request to pay deadline
    let mut deadline = req_to_pay_deadline.end_of_day();
    // requested to pay deadline after maturity date - deadline is req to pay deadline
    if deadline < maturity_date_end_of_day {
        // deadline to pay before end of day of maturity date - deadline base is maturity
        // date end of day
        deadline = maturity_date_end_of_day;
    }
    Ok(deadline)
}

impl BillValidateActionData {
    /// if the bill was rejected to accept, rejected to pay, or either of them expired, it can only
    /// be recoursed from that point on
    fn bill_can_only_be_recoursed(&self) -> Result<(), ProtocolValidationError> {
        match self.bill_action() {
            BillOpCode::Recourse
            | BillOpCode::RequestRecourse
            | BillOpCode::RejectToPayRecourse => {
                // do nothing, these actions are fine
                Ok(())
            }
            _ => {
                if self
                    .blockchain
                    .block_with_operation_code_exists(BillOpCode::RejectToAccept)
                {
                    return Err(ProtocolValidationError::BillWasRejectedToAccept);
                }

                if self
                    .blockchain
                    .block_with_operation_code_exists(BillOpCode::RejectToPay)
                {
                    return Err(ProtocolValidationError::BillWasRejectedToPay);
                }

                if let Some(req_to_pay_block) = self
                    .blockchain
                    .get_last_version_block_with_op_code(BillOpCode::RequestToPay)
                {
                    let is_expired = match self.mode {
                        BillValidationActionMode::Deep(_) => {
                            let (is_expired, _) = self
                                .blockchain
                                .is_req_to_pay_block_payment_expired(
                                    req_to_pay_block,
                                    &self.bill_keys,
                                    self.timestamp,
                                    Some(&self.maturity_date),
                                )
                                .map_err(|e| ProtocolValidationError::Blockchain(e.to_string()))?;
                            is_expired
                        }
                        BillValidationActionMode::Shallow(ref bill_shallow_validation_data) => {
                            bill_shallow_validation_data.is_req_to_pay_expired
                        }
                    };
                    // not paid and not rejected (checked above)
                    if !self.is_paid && is_expired {
                        return Err(ProtocolValidationError::BillPaymentExpired);
                    }
                }

                if let Some(req_to_accept_block) = self
                    .blockchain
                    .get_last_version_block_with_op_code(BillOpCode::RequestToAccept)
                {
                    let accepted = self
                        .blockchain
                        .block_with_operation_code_exists(BillOpCode::Accept);

                    let is_expired = match self.mode {
                        // for deep validation, calculate the value
                        BillValidationActionMode::Deep(_) => {
                            let (is_expired, _) = self
                                .blockchain
                                .is_req_to_accept_block_expired(
                                    req_to_accept_block,
                                    &self.bill_keys,
                                    self.timestamp,
                                )
                                .map_err(|e| ProtocolValidationError::Blockchain(e.to_string()))?;
                            is_expired
                        }
                        BillValidationActionMode::Shallow(ref bill_shallow_validation_data) => {
                            bill_shallow_validation_data.is_req_to_accept_expired
                        }
                    };
                    // not accepted and not rejected (checked above)
                    if !accepted && is_expired {
                        return Err(ProtocolValidationError::BillAcceptanceExpired);
                    }
                }

                Ok(())
            }
        }
    }

    /// if the bill is waiting for payment, it's blocked
    fn bill_is_blocked(&self) -> Result<(), ProtocolValidationError> {
        // not waiting for req to pay
        self.bill_waiting_for_req_to_pay()?;
        // not offered to sell
        self.bill_waiting_for_offer_to_sell()?;
        // not in recourse
        self.bill_waiting_for_recourse_payment()?;
        Ok(())
    }

    fn bill_waiting_for_offer_to_sell(&self) -> Result<(), ProtocolValidationError> {
        if let OfferToSellWaitingForPayment::Yes(_) = self.waiting_for_offer_to_sell()? {
            return Err(ProtocolValidationError::BillIsOfferedToSellAndWaitingForPayment);
        }
        Ok(())
    }

    fn waiting_for_offer_to_sell(
        &self,
    ) -> Result<OfferToSellWaitingForPayment, ProtocolValidationError> {
        match self.mode {
            BillValidationActionMode::Deep(_) => {
                let res = self
                    .blockchain
                    .is_last_offer_to_sell_block_waiting_for_payment(
                        &self.bill_keys,
                        self.timestamp,
                    )
                    .map_err(|e| ProtocolValidationError::Blockchain(e.to_string()))?;
                Ok(res)
            }
            BillValidationActionMode::Shallow(ref bill_shallow_validation_data) => {
                Ok(bill_shallow_validation_data
                    .waiting_for_offer_to_sell
                    .to_owned())
            }
        }
    }

    fn bill_waiting_for_recourse_payment(&self) -> Result<(), ProtocolValidationError> {
        if let RecourseWaitingForPayment::Yes(_) = self.waiting_for_recourse_payment()? {
            return Err(ProtocolValidationError::BillIsInRecourseAndWaitingForPayment);
        }
        Ok(())
    }

    fn waiting_for_recourse_payment(
        &self,
    ) -> Result<RecourseWaitingForPayment, ProtocolValidationError> {
        match self.mode {
            BillValidationActionMode::Deep(_) => {
                let res = self
                    .blockchain
                    .is_last_request_to_recourse_block_waiting_for_payment(
                        &self.bill_keys,
                        self.timestamp,
                    )
                    .map_err(|e| ProtocolValidationError::Blockchain(e.to_string()))?;
                Ok(res)
            }
            BillValidationActionMode::Shallow(ref bill_shallow_validation_data) => {
                Ok(bill_shallow_validation_data
                    .waiting_for_recourse_payment
                    .to_owned())
            }
        }
    }

    /// active req to pay, calculated from the deadline
    fn bill_waiting_for_req_to_pay(&self) -> Result<(), ProtocolValidationError> {
        match self.mode {
            BillValidationActionMode::Deep(_) => {
                if self.blockchain.get_latest_block().op_code == BillOpCode::RequestToPay
                    && let Some(req_to_pay) = self
                        .blockchain
                        .get_last_version_block_with_op_code(BillOpCode::RequestToPay)
                {
                    let (is_expired, _) = self
                        .blockchain
                        .is_req_to_pay_block_payment_expired(
                            req_to_pay,
                            &self.bill_keys,
                            self.timestamp,
                            None, // not calculated from maturity date
                        )
                        .map_err(|e| ProtocolValidationError::Blockchain(e.to_string()))?;
                    if !self.is_paid && !is_expired {
                        return Err(
                            ProtocolValidationError::BillIsRequestedToPayAndWaitingForPayment,
                        );
                    }
                }
                Ok(())
            }
            BillValidationActionMode::Shallow(ref bill_shallow_validation_data) => {
                if bill_shallow_validation_data.is_waiting_for_req_to_pay {
                    return Err(ProtocolValidationError::BillIsRequestedToPayAndWaitingForPayment);
                }
                Ok(())
            }
        }
    }

    fn past_endorsees(&self) -> Result<Vec<PastEndorsee>, ProtocolValidationError> {
        match self.mode {
            BillValidationActionMode::Deep(_) => {
                let res = self
                    .blockchain
                    .get_past_endorsees_for_bill(&self.bill_keys, &self.signer_node_id)
                    .map_err(|e| ProtocolValidationError::Blockchain(e.to_string()))?;
                Ok(res)
            }
            BillValidationActionMode::Shallow(ref bill_shallow_validation_data) => {
                Ok(bill_shallow_validation_data.past_endorsees.to_owned())
            }
        }
    }

    fn bill_action(&self) -> BillOpCode {
        match self.mode {
            BillValidationActionMode::Deep(ref bill_action) => bill_action.op_code(),
            BillValidationActionMode::Shallow(ref bill_shallow_validation_data) => {
                bill_shallow_validation_data.bill_action.to_owned()
            }
        }
    }

    fn req_to_recourse_reason(&self) -> Option<RecourseReason> {
        match self.mode {
            BillValidationActionMode::Deep(ref bill_action) => match bill_action {
                BillAction::RequestRecourse(_, recourse_reason, _) => {
                    Some(recourse_reason.to_owned())
                }
                _ => None,
            },
            BillValidationActionMode::Shallow(ref bill_shallow_validation_data) => {
                bill_shallow_validation_data.recourse_reason.to_owned()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::{
        City, Country, Currency, Sum,
        blockchain::bill::{
            BillBlock, BillBlockchain,
            block::{
                BillAcceptBlockData, BillEndorseBlockData, BillIssueBlockData,
                BillOfferToSellBlockData, BillRecourseBlockData, BillRejectBlockData,
                BillRejectToBuyBlockData, BillRequestRecourseBlockData,
                BillRequestToAcceptBlockData, BillRequestToPayBlockData,
                tests::valid_bill_issue_block_data,
            },
            participant::BillIdentParticipant,
        },
        constants::{
            ACCEPT_DEADLINE_SECONDS, DAY_IN_SECS, PAYMENT_DEADLINE_SECONDS,
            RECOURSE_DEADLINE_SECONDS,
        },
        crypto::BcrKeys,
        tests::tests::{
            bill_id_test, node_id_test, node_id_test_and_another, node_id_test_other,
            other_valid_payment_address_testnet, private_key_test, safe_deadline_ts, valid_address,
            valid_and_another_bill_identified_participant, valid_bill_identified_participant,
            valid_bill_participant, valid_other_bill_identified_participant,
            valid_other_bill_participant, valid_payment_address_testnet,
        },
    };

    use super::*;
    use rstest::rstest;

    fn valid_bill_issue_data() -> BillIssueData {
        BillIssueData {
            t: 0,
            country_of_issuing: Country::AT,
            city_of_issuing: City::new("Vienna").unwrap(),
            issue_date: Date::new("2025-08-12").unwrap(),
            maturity_date: Date::new("2025-11-12").unwrap(),
            drawee: node_id_test(),
            payee: node_id_test_other(),
            sum: Sum::new_sat(500).expect("sat works"),
            country_of_payment: Country::FR,
            city_of_payment: City::new("Paris").unwrap(),
            file_upload_ids: vec![],
            drawer_public_data: BillParticipant::Ident(valid_bill_identified_participant()),
            drawer_keys: BcrKeys::from_private_key(&private_key_test()),
            timestamp: Timestamp::new(1731593928).unwrap(),
            blank_issue: false,
        }
    }

    #[test]
    fn test_valid_bill_issue_data() {
        let result = validate_bill_issue(&valid_bill_issue_data());
        assert_eq!(result, Ok(()));
    }

    #[rstest]
    #[case::maturity_date_before_now( BillIssueData { maturity_date: Date::new("2004-01-12").unwrap(), ..valid_bill_issue_data() }, ProtocolValidationError::MaturityDateInThePast)]
    #[case::issue_date_after_maturity_date( BillIssueData { issue_date: Date::new("2028-01-12").unwrap(), ..valid_bill_issue_data() }, ProtocolValidationError::IssueDateAfterMaturityDate)]
    #[case::drawee_equals_payee( BillIssueData { drawee: node_id_test(), payee: node_id_test(), ..valid_bill_issue_data() }, ProtocolValidationError::DraweeCantBePayee)]
    fn test_validate_bill_issue_data_errors(
        #[case] input: BillIssueData,
        #[case] expected: ProtocolValidationError,
    ) {
        assert_eq!(validate_bill_issue(&input), Err(expected));
    }

    fn valid_bill_blockchain_issue(issue_block_data: BillIssueBlockData) -> BillBlockchain {
        let chain = BillBlockchain::new(
            &issue_block_data,
            BcrKeys::from_private_key(&private_key_test()),
            None,
            BcrKeys::from_private_key(&private_key_test()),
            Timestamp::now() - 10,
        )
        .unwrap();
        assert!(chain.is_chain_valid());
        chain
    }

    fn keys() -> BcrKeys {
        BcrKeys::from_private_key(&private_key_test())
    }

    fn add_req_to_accept_block(mut chain: BillBlockchain) -> BillBlockchain {
        let ts = chain.get_latest_block().timestamp + 1;
        let block = BillBlock::create_block_for_request_to_accept(
            bill_id_test(),
            chain.get_latest_block(),
            &BillRequestToAcceptBlockData {
                requester: valid_bill_participant().into(),
                signatory: None,
                signing_timestamp: ts,
                signing_address: Some(valid_address()),
                acceptance_deadline_timestamp: ts + 2 * ACCEPT_DEADLINE_SECONDS,
            },
            &keys(),
            None,
            &keys(),
            chain.get_latest_block().timestamp + 1,
        )
        .unwrap();
        assert!(chain.try_add_block(block));
        assert!(chain.is_chain_valid());
        chain
    }

    fn add_endorse_block(
        mut chain: BillBlockchain,
        endorsee: BillIdentParticipant,
        endorser: BillIdentParticipant,
    ) -> BillBlockchain {
        let block = BillBlock::create_block_for_endorse(
            bill_id_test(),
            chain.get_latest_block(),
            &BillEndorseBlockData {
                endorser: BillParticipant::Ident(endorser).into(),
                endorsee: BillParticipant::Ident(endorsee).into(),
                signatory: None,
                signing_timestamp: chain.get_latest_block().timestamp + 1,
                signing_address: Some(valid_address()),
            },
            &keys(),
            None,
            &keys(),
            chain.get_latest_block().timestamp + 1,
        )
        .unwrap();
        assert!(chain.try_add_block(block));
        assert!(chain.is_chain_valid());
        chain
    }

    fn add_accept_block(mut chain: BillBlockchain) -> BillBlockchain {
        let block = BillBlock::create_block_for_accept(
            bill_id_test(),
            chain.get_latest_block(),
            &BillAcceptBlockData {
                accepter: valid_bill_identified_participant().into(),
                signatory: None,
                signing_timestamp: chain.get_latest_block().timestamp + 1,
                signing_address: valid_address(),
            },
            &keys(),
            None,
            &keys(),
            chain.get_latest_block().timestamp + 1,
        )
        .unwrap();
        assert!(chain.try_add_block(block));
        assert!(chain.is_chain_valid());
        chain
    }

    fn add_req_to_pay_block(mut chain: BillBlockchain) -> BillBlockchain {
        let ts = chain.get_latest_block().timestamp + 1;
        let block = BillBlock::create_block_for_request_to_pay(
            bill_id_test(),
            chain.get_latest_block(),
            &BillRequestToPayBlockData {
                requester: valid_bill_participant().into(),
                currency: Currency::sat(),
                signatory: None,
                signing_timestamp: ts,
                signing_address: Some(valid_address()),
                payment_deadline_timestamp: ts + 2 * PAYMENT_DEADLINE_SECONDS,
            },
            &keys(),
            None,
            &keys(),
            chain.get_latest_block().timestamp + 1,
        )
        .unwrap();
        assert!(chain.try_add_block(block));
        assert!(chain.is_chain_valid());
        chain
    }

    fn add_offer_to_sell_block(mut chain: BillBlockchain) -> BillBlockchain {
        let ts = chain.get_latest_block().timestamp + 1;
        let block = BillBlock::create_block_for_offer_to_sell(
            bill_id_test(),
            chain.get_latest_block(),
            &BillOfferToSellBlockData {
                buyer: valid_bill_participant().into(),
                seller: valid_other_bill_participant().into(),
                sum: Sum::new_sat(500).expect("sat works"),
                payment_address: valid_payment_address_testnet(),
                signatory: None,
                signing_timestamp: ts,
                signing_address: Some(valid_address()),
                buying_deadline_timestamp: ts + 2 * DAY_IN_SECS,
            },
            &keys(),
            None,
            &keys(),
            chain.get_latest_block().timestamp + 1,
        )
        .unwrap();
        assert!(chain.try_add_block(block));
        assert!(chain.is_chain_valid());
        chain
    }

    fn add_req_to_recourse_accept_block(mut chain: BillBlockchain) -> BillBlockchain {
        let ts = chain.get_latest_block().timestamp + 1;
        let block = BillBlock::create_block_for_request_recourse(
            bill_id_test(),
            chain.get_latest_block(),
            &BillRequestRecourseBlockData {
                recourser: BillParticipant::Ident(valid_bill_identified_participant()).into(),
                recoursee: valid_other_bill_identified_participant().into(),
                sum: Sum::new_sat(500).expect("sat works"),
                recourse_reason: BillRecourseReasonBlockData::Accept,
                signatory: None,
                signing_timestamp: ts,
                signing_address: Some(valid_address()),
                recourse_deadline_timestamp: ts + 2 * RECOURSE_DEADLINE_SECONDS,
            },
            &keys(),
            None,
            &keys(),
            chain.get_latest_block().timestamp + 1,
        )
        .unwrap();
        assert!(chain.try_add_block(block));
        assert!(chain.is_chain_valid());
        chain
    }

    fn add_req_to_recourse_payment_block(mut chain: BillBlockchain) -> BillBlockchain {
        let ts = chain.get_latest_block().timestamp + 1;
        let block = BillBlock::create_block_for_request_recourse(
            bill_id_test(),
            chain.get_latest_block(),
            &BillRequestRecourseBlockData {
                recourser: BillParticipant::Ident(valid_other_bill_identified_participant()).into(),
                recoursee: valid_bill_identified_participant().into(),
                sum: Sum::new_sat(500).expect("sat works"),
                recourse_reason: BillRecourseReasonBlockData::Pay,
                signatory: None,
                signing_timestamp: ts,
                signing_address: Some(valid_address()),
                recourse_deadline_timestamp: ts + 2 * RECOURSE_DEADLINE_SECONDS,
            },
            &keys(),
            None,
            &keys(),
            chain.get_latest_block().timestamp + 1,
        )
        .unwrap();
        assert!(chain.try_add_block(block));
        assert!(chain.is_chain_valid());
        chain
    }

    fn add_reject_accept_block(mut chain: BillBlockchain) -> BillBlockchain {
        let block = BillBlock::create_block_for_reject_to_accept(
            bill_id_test(),
            chain.get_latest_block(),
            &BillRejectBlockData {
                rejecter: valid_bill_identified_participant().into(),
                signatory: None,
                signing_timestamp: chain.get_latest_block().timestamp + 1,
                signing_address: valid_address(),
            },
            &keys(),
            None,
            &keys(),
            chain.get_latest_block().timestamp + 1,
        )
        .unwrap();
        assert!(chain.try_add_block(block));
        assert!(chain.is_chain_valid());
        chain
    }

    fn add_reject_pay_block(mut chain: BillBlockchain) -> BillBlockchain {
        let block = BillBlock::create_block_for_reject_to_pay(
            bill_id_test(),
            chain.get_latest_block(),
            &BillRejectBlockData {
                rejecter: valid_bill_identified_participant().into(),
                signatory: None,
                signing_timestamp: chain.get_latest_block().timestamp + 1,
                signing_address: valid_address(),
            },
            &keys(),
            None,
            &keys(),
            chain.get_latest_block().timestamp + 1,
        )
        .unwrap();
        assert!(chain.try_add_block(block));
        assert!(chain.is_chain_valid());
        chain
    }

    fn add_reject_buy_block(mut chain: BillBlockchain) -> BillBlockchain {
        let block = BillBlock::create_block_for_reject_to_buy(
            bill_id_test(),
            chain.get_latest_block(),
            &BillRejectToBuyBlockData {
                rejecter: valid_bill_participant().into(),
                signatory: None,
                signing_timestamp: chain.get_latest_block().timestamp + 1,
                signing_address: Some(valid_address()),
            },
            &keys(),
            None,
            &keys(),
            chain.get_latest_block().timestamp + 1,
        )
        .unwrap();
        assert!(chain.try_add_block(block));
        assert!(chain.is_chain_valid());
        chain
    }

    #[allow(dead_code)]
    fn add_reject_recourse_block(mut chain: BillBlockchain) -> BillBlockchain {
        let block = BillBlock::create_block_for_reject_to_pay_recourse(
            bill_id_test(),
            chain.get_latest_block(),
            &BillRejectBlockData {
                rejecter: valid_bill_identified_participant().into(),
                signatory: None,
                signing_timestamp: chain.get_latest_block().timestamp + 1,
                signing_address: valid_address(),
            },
            &keys(),
            None,
            &keys(),
            chain.get_latest_block().timestamp + 1,
        )
        .unwrap();
        assert!(chain.try_add_block(block));
        assert!(chain.is_chain_valid());
        chain
    }

    fn add_recourse_accept_block(mut chain: BillBlockchain) -> BillBlockchain {
        let block = BillBlock::create_block_for_recourse(
            bill_id_test(),
            chain.get_latest_block(),
            &BillRecourseBlockData {
                recourser: BillParticipant::Ident(valid_bill_identified_participant()).into(),
                recoursee: valid_other_bill_identified_participant().into(),
                sum: Sum::new_sat(500).expect("sat works"),
                recourse_reason: BillRecourseReasonBlockData::Accept,
                signatory: None,
                signing_timestamp: chain.get_latest_block().timestamp + 1,
                signing_address: Some(valid_address()),
            },
            &keys(),
            None,
            &keys(),
            chain.get_latest_block().timestamp + 1,
        )
        .unwrap();
        assert!(chain.try_add_block(block));
        assert!(chain.is_chain_valid());
        chain
    }

    fn valid_bill_validate_action_data(chain: BillBlockchain) -> BillValidateActionData {
        BillValidateActionData {
            blockchain: chain,
            drawee_node_id: node_id_test(),
            payee_node_id: node_id_test_other(),
            endorsee_node_id: None,
            maturity_date: Date::new("2024-11-12").unwrap(),
            bill_keys: BcrKeys::from_private_key(&private_key_test()),
            timestamp: Timestamp::now(),
            signer_node_id: node_id_test(),
            is_paid: false,
            mode: BillValidationActionMode::Deep(BillAction::Accept),
        }
    }

    #[rstest]
    #[case::is_paid(BillValidateActionData { is_paid: true, ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Err(ProtocolValidationError::BillAlreadyPaid))]
    #[case::is_not_paid(BillValidateActionData { ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Ok(()))]
    fn test_validate_bill_paid_or_not(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ProtocolValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::accept(BillValidateActionData { drawee_node_id: node_id_test(), ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Ok(()))]
    fn test_validate_bill_accept_valid(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ProtocolValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::last_recourse_blocked(BillValidateActionData { ..valid_bill_validate_action_data(add_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillWasRecoursedToTheEnd))]
    #[case::active_req_to_pay_blocked(BillValidateActionData { ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillIsRequestedToPayAndWaitingForPayment))]
    #[case::active_offer_to_sell_blocked(BillValidateActionData { ..valid_bill_validate_action_data(add_offer_to_sell_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillIsOfferedToSellAndWaitingForPayment))]
    #[case::active_recourse_blocked(BillValidateActionData { ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillIsInRecourseAndWaitingForPayment))]
    #[case::rejected_to_accept_only_recourse(BillValidateActionData { ..valid_bill_validate_action_data(add_reject_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillWasRejectedToAccept))]
    #[case::rejected_to_pay_only_recourse(BillValidateActionData { ..valid_bill_validate_action_data(add_reject_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillWasRejectedToPay))]
    #[case::payment_expired_only_recourse(BillValidateActionData { timestamp: Timestamp::now() + (PAYMENT_DEADLINE_SECONDS * 3), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillPaymentExpired))]
    #[case::acceptance_expired_only_recourse(BillValidateActionData { timestamp: Timestamp::now() + (ACCEPT_DEADLINE_SECONDS * 3), ..valid_bill_validate_action_data(add_req_to_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillAcceptanceExpired))]
    #[case::accept_already_accepted(BillValidateActionData { ..valid_bill_validate_action_data(add_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillAlreadyAccepted))]
    #[case::accept_not_drawee(BillValidateActionData { drawee_node_id: node_id_test_other(), ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Err(ProtocolValidationError::CallerIsNotDrawee))]
    fn test_validate_bill_accept_errors(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ProtocolValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::req_to_accept(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RequestAcceptance(safe_deadline_ts(ACCEPT_DEADLINE_SECONDS))), signer_node_id: node_id_test_other(), ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Ok(()))]
    fn test_validate_bill_req_to_accept_valid(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ProtocolValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::last_recourse_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RequestAcceptance(safe_deadline_ts(ACCEPT_DEADLINE_SECONDS))), ..valid_bill_validate_action_data(add_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillWasRecoursedToTheEnd))]
    #[case::active_req_to_pay_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RequestAcceptance(safe_deadline_ts(ACCEPT_DEADLINE_SECONDS))), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillIsRequestedToPayAndWaitingForPayment))]
    #[case::active_offer_to_sell_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RequestAcceptance(safe_deadline_ts(ACCEPT_DEADLINE_SECONDS))), ..valid_bill_validate_action_data(add_offer_to_sell_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillIsOfferedToSellAndWaitingForPayment))]
    #[case::active_recourse_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RequestAcceptance(safe_deadline_ts(ACCEPT_DEADLINE_SECONDS))), ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillIsInRecourseAndWaitingForPayment))]
    #[case::rejected_to_accept_only_recourse(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RequestAcceptance(safe_deadline_ts(ACCEPT_DEADLINE_SECONDS))), ..valid_bill_validate_action_data(add_reject_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillWasRejectedToAccept))]
    #[case::rejected_to_pay_only_recourse(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RequestAcceptance(safe_deadline_ts(ACCEPT_DEADLINE_SECONDS))), ..valid_bill_validate_action_data(add_reject_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillWasRejectedToPay))]
    #[case::payment_expired_only_recourse(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RequestAcceptance(safe_deadline_ts(ACCEPT_DEADLINE_SECONDS))), timestamp: Timestamp::now() + (PAYMENT_DEADLINE_SECONDS * 3), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillPaymentExpired))]
    #[case::acceptance_expired_only_recourse(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RequestAcceptance(safe_deadline_ts(ACCEPT_DEADLINE_SECONDS))), timestamp: Timestamp::now() + (ACCEPT_DEADLINE_SECONDS * 3), ..valid_bill_validate_action_data(add_req_to_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillAcceptanceExpired))]
    #[case::req_to_accept_not_holder(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RequestAcceptance(safe_deadline_ts(ACCEPT_DEADLINE_SECONDS))), signer_node_id: node_id_test(), ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Err(ProtocolValidationError::CallerIsNotHolder))]
    #[case::req_to_accept_already_accepted(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RequestAcceptance(safe_deadline_ts(ACCEPT_DEADLINE_SECONDS))), ..valid_bill_validate_action_data(add_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillAlreadyAccepted))]
    #[case::req_to_accept_already_req_to_accepted(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RequestAcceptance(safe_deadline_ts(ACCEPT_DEADLINE_SECONDS))), ..valid_bill_validate_action_data(add_req_to_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillAlreadyRequestedToAccept))]
    fn test_validate_bill_req_to_accept_errors(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ProtocolValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::req_to_pay(BillValidateActionData { signer_node_id: node_id_test_other(), mode: BillValidationActionMode::Deep(BillAction::RequestToPay(Currency::sat(), safe_deadline_ts(PAYMENT_DEADLINE_SECONDS))), ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Ok(()))]
    #[case::req_to_pay_after_maturity(BillValidateActionData { maturity_date: Date::new("2022-11-12").unwrap(), signer_node_id: node_id_test_other(), mode: BillValidationActionMode::Deep(BillAction::RequestToPay(Currency::sat(), safe_deadline_ts(PAYMENT_DEADLINE_SECONDS))), ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Ok(()))]
    #[case::req_to_pay_before_maturity(BillValidateActionData { maturity_date: Date::new("2099-11-12").unwrap(), signer_node_id: node_id_test_other(), mode: BillValidationActionMode::Deep(BillAction::RequestToPay(Currency::sat(), safe_deadline_ts(PAYMENT_DEADLINE_SECONDS))), ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data() ,)) }, Ok(()))]
    fn test_validate_bill_req_to_pay_valid(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ProtocolValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::last_recourse_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RequestToPay(Currency::sat(), safe_deadline_ts(PAYMENT_DEADLINE_SECONDS))), ..valid_bill_validate_action_data(add_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillWasRecoursedToTheEnd))]
    #[case::active_req_to_pay_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RequestToPay(Currency::sat(), safe_deadline_ts(PAYMENT_DEADLINE_SECONDS))), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillIsRequestedToPayAndWaitingForPayment))]
    #[case::active_offer_to_sell_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RequestToPay(Currency::sat(), safe_deadline_ts(PAYMENT_DEADLINE_SECONDS))), ..valid_bill_validate_action_data(add_offer_to_sell_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillIsOfferedToSellAndWaitingForPayment))]
    #[case::active_recourse_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RequestToPay(Currency::sat(), safe_deadline_ts(PAYMENT_DEADLINE_SECONDS))), ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillIsInRecourseAndWaitingForPayment))]
    #[case::rejected_to_accept_only_recourse(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RequestToPay(Currency::sat(), safe_deadline_ts(PAYMENT_DEADLINE_SECONDS))), ..valid_bill_validate_action_data(add_reject_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillWasRejectedToAccept))]
    #[case::rejected_to_pay_only_recourse(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RequestToPay(Currency::sat(), safe_deadline_ts(PAYMENT_DEADLINE_SECONDS))), ..valid_bill_validate_action_data(add_reject_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillWasRejectedToPay))]
    #[case::payment_expired_only_recourse(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RequestToPay(Currency::sat(), safe_deadline_ts(PAYMENT_DEADLINE_SECONDS))), timestamp: Timestamp::now() + (PAYMENT_DEADLINE_SECONDS * 3), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillPaymentExpired))]
    #[case::acceptance_expired_only_recourse(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RequestToPay(Currency::sat(), safe_deadline_ts(PAYMENT_DEADLINE_SECONDS))), timestamp: Timestamp::now() + (ACCEPT_DEADLINE_SECONDS * 2), ..valid_bill_validate_action_data(add_req_to_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillAcceptanceExpired))]
    #[case::req_to_pay_not_holder(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RequestToPay(Currency::sat(), safe_deadline_ts(PAYMENT_DEADLINE_SECONDS))), signer_node_id: node_id_test(), ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Err(ProtocolValidationError::CallerIsNotHolder))]
    #[case::req_to_pay_already_req_to_payed(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RequestToPay(Currency::sat(), safe_deadline_ts(PAYMENT_DEADLINE_SECONDS))), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillIsRequestedToPayAndWaitingForPayment))]
    fn test_validate_bill_req_to_pay_errors(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ProtocolValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::req_to_recourse_not_rejected_but_expired(BillValidateActionData { signer_node_id: node_id_test_and_another(), timestamp: Timestamp::now() + (RECOURSE_DEADLINE_SECONDS * 2), endorsee_node_id: Some(node_id_test_and_another()), mode: BillValidationActionMode::Deep(BillAction::RequestRecourse(valid_bill_identified_participant(), RecourseReason::Accept, safe_deadline_ts(RECOURSE_DEADLINE_SECONDS))), ..valid_bill_validate_action_data(add_req_to_accept_block(add_endorse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),), valid_and_another_bill_identified_participant(), valid_bill_identified_participant()))) }, Ok(()))]
    #[case::req_to_recourse_not_expired_but_rejected(BillValidateActionData { signer_node_id: node_id_test_and_another(), endorsee_node_id: Some(node_id_test_and_another()), mode: BillValidationActionMode::Deep(BillAction::RequestRecourse(valid_bill_identified_participant(), RecourseReason::Accept, safe_deadline_ts(RECOURSE_DEADLINE_SECONDS))), ..valid_bill_validate_action_data(add_reject_accept_block(add_req_to_accept_block(add_endorse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),), valid_and_another_bill_identified_participant(), valid_bill_identified_participant())))) }, Ok(()))]
    #[case::req_to_recourse_not_req_to_accept_but_rejected(BillValidateActionData { signer_node_id: node_id_test_and_another(), endorsee_node_id: Some(node_id_test_and_another()), mode: BillValidationActionMode::Deep(BillAction::RequestRecourse(valid_bill_identified_participant(), RecourseReason::Accept, safe_deadline_ts(RECOURSE_DEADLINE_SECONDS))), ..valid_bill_validate_action_data(add_reject_accept_block(add_endorse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),), valid_and_another_bill_identified_participant(), valid_bill_identified_participant()))) }, Ok(()))]
    fn test_validate_bill_req_to_recourse_accept_valid(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ProtocolValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::last_recourse_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RequestRecourse(valid_bill_identified_participant(), RecourseReason::Accept, safe_deadline_ts(RECOURSE_DEADLINE_SECONDS))), ..valid_bill_validate_action_data(add_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillWasRecoursedToTheEnd))]
    #[case::active_req_to_pay_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RequestRecourse(valid_bill_identified_participant(), RecourseReason::Accept, safe_deadline_ts(RECOURSE_DEADLINE_SECONDS))), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillIsRequestedToPayAndWaitingForPayment))]
    #[case::active_offer_to_sell_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RequestRecourse(valid_bill_identified_participant(), RecourseReason::Accept, safe_deadline_ts(RECOURSE_DEADLINE_SECONDS))), ..valid_bill_validate_action_data(add_offer_to_sell_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillIsOfferedToSellAndWaitingForPayment))]
    #[case::active_recourse_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RequestRecourse(valid_bill_identified_participant(), RecourseReason::Accept, safe_deadline_ts(RECOURSE_DEADLINE_SECONDS))), ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillIsInRecourseAndWaitingForPayment))]
    #[case::req_to_recourse_not_holder(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RequestRecourse(valid_bill_identified_participant(), RecourseReason::Accept, safe_deadline_ts(RECOURSE_DEADLINE_SECONDS))), signer_node_id: node_id_test(), ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Err(ProtocolValidationError::CallerIsNotHolder))]
    #[case::req_to_recourse_not_past_endorsee(BillValidateActionData { endorsee_node_id: Some(node_id_test()), mode: BillValidationActionMode::Deep(BillAction::RequestRecourse(valid_other_bill_identified_participant(), RecourseReason::Accept, safe_deadline_ts(RECOURSE_DEADLINE_SECONDS))), ..valid_bill_validate_action_data(add_endorse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),), valid_other_bill_identified_participant(), valid_bill_identified_participant())) }, Err(ProtocolValidationError::RecourseeNotPastHolder))]
    #[case::req_to_recourse_not_req_to_accept_or_rejected(BillValidateActionData { signer_node_id: node_id_test_and_another(), endorsee_node_id: Some(node_id_test_and_another()), mode: BillValidationActionMode::Deep(BillAction::RequestRecourse(valid_bill_identified_participant(), RecourseReason::Accept, safe_deadline_ts(RECOURSE_DEADLINE_SECONDS))), ..valid_bill_validate_action_data(add_endorse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),), valid_and_another_bill_identified_participant(), valid_bill_identified_participant())) }, Err(ProtocolValidationError::BillRequestToAcceptDidNotExpireAndWasNotRejected))]
    #[case::req_to_recourse_not_expired_or_rejected(BillValidateActionData { signer_node_id: node_id_test_and_another(), endorsee_node_id: Some(node_id_test_and_another()), mode: BillValidationActionMode::Deep(BillAction::RequestRecourse(valid_bill_identified_participant(), RecourseReason::Accept, safe_deadline_ts(RECOURSE_DEADLINE_SECONDS))), ..valid_bill_validate_action_data(add_req_to_accept_block(add_endorse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),), valid_and_another_bill_identified_participant(), valid_bill_identified_participant()))) }, Err(ProtocolValidationError::BillRequestToAcceptDidNotExpireAndWasNotRejected))]
    fn test_validate_bill_req_to_recourse_accept_errors(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ProtocolValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::req_to_recourse_rejected(BillValidateActionData { signer_node_id: node_id_test_and_another(), endorsee_node_id: Some(node_id_test_and_another()), mode: BillValidationActionMode::Deep(BillAction::RequestRecourse(valid_bill_identified_participant(), RecourseReason::Pay(Sum::new_sat(500).expect("sat works")), safe_deadline_ts(RECOURSE_DEADLINE_SECONDS))), ..valid_bill_validate_action_data(add_reject_pay_block(add_req_to_pay_block(add_endorse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),), valid_and_another_bill_identified_participant(), valid_bill_identified_participant())))) }, Ok(()))]
    #[case::req_to_recourse_expired(BillValidateActionData { signer_node_id: node_id_test_and_another(), timestamp: Timestamp::now() + (RECOURSE_DEADLINE_SECONDS * 3), endorsee_node_id: Some(node_id_test_and_another()), mode: BillValidationActionMode::Deep(BillAction::RequestRecourse(valid_bill_identified_participant(), RecourseReason::Pay(Sum::new_sat(500).expect("sat works")), safe_deadline_ts(RECOURSE_DEADLINE_SECONDS))), ..valid_bill_validate_action_data(add_req_to_pay_block(add_endorse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),), valid_and_another_bill_identified_participant(), valid_bill_identified_participant()))) }, Ok(()))]
    fn test_validate_bill_req_to_recourse_payment_valid(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ProtocolValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::last_recourse_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RequestRecourse(valid_bill_identified_participant(), RecourseReason::Pay(Sum::new_sat(5000).expect("sat works")), safe_deadline_ts(RECOURSE_DEADLINE_SECONDS))), ..valid_bill_validate_action_data(add_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillWasRecoursedToTheEnd))]
    #[case::active_req_to_pay_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RequestRecourse(valid_bill_identified_participant(), RecourseReason::Pay(Sum::new_sat(5000).expect("sat works")), safe_deadline_ts(RECOURSE_DEADLINE_SECONDS))), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillIsRequestedToPayAndWaitingForPayment))]
    #[case::active_offer_to_sell_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RequestRecourse(valid_bill_identified_participant(), RecourseReason::Pay(Sum::new_sat(5000).expect("sat works")), safe_deadline_ts(RECOURSE_DEADLINE_SECONDS))), ..valid_bill_validate_action_data(add_offer_to_sell_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillIsOfferedToSellAndWaitingForPayment))]
    #[case::active_recourse_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RequestRecourse(valid_bill_identified_participant(), RecourseReason::Pay(Sum::new_sat(5000).expect("sat works")), safe_deadline_ts(RECOURSE_DEADLINE_SECONDS))), ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillIsInRecourseAndWaitingForPayment))]
    #[case::req_to_recourse_not_holder(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RequestRecourse(valid_bill_identified_participant(), RecourseReason::Pay(Sum::new_sat(5000).expect("sat works")), safe_deadline_ts(RECOURSE_DEADLINE_SECONDS))), signer_node_id: node_id_test(), ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Err(ProtocolValidationError::CallerIsNotHolder))]
    #[case::req_to_recourse_not_past_endorsee(BillValidateActionData { endorsee_node_id: Some(node_id_test()), mode: BillValidationActionMode::Deep(BillAction::RequestRecourse(valid_other_bill_identified_participant(), RecourseReason::Pay(Sum::new_sat(5000).expect("sat works")), safe_deadline_ts(RECOURSE_DEADLINE_SECONDS))), ..valid_bill_validate_action_data(add_endorse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),), valid_other_bill_identified_participant(), valid_bill_identified_participant())) }, Err(ProtocolValidationError::RecourseeNotPastHolder))]
    #[case::req_to_recourse_paid(BillValidateActionData { is_paid: true, endorsee_node_id: Some(node_id_test()), mode: BillValidationActionMode::Deep(BillAction::RequestRecourse(valid_other_bill_identified_participant(), RecourseReason::Pay(Sum::new_sat(5000).expect("sat works")), safe_deadline_ts(RECOURSE_DEADLINE_SECONDS))), ..valid_bill_validate_action_data(add_endorse_block(add_endorse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),), valid_other_bill_identified_participant(), valid_bill_identified_participant()), valid_bill_identified_participant(), valid_other_bill_identified_participant())) }, Err(ProtocolValidationError::BillAlreadyPaid))]
    #[case::req_to_recourse_not_req_to_pay(BillValidateActionData { signer_node_id: node_id_test_and_another(), endorsee_node_id: Some(node_id_test_and_another()), mode: BillValidationActionMode::Deep(BillAction::RequestRecourse(valid_bill_identified_participant(), RecourseReason::Pay(Sum::new_sat(5000).expect("sat works")), safe_deadline_ts(RECOURSE_DEADLINE_SECONDS))), ..valid_bill_validate_action_data(add_endorse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),), valid_and_another_bill_identified_participant(), valid_bill_identified_participant())) }, Err(ProtocolValidationError::BillWasNotRequestedToPay))]
    #[case::req_to_recourse_not_expired_or_rejected(BillValidateActionData { signer_node_id: node_id_test_and_another(), endorsee_node_id: Some(node_id_test_and_another()), mode: BillValidationActionMode::Deep(BillAction::RequestRecourse(valid_bill_identified_participant(), RecourseReason::Pay(Sum::new_sat(5000).expect("sat works")), safe_deadline_ts(RECOURSE_DEADLINE_SECONDS))), ..valid_bill_validate_action_data(add_req_to_pay_block(add_endorse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),), valid_and_another_bill_identified_participant(), valid_bill_identified_participant()))) }, Err(ProtocolValidationError::BillIsRequestedToPayAndWaitingForPayment))]
    fn test_validate_bill_req_to_recourse_payment_errors(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ProtocolValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::recourse(BillValidateActionData { endorsee_node_id: Some(node_id_test()), mode: BillValidationActionMode::Deep(BillAction::Recourse(valid_other_bill_identified_participant(), Sum::new_sat(500).expect("sat works"), RecourseReason::Accept)), ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(add_endorse_block(add_endorse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),), valid_other_bill_identified_participant(), valid_bill_identified_participant()), valid_bill_identified_participant(), valid_other_bill_identified_participant()))) }, Ok(()))]
    fn test_validate_bill_recourse_payment_valid(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ProtocolValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::last_recourse_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::Recourse(valid_bill_identified_participant(), Sum::new_sat(500).expect("sat works"), RecourseReason::Accept)), ..valid_bill_validate_action_data(add_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillWasRecoursedToTheEnd))]
    #[case::active_req_to_pay_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::Recourse(valid_bill_identified_participant(), Sum::new_sat(500).expect("sat works"), RecourseReason::Accept)), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillIsRequestedToPayAndWaitingForPayment))]
    #[case::active_offer_to_sell_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::Recourse(valid_bill_identified_participant(),  Sum::new_sat(500).expect("sat works"),RecourseReason::Accept)), ..valid_bill_validate_action_data(add_offer_to_sell_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillIsOfferedToSellAndWaitingForPayment))]
    #[case::recourse_not_holder(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::Recourse(valid_bill_identified_participant(),  Sum::new_sat(500).expect("sat works"),RecourseReason::Accept)), signer_node_id: node_id_test(), ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Err(ProtocolValidationError::CallerIsNotHolder))]
    #[case::recourse_not_in_recourse(BillValidateActionData { endorsee_node_id: Some(node_id_test()), mode: BillValidationActionMode::Deep(BillAction::Recourse(valid_other_bill_identified_participant(),  Sum::new_sat(500).expect("sat works"),RecourseReason::Accept)), ..valid_bill_validate_action_data(add_endorse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),), valid_other_bill_identified_participant(), valid_bill_identified_participant())) }, Err(ProtocolValidationError::BillIsNotRequestedToRecourseAndWaitingForPayment))]
    #[case::recourse_invalid_data_reason(BillValidateActionData { endorsee_node_id: Some(node_id_test()), mode: BillValidationActionMode::Deep(BillAction::Recourse(valid_other_bill_identified_participant(), Sum::new_sat(500).expect("sat works"), RecourseReason::Pay(Sum::new_sat(100).expect("sat works"),))), ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(add_endorse_block(add_endorse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),), valid_other_bill_identified_participant(), valid_bill_identified_participant()), valid_bill_identified_participant(), valid_other_bill_identified_participant()))) }, Err(ProtocolValidationError::BillRecourseDataInvalid))]
    #[case::recourse_invalid_data_recoursee(BillValidateActionData { endorsee_node_id: Some(node_id_test()), mode: BillValidationActionMode::Deep(BillAction::Recourse(valid_bill_identified_participant(), Sum::new_sat(500).expect("sat works"), RecourseReason::Accept)), ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(add_endorse_block(add_endorse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),), valid_other_bill_identified_participant(), valid_bill_identified_participant()), valid_bill_identified_participant(), valid_other_bill_identified_participant()))) }, Err(ProtocolValidationError::BillRecourseDataInvalid))]
    fn test_validate_bill_recourse_payment_errors(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ProtocolValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::mint(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::Mint(valid_other_bill_participant(), Sum::new_sat(500).expect("sat works"))), signer_node_id: node_id_test_other(), ..valid_bill_validate_action_data(add_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Ok(()))]
    fn test_validate_bill_mint_valid(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ProtocolValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::last_recourse_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::Mint(valid_other_bill_participant(), Sum::new_sat(500).expect("sat works"))), ..valid_bill_validate_action_data(add_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillWasRecoursedToTheEnd))]
    #[case::active_req_to_pay_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::Mint(valid_other_bill_participant(), Sum::new_sat(500).expect("sat works"))), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillIsRequestedToPayAndWaitingForPayment))]
    #[case::active_offer_to_sell_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::Mint(valid_other_bill_participant(), Sum::new_sat(500).expect("sat works"))), ..valid_bill_validate_action_data(add_offer_to_sell_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillIsOfferedToSellAndWaitingForPayment))]
    #[case::active_recourse_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::Mint(valid_other_bill_participant(), Sum::new_sat(500).expect("sat works"))), ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillIsInRecourseAndWaitingForPayment))]
    #[case::rejected_to_accept_only_recourse(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::Mint(valid_other_bill_participant(), Sum::new_sat(500).expect("sat works"))), ..valid_bill_validate_action_data(add_reject_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillWasRejectedToAccept))]
    #[case::rejected_to_pay_only_recourse(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::Mint(valid_other_bill_participant(), Sum::new_sat(500).expect("sat works"))), ..valid_bill_validate_action_data(add_reject_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillWasRejectedToPay))]
    #[case::payment_expired_only_recourse(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::Mint(valid_other_bill_participant(), Sum::new_sat(500).expect("sat works"))), timestamp: Timestamp::now() + (PAYMENT_DEADLINE_SECONDS * 3), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillPaymentExpired))]
    #[case::acceptance_expired_only_recourse(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::Mint(valid_other_bill_participant(), Sum::new_sat(500).expect("sat works"))), timestamp: Timestamp::now() + (ACCEPT_DEADLINE_SECONDS * 2), ..valid_bill_validate_action_data(add_req_to_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillAcceptanceExpired))]
    #[case::mint_not_accepted(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::Mint(valid_other_bill_participant(), Sum::new_sat(500).expect("sat works"))), ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Err(ProtocolValidationError::BillNotAccepted))]
    #[case::mint_not_holder(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::Mint(valid_other_bill_participant(), Sum::new_sat(500).expect("sat works"))), signer_node_id: node_id_test(), ..valid_bill_validate_action_data(add_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::CallerIsNotHolder))]
    fn test_validate_bill_mint_errors(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ProtocolValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::endorse(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::Endorse(valid_other_bill_participant())), signer_node_id: node_id_test_other(), ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Ok(()))]
    fn test_validate_bill_endorse_valid(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ProtocolValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::last_recourse_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::Endorse(valid_other_bill_participant())), ..valid_bill_validate_action_data(add_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillWasRecoursedToTheEnd))]
    #[case::active_req_to_pay_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::Endorse(valid_other_bill_participant())), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillIsRequestedToPayAndWaitingForPayment))]
    #[case::active_offer_to_sell_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::Endorse(valid_other_bill_participant())), ..valid_bill_validate_action_data(add_offer_to_sell_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillIsOfferedToSellAndWaitingForPayment))]
    #[case::active_recourse_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::Endorse(valid_other_bill_participant())), ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillIsInRecourseAndWaitingForPayment))]
    #[case::rejected_to_accept_only_recourse(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::Endorse(valid_other_bill_participant())), ..valid_bill_validate_action_data(add_reject_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillWasRejectedToAccept))]
    #[case::rejected_to_pay_only_recourse(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::Endorse(valid_other_bill_participant())), ..valid_bill_validate_action_data(add_reject_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillWasRejectedToPay))]
    #[case::payment_expired_only_recourse(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::Endorse(valid_other_bill_participant())), timestamp: Timestamp::now() + (PAYMENT_DEADLINE_SECONDS * 3), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillPaymentExpired))]
    #[case::acceptance_expired_only_recourse(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::Endorse(valid_other_bill_participant())), timestamp: Timestamp::now() + (ACCEPT_DEADLINE_SECONDS * 2), ..valid_bill_validate_action_data(add_req_to_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillAcceptanceExpired))]
    #[case::endorse_not_holder(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::Endorse(valid_other_bill_participant())), signer_node_id: node_id_test(), ..valid_bill_validate_action_data(add_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::CallerIsNotHolder))]
    fn test_validate_bill_endorse_errors(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ProtocolValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::offer_to_sell(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::OfferToSell(valid_other_bill_participant(), Sum::new_sat(500).expect("sat works"), safe_deadline_ts(DAY_IN_SECS))), signer_node_id: node_id_test_other(), ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Ok(()))]
    #[case::offer_to_sell_req_to_pay_expired_before_maturity(BillValidateActionData { maturity_date: Date::new("2099-11-12").unwrap(), timestamp: Timestamp::now() + (PAYMENT_DEADLINE_SECONDS * 2) , mode: BillValidationActionMode::Deep(BillAction::OfferToSell(valid_other_bill_participant(), Sum::new_sat(500).expect("sat works"), safe_deadline_ts(DAY_IN_SECS))), signer_node_id: node_id_test_other(), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Ok(()))]
    fn test_validate_bill_offer_to_sell_valid(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ProtocolValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::last_recourse_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::OfferToSell(valid_other_bill_participant(), Sum::new_sat(500).expect("sat works"), safe_deadline_ts(DAY_IN_SECS))), ..valid_bill_validate_action_data(add_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillWasRecoursedToTheEnd))]
    #[case::active_req_to_pay_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::OfferToSell(valid_other_bill_participant(), Sum::new_sat(500).expect("sat works"), safe_deadline_ts(DAY_IN_SECS))), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillIsRequestedToPayAndWaitingForPayment))]
    #[case::active_offer_to_sell_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::OfferToSell(valid_other_bill_participant(), Sum::new_sat(500).expect("sat works"), safe_deadline_ts(DAY_IN_SECS))), ..valid_bill_validate_action_data(add_offer_to_sell_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillIsOfferedToSellAndWaitingForPayment))]
    #[case::active_recourse_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::OfferToSell(valid_other_bill_participant(), Sum::new_sat(500).expect("sat works"), safe_deadline_ts(DAY_IN_SECS))), ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillIsInRecourseAndWaitingForPayment))]
    #[case::rejected_to_accept_only_recourse(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::OfferToSell(valid_other_bill_participant(), Sum::new_sat(500).expect("sat works"), safe_deadline_ts(DAY_IN_SECS))), ..valid_bill_validate_action_data(add_reject_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillWasRejectedToAccept))]
    #[case::rejected_to_pay_only_recourse(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::OfferToSell(valid_other_bill_participant(), Sum::new_sat(500).expect("sat works"), safe_deadline_ts(DAY_IN_SECS))), ..valid_bill_validate_action_data(add_reject_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillWasRejectedToPay))]
    #[case::payment_expired_only_recourse(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::OfferToSell(valid_other_bill_participant(), Sum::new_sat(500).expect("sat works"), safe_deadline_ts(DAY_IN_SECS))), timestamp: Timestamp::now() + (PAYMENT_DEADLINE_SECONDS * 3), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillPaymentExpired))]
    #[case::acceptance_expired_only_recourse(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::OfferToSell(valid_other_bill_participant(), Sum::new_sat(500).expect("sat works"), safe_deadline_ts(DAY_IN_SECS))), timestamp: Timestamp::now() + (ACCEPT_DEADLINE_SECONDS * 2), ..valid_bill_validate_action_data(add_req_to_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillAcceptanceExpired))]
    #[case::offer_to_sell_not_holder(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::OfferToSell(valid_other_bill_participant(), Sum::new_sat(500).expect("sat works"), safe_deadline_ts(DAY_IN_SECS))), signer_node_id: node_id_test(), ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Err(ProtocolValidationError::CallerIsNotHolder))]
    fn test_validate_bill_offer_to_sell_errors(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ProtocolValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::sell(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::Sell(valid_bill_participant(), Sum::new_sat(500).expect("sat works"), valid_payment_address_testnet())), signer_node_id: node_id_test_other(), ..valid_bill_validate_action_data(add_offer_to_sell_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Ok(()))]
    // minus 8 seconds so timestamp is before offer to sell expiry and after req to pay expiry
    // as every block adds 1 sec to issue block, which is now() - 10
    #[case::sell_req_to_pay_expired_before_maturity(BillValidateActionData { maturity_date: Date::new("2099-11-12").unwrap(), timestamp: Timestamp::now() + (PAYMENT_DEADLINE_SECONDS - 8), mode: BillValidationActionMode::Deep(BillAction::Sell(valid_bill_participant(), Sum::new_sat(500).expect("sat works"), valid_payment_address_testnet())), signer_node_id: node_id_test_other(), ..valid_bill_validate_action_data(add_offer_to_sell_block(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)))) }, Ok(()))]
    fn test_validate_bill_sell_valid(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ProtocolValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::last_recourse_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::Sell(valid_other_bill_participant(), Sum::new_sat(500).expect("sat works"), valid_payment_address_testnet())), ..valid_bill_validate_action_data(add_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillWasRecoursedToTheEnd))]
    #[case::active_req_to_pay_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::Sell(valid_other_bill_participant(), Sum::new_sat(500).expect("sat works"), valid_payment_address_testnet())), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillIsRequestedToPayAndWaitingForPayment))]
    #[case::active_recourse_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::Sell(valid_other_bill_participant(), Sum::new_sat(500).expect("sat works"), valid_payment_address_testnet())), ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillIsInRecourseAndWaitingForPayment))]
    #[case::rejected_to_accept_only_recourse(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::Sell(valid_other_bill_participant(), Sum::new_sat(500).expect("sat works"), valid_payment_address_testnet())), ..valid_bill_validate_action_data(add_reject_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillWasRejectedToAccept))]
    #[case::rejected_to_pay_only_recourse(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::Sell(valid_other_bill_participant(), Sum::new_sat(500).expect("sat works"), valid_payment_address_testnet())), ..valid_bill_validate_action_data(add_reject_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillWasRejectedToPay))]
    #[case::payment_expired_only_recourse(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::Sell(valid_other_bill_participant(), Sum::new_sat(500).expect("sat works"), valid_payment_address_testnet())), timestamp: Timestamp::now() + (PAYMENT_DEADLINE_SECONDS * 3), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillPaymentExpired))]
    #[case::acceptance_expired_only_recourse(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::Sell(valid_other_bill_participant(), Sum::new_sat(500).expect("sat works"), valid_payment_address_testnet())), timestamp: Timestamp::now() + (ACCEPT_DEADLINE_SECONDS * 2), ..valid_bill_validate_action_data(add_req_to_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillAcceptanceExpired))]
    #[case::sell_not_holder(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::Sell(valid_other_bill_participant(), Sum::new_sat(500).expect("sat works"), valid_payment_address_testnet())), signer_node_id: node_id_test(), ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Err(ProtocolValidationError::CallerIsNotHolder))]
    #[case::sell_not_offered_to_sell(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::Sell(valid_other_bill_participant(), Sum::new_sat(500).expect("sat works"), valid_payment_address_testnet())), signer_node_id: node_id_test_other(), ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Err(ProtocolValidationError::BillIsNotOfferToSellWaitingForPayment))]
    #[case::sell_invalid_data_buyer(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::Sell(valid_other_bill_participant(), Sum::new_sat(500).expect("sat works"), valid_payment_address_testnet())), signer_node_id: node_id_test_other(), ..valid_bill_validate_action_data(add_offer_to_sell_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillSellDataInvalid))]
    #[case::sell_invalid_data_payment_address(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::Sell(valid_other_bill_participant(), Sum::new_sat(500).expect("sat works"), other_valid_payment_address_testnet())), signer_node_id: node_id_test_other(), ..valid_bill_validate_action_data(add_offer_to_sell_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillSellDataInvalid))]
    fn test_validate_bill_sell_errors(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ProtocolValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::reject_to_accept(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RejectAcceptance), ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Ok(()))]
    fn test_validate_bill_reject_accept_valid(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ProtocolValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::last_recourse_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RejectAcceptance), ..valid_bill_validate_action_data(add_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillWasRecoursedToTheEnd))]
    #[case::active_req_to_pay_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RejectAcceptance), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillIsRequestedToPayAndWaitingForPayment))]
    #[case::active_offer_to_sell_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RejectAcceptance), ..valid_bill_validate_action_data(add_offer_to_sell_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillIsOfferedToSellAndWaitingForPayment))]
    #[case::active_recourse_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RejectAcceptance), ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillIsInRecourseAndWaitingForPayment))]
    #[case::rejected_to_accept_only_recourse(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RejectAcceptance), ..valid_bill_validate_action_data(add_reject_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillWasRejectedToAccept))]
    #[case::rejected_to_pay_only_recourse(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RejectAcceptance), ..valid_bill_validate_action_data(add_reject_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillWasRejectedToPay))]
    #[case::payment_expired_only_recourse(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RejectAcceptance), timestamp: Timestamp::now() + (PAYMENT_DEADLINE_SECONDS * 3), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillPaymentExpired))]
    #[case::acceptance_expired_only_recourse(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RejectAcceptance), timestamp: Timestamp::now() + (ACCEPT_DEADLINE_SECONDS * 2), ..valid_bill_validate_action_data(add_req_to_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillAcceptanceExpired))]
    #[case::reject_to_accept_already_rejected(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RejectAcceptance), ..valid_bill_validate_action_data(add_reject_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillWasRejectedToAccept))]
    #[case::reject_to_accept_not_drawee(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RejectAcceptance), signer_node_id: node_id_test_other(), ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Err(ProtocolValidationError::CallerIsNotDrawee))]
    #[case::reject_to_accept_accepted(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RejectAcceptance), ..valid_bill_validate_action_data(add_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillAlreadyAccepted))]
    fn test_validate_bill_reject_accept_errors(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ProtocolValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::reject_to_buy_not_buyer(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RejectBuying), signer_node_id: node_id_test(), ..valid_bill_validate_action_data(add_offer_to_sell_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Ok(()))]
    fn test_validate_bill_reject_buying_valid(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ProtocolValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::last_recourse_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RejectBuying), ..valid_bill_validate_action_data(add_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillWasRecoursedToTheEnd))]
    #[case::active_req_to_pay_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RejectBuying), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillIsRequestedToPayAndWaitingForPayment))]
    #[case::active_recourse_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RejectBuying), ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillIsInRecourseAndWaitingForPayment))]
    #[case::rejected_to_accept_only_recourse(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RejectBuying), ..valid_bill_validate_action_data(add_reject_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillWasRejectedToAccept))]
    #[case::rejected_to_pay_only_recourse(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RejectBuying), ..valid_bill_validate_action_data(add_reject_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillWasRejectedToPay))]
    #[case::payment_expired_only_recourse(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RejectBuying), timestamp: Timestamp::now() + (PAYMENT_DEADLINE_SECONDS * 3), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillPaymentExpired))]
    #[case::acceptance_expired_only_recourse(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RejectBuying), timestamp: Timestamp::now() + (ACCEPT_DEADLINE_SECONDS * 2), ..valid_bill_validate_action_data(add_req_to_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillAcceptanceExpired))]
    #[case::reject_to_buy_already_rejected(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RejectBuying), ..valid_bill_validate_action_data(add_reject_buy_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::RequestAlreadyRejected))]
    #[case::reject_to_buy_not_offered_to_sell(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RejectBuying), ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Err(ProtocolValidationError::BillWasNotOfferedToSell))]
    #[case::reject_to_buy_not_buyer(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RejectBuying), signer_node_id: node_id_test_other(), ..valid_bill_validate_action_data(add_offer_to_sell_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::CallerIsNotBuyer))]
    fn test_validate_bill_reject_buying_errors(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ProtocolValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::reject_to_pay(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RejectPayment), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Ok(()))]
    #[case::reject_to_pay_maturity_not_expired(BillValidateActionData { maturity_date: Date::from(Timestamp::now()), mode: BillValidationActionMode::Deep(BillAction::RejectPayment), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Ok(()))]
    fn test_validate_bill_reject_payment_valid(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ProtocolValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::last_recourse_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RejectPayment), ..valid_bill_validate_action_data(add_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillWasRecoursedToTheEnd))]
    #[case::active_offer_to_sell_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RejectAcceptance), ..valid_bill_validate_action_data(add_offer_to_sell_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillIsOfferedToSellAndWaitingForPayment))]
    #[case::active_recourse_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RejectPayment), ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillIsInRecourseAndWaitingForPayment))]
    #[case::rejected_to_accept_only_recourse(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RejectPayment), ..valid_bill_validate_action_data(add_reject_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillWasRejectedToAccept))]
    #[case::rejected_to_pay_only_recourse(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RejectPayment), ..valid_bill_validate_action_data(add_reject_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillWasRejectedToPay))]
    #[case::payment_expired_only_recourse(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RejectPayment), timestamp: Timestamp::now() + (PAYMENT_DEADLINE_SECONDS * 3), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillPaymentExpired))]
    #[case::acceptance_expired_only_recourse(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RejectPayment), timestamp: Timestamp::now() + (ACCEPT_DEADLINE_SECONDS * 2), ..valid_bill_validate_action_data(add_req_to_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillAcceptanceExpired))]
    #[case::reject_to_pay_already_rejected(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RejectPayment), ..valid_bill_validate_action_data(add_reject_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillWasRejectedToPay))]
    #[case::reject_to_pay_not_drawee(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RejectPayment), signer_node_id: node_id_test_other(), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::CallerIsNotDrawee))]
    #[case::reject_to_pay_paid(BillValidateActionData { is_paid: true, mode: BillValidationActionMode::Deep(BillAction::RejectPayment), ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Err(ProtocolValidationError::BillAlreadyPaid))]
    #[case::reject_to_pay_not_req_to_pay(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RejectPayment), ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Err(ProtocolValidationError::BillWasNotRequestedToPay))]
    #[case::reject_to_pay_expired(BillValidateActionData { timestamp: Timestamp::now() + (PAYMENT_DEADLINE_SECONDS * 3), mode: BillValidationActionMode::Deep(BillAction::RejectPayment), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillPaymentExpired))]
    fn test_validate_bill_reject_payment_errors(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ProtocolValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::reject_to_recourse(BillValidateActionData { signer_node_id: node_id_test_other(), mode: BillValidationActionMode::Deep(BillAction::RejectPaymentForRecourse), ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Ok(()))]
    #[case::reject_to_recourse_last_endorsee(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RejectPaymentForRecourse), ..valid_bill_validate_action_data(add_req_to_recourse_payment_block(add_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)))) }, Ok(()))]
    fn test_validate_bill_reject_recourse_valid(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ProtocolValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::active_offer_to_sell_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RejectAcceptance), ..valid_bill_validate_action_data(add_offer_to_sell_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillIsOfferedToSellAndWaitingForPayment))]
    #[case::active_req_to_pay_blocked(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RejectBuying), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::BillIsRequestedToPayAndWaitingForPayment))]
    #[case::reject_to_recourse_not_req_to_recourse(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RejectPaymentForRecourse), ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Err(ProtocolValidationError::BillWasNotRequestedToRecourse))]
    #[case::reject_to_recourse_not_recoursee(BillValidateActionData { mode: BillValidationActionMode::Deep(BillAction::RejectPaymentForRecourse), signer_node_id: node_id_test(), ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ProtocolValidationError::CallerIsNotRecoursee))]
    fn test_validate_bill_reject_recourse_errors(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ProtocolValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }
}
