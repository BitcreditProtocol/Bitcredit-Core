use crate::{
    Validate, ValidationError,
    blockchain::{
        Block, Blockchain,
        bill::{
            BillOpCode, OfferToSellWaitingForPayment, RecourseWaitingForPayment,
            block::BillRecourseReasonBlockData,
        },
    },
    constants::{ACCEPT_DEADLINE_SECONDS, PAYMENT_DEADLINE_SECONDS, RECOURSE_DEADLINE_SECONDS},
    contact::BillParticipant,
    util::{self, date::start_of_day_as_timestamp},
};

use super::{BillAction, BillIssueData, BillType, BillValidateActionData, RecourseReason};

pub fn validate_bill_issue(data: &BillIssueData) -> Result<(u64, BillType), ValidationError> {
    let sum = util::currency::parse_sum(&data.sum).map_err(|_| ValidationError::InvalidSum)?;

    for file_upload_id in &data.file_upload_ids {
        util::validate_file_upload_id(Some(file_upload_id))?;
    }

    // anon users can't issue bill
    if let BillParticipant::Anon(_) = data.drawer_public_data {
        return Err(ValidationError::DrawerIsNotBillIssuer);
    }

    let issue_date_ts = util::date::date_string_to_timestamp(&data.issue_date, None)?;
    let maturity_date_ts = util::date::date_string_to_timestamp(&data.maturity_date, None)?;
    let start_of_day = start_of_day_as_timestamp(data.timestamp);

    if maturity_date_ts < start_of_day {
        return Err(ValidationError::MaturityDateInThePast);
    }

    if issue_date_ts > maturity_date_ts {
        return Err(ValidationError::IssueDateAfterMaturityDate);
    }

    let bill_type = match data.t {
        0 => BillType::PromissoryNote,
        1 => BillType::SelfDrafted,
        2 => BillType::ThreeParties,
        _ => return Err(ValidationError::InvalidBillType),
    };

    if data.drawee == data.payee {
        return Err(ValidationError::DraweeCantBePayee);
    }
    Ok((sum, bill_type))
}

impl Validate for BillValidateActionData {
    fn validate(&self) -> Result<(), ValidationError> {
        let holder_node_id = match self.endorsee_node_id {
            None => self.payee_node_id.clone(),
            Some(ref endorsee) => endorsee.clone(),
        };

        // if the bill was rejected to recourse, no further actions are allowed
        if self
            .blockchain
            .block_with_operation_code_exists(BillOpCode::RejectToPayRecourse)
        {
            return Err(ValidationError::BillWasRejectedToRecourse);
        }

        // if the bill was recoursed and there are no past endorsees to recourse against anymore,
        // no further actions are allowed
        if self
            .blockchain
            .block_with_operation_code_exists(BillOpCode::Recourse)
        {
            let past_holders = self
                .blockchain
                .get_past_endorsees_for_bill(&self.bill_keys, &self.signer_node_id)?;
            if past_holders.is_empty() {
                return Err(ValidationError::BillWasRecoursedToTheEnd);
            }
        }

        // if the last block is req to recourse and it expired, no further actions are allowed
        if let Some(req_to_recourse) = self
            .blockchain
            .get_last_version_block_with_op_code(BillOpCode::RequestRecourse)
            && BillOpCode::RequestRecourse == *self.blockchain.get_latest_block().op_code()
            && util::date::check_if_deadline_has_passed(
                req_to_recourse.timestamp,
                self.timestamp,
                RECOURSE_DEADLINE_SECONDS,
            )
        {
            return Err(ValidationError::BillRequestToRecourseExpired);
        }

        // If the bill was paid, no further actions are allowed
        if self.is_paid {
            return Err(ValidationError::BillAlreadyPaid);
        }

        match &self.bill_action {
            BillAction::Accept => {
                self.bill_is_blocked()?;
                self.bill_can_only_be_recoursed()?;
                // not already accepted
                if self
                    .blockchain
                    .block_with_operation_code_exists(BillOpCode::Accept)
                {
                    return Err(ValidationError::BillAlreadyAccepted);
                }
                // signer is drawee
                if !self.drawee_node_id.eq(&self.signer_node_id) {
                    return Err(ValidationError::CallerIsNotDrawee);
                }
            }
            BillAction::RequestAcceptance => {
                self.bill_is_blocked()?;
                self.bill_can_only_be_recoursed()?;
                // not already accepted
                if self
                    .blockchain
                    .block_with_operation_code_exists(BillOpCode::Accept)
                {
                    return Err(ValidationError::BillAlreadyAccepted);
                }
                // not already requested to accept
                if self
                    .blockchain
                    .block_with_operation_code_exists(BillOpCode::RequestToAccept)
                {
                    return Err(ValidationError::BillAlreadyRequestedToAccept);
                }
                // the caller has to be the bill holder
                if self.signer_node_id != holder_node_id {
                    return Err(ValidationError::CallerIsNotHolder);
                }
            }
            BillAction::RequestToPay(_) => {
                self.bill_is_blocked()?;
                self.bill_can_only_be_recoursed()?;
                // not already requested to pay - checked above already
                // the caller has to be the bill holder
                if self.signer_node_id != holder_node_id {
                    return Err(ValidationError::CallerIsNotHolder);
                }
            }
            BillAction::RequestRecourse(recoursee, recourse_reason) => {
                // not blocked
                self.bill_is_blocked()?;

                // the caller has to be the bill holder
                if self.signer_node_id != holder_node_id {
                    return Err(ValidationError::CallerIsNotHolder);
                }

                let past_holders = self
                    .blockchain
                    .get_past_endorsees_for_bill(&self.bill_keys, &self.signer_node_id)?;

                // validation
                if !past_holders
                    .iter()
                    .any(|h| h.pay_to_the_order_of.node_id == recoursee.node_id)
                {
                    return Err(ValidationError::RecourseeNotPastHolder);
                }

                match recourse_reason {
                    RecourseReason::Accept => {
                        if let Some(req_to_accept) = self
                            .blockchain
                            .get_last_version_block_with_op_code(BillOpCode::RequestToAccept)
                        {
                            // only if the request to accept expired or was rejected
                            if !util::date::check_if_deadline_has_passed(
                                req_to_accept.timestamp,
                                self.timestamp,
                                ACCEPT_DEADLINE_SECONDS,
                            ) && !self
                                .blockchain
                                .block_with_operation_code_exists(BillOpCode::RejectToAccept)
                            {
                                return Err(ValidationError::BillRequestToAcceptDidNotExpireAndWasNotRejected);
                            }
                        } else {
                            // if there was no request to accept, only if it was rejected
                            if !self
                                .blockchain
                                .block_with_operation_code_exists(BillOpCode::RejectToAccept)
                            {
                                return Err(ValidationError::BillRequestToAcceptDidNotExpireAndWasNotRejected);
                            }
                        }
                    }
                    RecourseReason::Pay(_, _) => {
                        if let Some(req_to_pay) = self
                            .blockchain
                            .get_last_version_block_with_op_code(BillOpCode::RequestToPay)
                        {
                            // only if the bill is not paid already - checked above

                            // only if the deadline to pay expired or was rejected
                            let deadline_base = get_expiration_deadline_base_for_req_to_pay(
                                req_to_pay.timestamp,
                                &self.maturity_date,
                            )?;
                            if !util::date::check_if_deadline_has_passed(
                                deadline_base,
                                self.timestamp,
                                PAYMENT_DEADLINE_SECONDS,
                            ) && !self
                                .blockchain
                                .block_with_operation_code_exists(BillOpCode::RejectToPay)
                            {
                                return Err(
                                    ValidationError::BillRequestToPayDidNotExpireAndWasNotRejected,
                                );
                            }
                        } else {
                            return Err(ValidationError::BillWasNotRequestedToPay);
                        }
                    }
                };
            }
            BillAction::Recourse(recoursee, sum, currency, reason) => {
                // not waiting for req to pay
                self.bill_waiting_for_req_to_pay()?;
                // not waiting for offer to sell
                self.bill_waiting_for_offer_to_sell()?;

                // the caller has to be the bill holder
                if self.signer_node_id != holder_node_id {
                    return Err(ValidationError::CallerIsNotHolder);
                }

                let recourse_reason = match reason {
                    RecourseReason::Pay(_, _) => BillRecourseReasonBlockData::Pay,
                    RecourseReason::Accept => BillRecourseReasonBlockData::Accept,
                };

                if let RecourseWaitingForPayment::Yes(payment_info) = self
                    .blockchain
                    .is_last_request_to_recourse_block_waiting_for_payment(
                        &self.bill_keys,
                        self.timestamp,
                    )?
                {
                    if payment_info.sum != *sum
                        || payment_info.currency != *currency
                        || payment_info.recoursee.node_id != recoursee.node_id
                        || payment_info.recourser.node_id != self.signer_node_id
                        || payment_info.reason != recourse_reason
                    {
                        return Err(ValidationError::BillRecourseDataInvalid);
                    }
                } else {
                    return Err(ValidationError::BillIsNotRequestedToRecourseAndWaitingForPayment);
                }
            }
            BillAction::Mint(_, _, _) => {
                self.bill_is_blocked()?;
                self.bill_can_only_be_recoursed()?;
                // the bill has to have been accepted
                if !self
                    .blockchain
                    .block_with_operation_code_exists(BillOpCode::Accept)
                {
                    return Err(ValidationError::BillNotAccepted);
                }
                // the caller has to be the bill holder
                if self.signer_node_id != holder_node_id {
                    return Err(ValidationError::CallerIsNotHolder);
                }
            }
            BillAction::OfferToSell(_, _, _) => {
                self.bill_is_blocked()?;
                self.bill_can_only_be_recoursed()?;
                // the caller has to be the bill holder
                if self.signer_node_id != holder_node_id {
                    return Err(ValidationError::CallerIsNotHolder);
                }
            }
            BillAction::Sell(buyer, sum, currency, payment_address) => {
                // not in recourse
                self.bill_waiting_for_recourse_payment()?;
                // not waiting for req to pay
                self.bill_waiting_for_req_to_pay()?;
                self.bill_can_only_be_recoursed()?;

                // the caller has to be the bill holder
                if self.signer_node_id != holder_node_id {
                    return Err(ValidationError::CallerIsNotHolder);
                }

                if let Ok(OfferToSellWaitingForPayment::Yes(payment_info)) = self
                    .blockchain
                    .is_last_offer_to_sell_block_waiting_for_payment(
                        &self.bill_keys,
                        self.timestamp,
                    )
                {
                    if payment_info.sum != *sum
                        || payment_info.currency != *currency
                        || payment_info.payment_address != *payment_address
                        || payment_info.buyer.node_id() != buyer.node_id()
                        || payment_info.seller.node_id() != self.signer_node_id
                    {
                        return Err(ValidationError::BillSellDataInvalid);
                    }
                } else {
                    return Err(ValidationError::BillIsNotOfferToSellWaitingForPayment);
                }
            }
            BillAction::Endorse(_) => {
                self.bill_is_blocked()?;
                self.bill_can_only_be_recoursed()?;
                // the caller has to be the bill holder
                if self.signer_node_id != holder_node_id {
                    return Err(ValidationError::CallerIsNotHolder);
                }
            }
            BillAction::RejectAcceptance => {
                self.bill_is_blocked()?;
                self.bill_can_only_be_recoursed()?;
                // if the op was already rejected, can't reject again - checked above
                // caller has to be the drawee
                if self.signer_node_id != self.drawee_node_id {
                    return Err(ValidationError::CallerIsNotDrawee);
                }
                // there is not allowed to be an accept block
                if self
                    .blockchain
                    .block_with_operation_code_exists(BillOpCode::Accept)
                {
                    return Err(ValidationError::BillAlreadyAccepted);
                }
            }
            BillAction::RejectBuying => {
                // not in recourse
                self.bill_waiting_for_recourse_payment()?;
                // not waiting for req to pay
                self.bill_waiting_for_req_to_pay()?;
                self.bill_can_only_be_recoursed()?;
                // if the op was already rejected, can't reject again
                if BillOpCode::RejectToBuy == *self.blockchain.get_latest_block().op_code() {
                    return Err(ValidationError::RequestAlreadyRejected);
                }
                // there has to be a offer to sell block that is not expired
                if let OfferToSellWaitingForPayment::Yes(payment_info) = self
                    .blockchain
                    .is_last_offer_to_sell_block_waiting_for_payment(
                        &self.bill_keys,
                        self.timestamp,
                    )?
                {
                    // caller has to be buyer of the offer to sell
                    if self.signer_node_id != payment_info.buyer.node_id() {
                        return Err(ValidationError::CallerIsNotBuyer);
                    }
                } else {
                    return Err(ValidationError::BillWasNotOfferedToSell);
                }
            }
            BillAction::RejectPayment => {
                // not waiting for offer to sell
                self.bill_waiting_for_offer_to_sell()?;
                // not in recourse
                self.bill_waiting_for_recourse_payment()?;
                self.bill_can_only_be_recoursed()?;
                // if the op was already rejected, can't reject again - checked above
                // caller has to be the drawee
                if self.signer_node_id != self.drawee_node_id {
                    return Err(ValidationError::CallerIsNotDrawee);
                }
                // bill is not paid already - checked above

                // there has to be a request to pay block
                if !self
                    .blockchain
                    .block_with_operation_code_exists(BillOpCode::RequestToPay)
                {
                    return Err(ValidationError::BillWasNotRequestedToPay);
                }
                // that is not expired - checked above
            }
            BillAction::RejectPaymentForRecourse => {
                // not offered to sell
                self.bill_waiting_for_offer_to_sell()?;
                // not waiting for req to pay
                self.bill_waiting_for_req_to_pay()?;
                // if the op was already rejected, can't reject again - checked above
                // there has to be a request to recourse that is not expired
                if let RecourseWaitingForPayment::Yes(payment_info) = self
                    .blockchain
                    .is_last_request_to_recourse_block_waiting_for_payment(
                        &self.bill_keys,
                        self.timestamp,
                    )?
                {
                    if self.signer_node_id != payment_info.recoursee.node_id {
                        return Err(ValidationError::CallerIsNotRecoursee);
                    }
                } else {
                    return Err(ValidationError::BillWasNotRequestedToRecourse);
                }
            }
        };
        Ok(())
    }
}

/// calculates the base for the expiration deadline of a request to pay - if it was before the
/// maturity date, we take the end of the day of the maturity date, otherwise the end of
/// day of the req to pay timestamp
pub fn get_expiration_deadline_base_for_req_to_pay(
    req_to_pay_ts: u64,
    bill_maturity_date: &str,
) -> Result<u64, ValidationError> {
    let maturity_date = util::date::date_string_to_timestamp(bill_maturity_date, None)?;
    // we calculate from the end of the day
    let maturity_date_end_of_day = util::date::end_of_day_as_timestamp(maturity_date);
    // we calculate from the end of the day of the request to pay
    let mut deadline_base = util::date::end_of_day_as_timestamp(req_to_pay_ts);
    // requested to pay after maturity date - deadline base is req to pay
    if deadline_base < maturity_date_end_of_day {
        // requested to pay before end of day of maturity date - deadline base is maturity
        // date end of day
        deadline_base = maturity_date_end_of_day;
    }
    Ok(deadline_base)
}

impl BillValidateActionData {
    /// if the bill was rejected to accept, rejected to pay, or either of them expired, it can only
    /// be recoursed from that point on
    fn bill_can_only_be_recoursed(&self) -> Result<(), ValidationError> {
        match self.bill_action {
            BillAction::Recourse(_, _, _, _)
            | BillAction::RequestRecourse(_, _)
            | BillAction::RejectPaymentForRecourse => {
                // do nothing, these actions are fine
                Ok(())
            }
            _ => {
                if self
                    .blockchain
                    .block_with_operation_code_exists(BillOpCode::RejectToAccept)
                {
                    return Err(ValidationError::BillWasRejectedToAccept);
                }

                if self
                    .blockchain
                    .block_with_operation_code_exists(BillOpCode::RejectToPay)
                {
                    return Err(ValidationError::BillWasRejectedToPay);
                }

                if let Some(req_to_pay_block) = self
                    .blockchain
                    .get_last_version_block_with_op_code(BillOpCode::RequestToPay)
                {
                    let deadline_base = get_expiration_deadline_base_for_req_to_pay(
                        req_to_pay_block.timestamp,
                        &self.maturity_date,
                    )?;
                    // not paid and not rejected (checked above)
                    if !self.is_paid
                        && util::date::check_if_deadline_has_passed(
                            deadline_base,
                            self.timestamp,
                            PAYMENT_DEADLINE_SECONDS,
                        )
                    {
                        return Err(ValidationError::BillPaymentExpired);
                    }
                }

                if let Some(req_to_accept_block) = self
                    .blockchain
                    .get_last_version_block_with_op_code(BillOpCode::RequestToAccept)
                {
                    let accepted = self
                        .blockchain
                        .block_with_operation_code_exists(BillOpCode::Accept);

                    // not accepted and not rejected (checked above)
                    if !accepted
                        && util::date::check_if_deadline_has_passed(
                            req_to_accept_block.timestamp,
                            self.timestamp,
                            ACCEPT_DEADLINE_SECONDS,
                        )
                    {
                        return Err(ValidationError::BillAcceptanceExpired);
                    }
                }

                Ok(())
            }
        }
    }

    /// if the bill is waiting for payment, it's blocked
    fn bill_is_blocked(&self) -> Result<(), ValidationError> {
        // not waiting for req to pay
        self.bill_waiting_for_req_to_pay()?;
        // not offered to sell
        self.bill_waiting_for_offer_to_sell()?;
        // not in recourse
        self.bill_waiting_for_recourse_payment()?;
        Ok(())
    }

    fn bill_waiting_for_offer_to_sell(&self) -> Result<(), ValidationError> {
        if let OfferToSellWaitingForPayment::Yes(_) = self
            .blockchain
            .is_last_offer_to_sell_block_waiting_for_payment(&self.bill_keys, self.timestamp)?
        {
            return Err(ValidationError::BillIsOfferedToSellAndWaitingForPayment);
        }
        Ok(())
    }

    fn bill_waiting_for_recourse_payment(&self) -> Result<(), ValidationError> {
        if let RecourseWaitingForPayment::Yes(_) = self
            .blockchain
            .is_last_request_to_recourse_block_waiting_for_payment(
                &self.bill_keys,
                self.timestamp,
            )?
        {
            return Err(ValidationError::BillIsInRecourseAndWaitingForPayment);
        }
        Ok(())
    }

    /// active req to pay, calculated from the start of the request
    fn bill_waiting_for_req_to_pay(&self) -> Result<(), ValidationError> {
        if self.blockchain.get_latest_block().op_code == BillOpCode::RequestToPay
            && let Some(req_to_pay) = self
                .blockchain
                .get_last_version_block_with_op_code(BillOpCode::RequestToPay)
            && !self.is_paid
            && !util::date::check_if_deadline_has_passed(
                req_to_pay.timestamp, // calculated from start of request
                self.timestamp,
                PAYMENT_DEADLINE_SECONDS,
            )
        {
            return Err(ValidationError::BillIsRequestedToPayAndWaitingForPayment);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        bill::BillKeys,
        blockchain::bill::{
            BillBlock, BillBlockchain,
            block::{
                BillAcceptBlockData, BillEndorseBlockData, BillIssueBlockData,
                BillOfferToSellBlockData, BillRecourseBlockData, BillRejectBlockData,
                BillRejectToBuyBlockData, BillRequestRecourseBlockData,
                BillRequestToAcceptBlockData, BillRequestToPayBlockData,
                tests::valid_bill_issue_block_data,
            },
        },
        contact::{BillIdentParticipant, BillParticipant},
        tests::tests::{
            OTHER_VALID_PAYMENT_ADDRESS_TESTNET, VALID_PAYMENT_ADDRESS_TESTNET, bill_id_test,
            node_id_test, node_id_test_other, private_key_test, valid_address,
            valid_bill_identified_participant, valid_bill_participant,
            valid_other_bill_identified_participant, valid_other_bill_participant,
        },
        util::{
            BcrKeys,
            date::{format_date_string, now},
        },
    };

    use super::*;
    use rstest::rstest;

    fn valid_bill_issue_data() -> BillIssueData {
        BillIssueData {
            t: 0,
            country_of_issuing: "AT".into(),
            city_of_issuing: "Vienna".into(),
            issue_date: "2025-08-12".into(),
            maturity_date: "2025-11-12".into(),
            drawee: node_id_test(),
            payee: node_id_test_other(),
            sum: "500".into(),
            currency: "sat".into(),
            country_of_payment: "FR".into(),
            city_of_payment: "Paris".into(),
            language: "de".into(),
            file_upload_ids: vec![],
            drawer_public_data: BillParticipant::Ident(valid_bill_identified_participant()),
            drawer_keys: BcrKeys::from_private_key(&private_key_test()).unwrap(),
            timestamp: 1731593928,
            blank_issue: false,
        }
    }

    #[test]
    fn test_valid_bill_issue_data() {
        let result = validate_bill_issue(&valid_bill_issue_data());
        assert_eq!(result, Ok((500, BillType::PromissoryNote)));
    }

    #[rstest]
    #[case::invalid_sum( BillIssueData { sum: "invalidsum".into(), ..valid_bill_issue_data() }, ValidationError::InvalidSum)]
    #[case::invalid_file_id( BillIssueData { file_upload_ids: vec!["".into()], ..valid_bill_issue_data() }, ValidationError::InvalidFileUploadId)]
    #[case::invalid_issue_date( BillIssueData { issue_date: "invaliddate".into(), ..valid_bill_issue_data() }, ValidationError::InvalidDate)]
    #[case::invalid_maturity_date( BillIssueData { maturity_date: "invaliddate".into(), ..valid_bill_issue_data() }, ValidationError::InvalidDate)]
    #[case::maturity_date_before_now( BillIssueData { maturity_date: "2004-01-12".into(), ..valid_bill_issue_data() }, ValidationError::MaturityDateInThePast)]
    #[case::issue_date_after_maturity_date( BillIssueData { issue_date: "2028-01-12".into(), ..valid_bill_issue_data() }, ValidationError::IssueDateAfterMaturityDate)]
    #[case::invalid_bill_type( BillIssueData { t: 5, ..valid_bill_issue_data() }, ValidationError::InvalidBillType)]
    #[case::drawee_equals_payee( BillIssueData { drawee: node_id_test(), payee: node_id_test(), ..valid_bill_issue_data() }, ValidationError::DraweeCantBePayee)]
    fn test_validate_bill_issue_data_errors(
        #[case] input: BillIssueData,
        #[case] expected: ValidationError,
    ) {
        assert_eq!(validate_bill_issue(&input), Err(expected));
    }

    fn valid_bill_blockchain_issue(issue_block_data: BillIssueBlockData) -> BillBlockchain {
        let chain = BillBlockchain::new(
            &issue_block_data,
            BcrKeys::from_private_key(&private_key_test()).unwrap(),
            None,
            BcrKeys::from_private_key(&private_key_test()).unwrap(),
            now().timestamp() as u64 - 10,
        )
        .unwrap();
        assert!(chain.is_chain_valid());
        chain
    }

    fn keys() -> BcrKeys {
        BcrKeys::from_private_key(&private_key_test()).unwrap()
    }

    fn add_req_to_accept_block(mut chain: BillBlockchain) -> BillBlockchain {
        let block = BillBlock::create_block_for_request_to_accept(
            bill_id_test(),
            chain.get_latest_block(),
            &BillRequestToAcceptBlockData {
                requester: valid_bill_participant().into(),
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
        let block = BillBlock::create_block_for_request_to_pay(
            bill_id_test(),
            chain.get_latest_block(),
            &BillRequestToPayBlockData {
                requester: valid_bill_participant().into(),
                currency: "sat".into(),
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

    fn add_offer_to_sell_block(mut chain: BillBlockchain) -> BillBlockchain {
        let block = BillBlock::create_block_for_offer_to_sell(
            bill_id_test(),
            chain.get_latest_block(),
            &BillOfferToSellBlockData {
                buyer: valid_bill_participant().into(),
                seller: valid_other_bill_participant().into(),
                sum: 500,
                currency: "sat".into(),
                payment_address: VALID_PAYMENT_ADDRESS_TESTNET.into(),
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

    fn add_req_to_recourse_accept_block(mut chain: BillBlockchain) -> BillBlockchain {
        let block = BillBlock::create_block_for_request_recourse(
            bill_id_test(),
            chain.get_latest_block(),
            &BillRequestRecourseBlockData {
                recourser: valid_bill_identified_participant().into(),
                recoursee: valid_other_bill_identified_participant().into(),
                sum: 500,
                currency: "sat".into(),
                recourse_reason: BillRecourseReasonBlockData::Accept,
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
                recourser: valid_bill_identified_participant().into(),
                recoursee: valid_other_bill_identified_participant().into(),
                sum: 500,
                currency: "sat".into(),
                recourse_reason: BillRecourseReasonBlockData::Accept,
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

    fn valid_bill_validate_action_data(chain: BillBlockchain) -> BillValidateActionData {
        BillValidateActionData {
            blockchain: chain,
            drawee_node_id: node_id_test(),
            payee_node_id: node_id_test_other(),
            endorsee_node_id: None,
            maturity_date: "2024-11-12".into(),
            bill_keys: BillKeys {
                private_key: private_key_test(),
                public_key: node_id_test().pub_key(),
            },
            timestamp: now().timestamp() as u64,
            signer_node_id: node_id_test(),
            bill_action: BillAction::Accept,
            is_paid: false,
        }
    }

    #[rstest]
    #[case::is_paid(BillValidateActionData { is_paid: true, ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Err(ValidationError::BillAlreadyPaid))]
    #[case::is_not_paid(BillValidateActionData { ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Ok(()))]
    fn test_validate_bill_paid_or_not(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::accept(BillValidateActionData { drawee_node_id: node_id_test(), ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Ok(()))]
    fn test_validate_bill_accept_valid(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::rejected_recourse_blocked(BillValidateActionData { ..valid_bill_validate_action_data(add_reject_recourse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRejectedToRecourse))]
    #[case::last_recourse_blocked(BillValidateActionData { ..valid_bill_validate_action_data(add_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRecoursedToTheEnd))]
    #[case::expired_req_to_recourse_blocked(BillValidateActionData { timestamp: now().timestamp() as u64 + (RECOURSE_DEADLINE_SECONDS * 2), ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillRequestToRecourseExpired))]
    #[case::active_req_to_pay_blocked(BillValidateActionData { ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillIsRequestedToPayAndWaitingForPayment))]
    #[case::active_offer_to_sell_blocked(BillValidateActionData { ..valid_bill_validate_action_data(add_offer_to_sell_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillIsOfferedToSellAndWaitingForPayment))]
    #[case::active_recourse_blocked(BillValidateActionData { ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillIsInRecourseAndWaitingForPayment))]
    #[case::rejected_to_accept_only_recourse(BillValidateActionData { ..valid_bill_validate_action_data(add_reject_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRejectedToAccept))]
    #[case::rejected_to_pay_only_recourse(BillValidateActionData { ..valid_bill_validate_action_data(add_reject_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRejectedToPay))]
    #[case::payment_expired_only_recourse(BillValidateActionData { timestamp: now().timestamp() as u64 + (PAYMENT_DEADLINE_SECONDS * 2), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillPaymentExpired))]
    #[case::acceptance_expired_only_recourse(BillValidateActionData { timestamp: now().timestamp() as u64 + (ACCEPT_DEADLINE_SECONDS * 2), ..valid_bill_validate_action_data(add_req_to_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillAcceptanceExpired))]
    #[case::accept_already_accepted(BillValidateActionData { ..valid_bill_validate_action_data(add_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillAlreadyAccepted))]
    #[case::accept_not_drawee(BillValidateActionData { drawee_node_id: node_id_test_other(), ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Err(ValidationError::CallerIsNotDrawee))]
    fn test_validate_bill_accept_errors(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::req_to_accept(BillValidateActionData { bill_action: BillAction::RequestAcceptance, signer_node_id: node_id_test_other(), ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Ok(()))]
    fn test_validate_bill_req_to_accept_valid(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::rejected_recourse_blocked(BillValidateActionData { bill_action: BillAction::RequestAcceptance, ..valid_bill_validate_action_data(add_reject_recourse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRejectedToRecourse))]
    #[case::last_recourse_blocked(BillValidateActionData { bill_action: BillAction::RequestAcceptance, ..valid_bill_validate_action_data(add_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRecoursedToTheEnd))]
    #[case::expired_req_to_recourse_blocked(BillValidateActionData { bill_action: BillAction::RequestAcceptance, timestamp: now().timestamp() as u64 + (RECOURSE_DEADLINE_SECONDS * 2), ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillRequestToRecourseExpired))]
    #[case::active_req_to_pay_blocked(BillValidateActionData { bill_action: BillAction::RequestAcceptance, ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillIsRequestedToPayAndWaitingForPayment))]
    #[case::active_offer_to_sell_blocked(BillValidateActionData { bill_action: BillAction::RequestAcceptance, ..valid_bill_validate_action_data(add_offer_to_sell_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillIsOfferedToSellAndWaitingForPayment))]
    #[case::active_recourse_blocked(BillValidateActionData { bill_action: BillAction::RequestAcceptance, ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillIsInRecourseAndWaitingForPayment))]
    #[case::rejected_to_accept_only_recourse(BillValidateActionData { bill_action: BillAction::RequestAcceptance, ..valid_bill_validate_action_data(add_reject_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRejectedToAccept))]
    #[case::rejected_to_pay_only_recourse(BillValidateActionData { bill_action: BillAction::RequestAcceptance, ..valid_bill_validate_action_data(add_reject_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRejectedToPay))]
    #[case::payment_expired_only_recourse(BillValidateActionData { bill_action: BillAction::RequestAcceptance, timestamp: now().timestamp() as u64 + (PAYMENT_DEADLINE_SECONDS * 2), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillPaymentExpired))]
    #[case::acceptance_expired_only_recourse(BillValidateActionData { bill_action: BillAction::RequestAcceptance, timestamp: now().timestamp() as u64 + (ACCEPT_DEADLINE_SECONDS * 2), ..valid_bill_validate_action_data(add_req_to_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillAcceptanceExpired))]
    #[case::req_to_accept_not_holder(BillValidateActionData { bill_action: BillAction::RequestAcceptance, signer_node_id: node_id_test(), ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Err(ValidationError::CallerIsNotHolder))]
    #[case::req_to_accept_already_accepted(BillValidateActionData { bill_action: BillAction::RequestAcceptance, ..valid_bill_validate_action_data(add_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillAlreadyAccepted))]
    #[case::req_to_accept_already_req_to_accepted(BillValidateActionData { bill_action: BillAction::RequestAcceptance, ..valid_bill_validate_action_data(add_req_to_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillAlreadyRequestedToAccept))]
    fn test_validate_bill_req_to_accept_errors(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::req_to_pay(BillValidateActionData { signer_node_id: node_id_test_other(), bill_action: BillAction::RequestToPay("sat".into()), ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Ok(()))]
    #[case::req_to_pay_after_maturity(BillValidateActionData { maturity_date: "2022-11-12".into(), signer_node_id: node_id_test_other(), bill_action: BillAction::RequestToPay("sat".into()), ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Ok(()))]
    #[case::req_to_pay_before_maturity(BillValidateActionData { maturity_date: "2099-11-12".into(), signer_node_id: node_id_test_other(), bill_action: BillAction::RequestToPay("sat".into()), ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data() ,)) }, Ok(()))]
    fn test_validate_bill_req_to_pay_valid(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::rejected_recourse_blocked(BillValidateActionData { bill_action: BillAction::RequestToPay("sat".into()), ..valid_bill_validate_action_data(add_reject_recourse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRejectedToRecourse))]
    #[case::last_recourse_blocked(BillValidateActionData { bill_action: BillAction::RequestToPay("sat".into()), ..valid_bill_validate_action_data(add_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRecoursedToTheEnd))]
    #[case::expired_req_to_recourse_blocked(BillValidateActionData { bill_action: BillAction::RequestToPay("sat".into()), timestamp: now().timestamp() as u64 + (RECOURSE_DEADLINE_SECONDS * 2), ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillRequestToRecourseExpired))]
    #[case::active_req_to_pay_blocked(BillValidateActionData { bill_action: BillAction::RequestToPay("sat".into()), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillIsRequestedToPayAndWaitingForPayment))]
    #[case::active_offer_to_sell_blocked(BillValidateActionData { bill_action: BillAction::RequestToPay("sat".into()), ..valid_bill_validate_action_data(add_offer_to_sell_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillIsOfferedToSellAndWaitingForPayment))]
    #[case::active_recourse_blocked(BillValidateActionData { bill_action: BillAction::RequestToPay("sat".into()), ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillIsInRecourseAndWaitingForPayment))]
    #[case::rejected_to_accept_only_recourse(BillValidateActionData { bill_action: BillAction::RequestToPay("sat".into()), ..valid_bill_validate_action_data(add_reject_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRejectedToAccept))]
    #[case::rejected_to_pay_only_recourse(BillValidateActionData { bill_action: BillAction::RequestToPay("sat".into()), ..valid_bill_validate_action_data(add_reject_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRejectedToPay))]
    #[case::payment_expired_only_recourse(BillValidateActionData { bill_action: BillAction::RequestToPay("sat".into()), timestamp: now().timestamp() as u64 + (PAYMENT_DEADLINE_SECONDS * 2), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillPaymentExpired))]
    #[case::acceptance_expired_only_recourse(BillValidateActionData { bill_action: BillAction::RequestToPay("sat".into()), timestamp: now().timestamp() as u64 + (ACCEPT_DEADLINE_SECONDS * 2), ..valid_bill_validate_action_data(add_req_to_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillAcceptanceExpired))]
    #[case::req_to_pay_not_holder(BillValidateActionData { bill_action: BillAction::RequestToPay("sat".into()), signer_node_id: node_id_test(), ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Err(ValidationError::CallerIsNotHolder))]
    #[case::req_to_pay_already_req_to_payed(BillValidateActionData { bill_action: BillAction::RequestToPay("sat".into()), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillIsRequestedToPayAndWaitingForPayment))]
    fn test_validate_bill_req_to_pay_errors(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::req_to_recourse_not_rejected_but_expired(BillValidateActionData { timestamp: now().timestamp() as u64 + (RECOURSE_DEADLINE_SECONDS * 2), endorsee_node_id: Some(node_id_test()), bill_action: BillAction::RequestRecourse(valid_other_bill_identified_participant(), RecourseReason::Accept), ..valid_bill_validate_action_data(add_req_to_accept_block(add_endorse_block(add_endorse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),), valid_other_bill_identified_participant(), valid_bill_identified_participant()), valid_bill_identified_participant(), valid_other_bill_identified_participant()))) }, Ok(()))]
    #[case::req_to_recourse_not_expired_but_rejected(BillValidateActionData { endorsee_node_id: Some(node_id_test()), bill_action: BillAction::RequestRecourse(valid_other_bill_identified_participant(), RecourseReason::Accept), ..valid_bill_validate_action_data(add_reject_accept_block(add_req_to_accept_block(add_endorse_block(add_endorse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),), valid_other_bill_identified_participant(), valid_bill_identified_participant()), valid_bill_identified_participant(), valid_other_bill_identified_participant())))) }, Ok(()))]
    #[case::req_to_recourse_not_req_to_accept_but_rejected(BillValidateActionData { endorsee_node_id: Some(node_id_test()), bill_action: BillAction::RequestRecourse(valid_other_bill_identified_participant(), RecourseReason::Accept), ..valid_bill_validate_action_data(add_reject_accept_block(add_endorse_block(add_endorse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),), valid_other_bill_identified_participant(), valid_bill_identified_participant()), valid_bill_identified_participant(), valid_other_bill_identified_participant()))) }, Ok(()))]
    fn test_validate_bill_req_to_recourse_accept_valid(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::rejected_recourse_blocked(BillValidateActionData { bill_action: BillAction::RequestRecourse(valid_bill_identified_participant(), RecourseReason::Accept), ..valid_bill_validate_action_data(add_reject_recourse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRejectedToRecourse))]
    #[case::last_recourse_blocked(BillValidateActionData { bill_action: BillAction::RequestRecourse(valid_bill_identified_participant(), RecourseReason::Accept), ..valid_bill_validate_action_data(add_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRecoursedToTheEnd))]
    #[case::expired_req_to_recourse_blocked(BillValidateActionData { bill_action: BillAction::RequestRecourse(valid_bill_identified_participant(), RecourseReason::Accept), timestamp: now().timestamp() as u64 + (RECOURSE_DEADLINE_SECONDS * 2), ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillRequestToRecourseExpired))]
    #[case::active_req_to_pay_blocked(BillValidateActionData { bill_action: BillAction::RequestRecourse(valid_bill_identified_participant(), RecourseReason::Accept), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillIsRequestedToPayAndWaitingForPayment))]
    #[case::active_offer_to_sell_blocked(BillValidateActionData { bill_action: BillAction::RequestRecourse(valid_bill_identified_participant(), RecourseReason::Accept), ..valid_bill_validate_action_data(add_offer_to_sell_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillIsOfferedToSellAndWaitingForPayment))]
    #[case::active_recourse_blocked(BillValidateActionData { bill_action: BillAction::RequestRecourse(valid_bill_identified_participant(), RecourseReason::Accept), ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillIsInRecourseAndWaitingForPayment))]
    #[case::req_to_recourse_not_holder(BillValidateActionData { bill_action: BillAction::RequestRecourse(valid_bill_identified_participant(), RecourseReason::Accept), signer_node_id: node_id_test(), ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Err(ValidationError::CallerIsNotHolder))]
    #[case::req_to_recourse_not_past_endorsee(BillValidateActionData { endorsee_node_id: Some(node_id_test()), bill_action: BillAction::RequestRecourse(valid_other_bill_identified_participant(), RecourseReason::Accept), ..valid_bill_validate_action_data(add_endorse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),), valid_other_bill_identified_participant(), valid_bill_identified_participant())) }, Err(ValidationError::RecourseeNotPastHolder))]
    #[case::req_to_recourse_not_req_to_accept_or_rejected(BillValidateActionData { endorsee_node_id: Some(node_id_test()), bill_action: BillAction::RequestRecourse(valid_other_bill_identified_participant(), RecourseReason::Accept), ..valid_bill_validate_action_data(add_endorse_block(add_endorse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),), valid_other_bill_identified_participant(), valid_bill_identified_participant()), valid_bill_identified_participant(), valid_other_bill_identified_participant())) }, Err(ValidationError::BillRequestToAcceptDidNotExpireAndWasNotRejected))]
    #[case::req_to_recourse_not_expired_or_rejected(BillValidateActionData { endorsee_node_id: Some(node_id_test()), bill_action: BillAction::RequestRecourse(valid_other_bill_identified_participant(), RecourseReason::Accept), ..valid_bill_validate_action_data(add_req_to_accept_block(add_endorse_block(add_endorse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),), valid_other_bill_identified_participant(), valid_bill_identified_participant()), valid_bill_identified_participant(), valid_other_bill_identified_participant()))) }, Err(ValidationError::BillRequestToAcceptDidNotExpireAndWasNotRejected))]
    fn test_validate_bill_req_to_recourse_accept_errors(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::req_to_recourse_rejected(BillValidateActionData { endorsee_node_id: Some(node_id_test()), bill_action: BillAction::RequestRecourse(valid_other_bill_identified_participant(), RecourseReason::Pay(500, "sat".into())), ..valid_bill_validate_action_data(add_reject_pay_block(add_req_to_pay_block(add_endorse_block(add_endorse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),), valid_other_bill_identified_participant(), valid_bill_identified_participant()), valid_bill_identified_participant(), valid_other_bill_identified_participant())))) }, Ok(()))]
    #[case::req_to_recourse_expired(BillValidateActionData { timestamp: now().timestamp() as u64 + (RECOURSE_DEADLINE_SECONDS * 2), endorsee_node_id: Some(node_id_test()), bill_action: BillAction::RequestRecourse(valid_other_bill_identified_participant(), RecourseReason::Pay(500, "sat".into())), ..valid_bill_validate_action_data(add_req_to_pay_block(add_endorse_block(add_endorse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),), valid_other_bill_identified_participant(), valid_bill_identified_participant()), valid_bill_identified_participant(), valid_other_bill_identified_participant()))) }, Ok(()))]
    fn test_validate_bill_req_to_recourse_payment_valid(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::rejected_recourse_blocked(BillValidateActionData { bill_action: BillAction::RequestRecourse(valid_bill_identified_participant(), RecourseReason::Pay(500, "sat".into())), ..valid_bill_validate_action_data(add_reject_recourse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRejectedToRecourse))]
    #[case::last_recourse_blocked(BillValidateActionData { bill_action: BillAction::RequestRecourse(valid_bill_identified_participant(), RecourseReason::Pay(500, "sat".into())), ..valid_bill_validate_action_data(add_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRecoursedToTheEnd))]
    #[case::expired_req_to_recourse_blocked(BillValidateActionData { bill_action: BillAction::RequestRecourse(valid_bill_identified_participant(), RecourseReason::Pay(500, "sat".into())), timestamp: now().timestamp() as u64 + (RECOURSE_DEADLINE_SECONDS * 2), ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillRequestToRecourseExpired))]
    #[case::active_req_to_pay_blocked(BillValidateActionData { bill_action: BillAction::RequestRecourse(valid_bill_identified_participant(), RecourseReason::Pay(500, "sat".into())), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillIsRequestedToPayAndWaitingForPayment))]
    #[case::active_offer_to_sell_blocked(BillValidateActionData { bill_action: BillAction::RequestRecourse(valid_bill_identified_participant(), RecourseReason::Pay(500, "sat".into())), ..valid_bill_validate_action_data(add_offer_to_sell_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillIsOfferedToSellAndWaitingForPayment))]
    #[case::active_recourse_blocked(BillValidateActionData { bill_action: BillAction::RequestRecourse(valid_bill_identified_participant(), RecourseReason::Pay(500, "sat".into())), ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillIsInRecourseAndWaitingForPayment))]
    #[case::req_to_recourse_not_holder(BillValidateActionData { bill_action: BillAction::RequestRecourse(valid_bill_identified_participant(), RecourseReason::Pay(500, "sat".into())), signer_node_id: node_id_test(), ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Err(ValidationError::CallerIsNotHolder))]
    #[case::req_to_recourse_not_past_endorsee(BillValidateActionData { endorsee_node_id: Some(node_id_test()), bill_action: BillAction::RequestRecourse(valid_other_bill_identified_participant(), RecourseReason::Pay(500, "sat".into())), ..valid_bill_validate_action_data(add_endorse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),), valid_other_bill_identified_participant(), valid_bill_identified_participant())) }, Err(ValidationError::RecourseeNotPastHolder))]
    #[case::req_to_recourse_paid(BillValidateActionData { is_paid: true, endorsee_node_id: Some(node_id_test()), bill_action: BillAction::RequestRecourse(valid_other_bill_identified_participant(), RecourseReason::Pay(500, "sat".into())), ..valid_bill_validate_action_data(add_endorse_block(add_endorse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),), valid_other_bill_identified_participant(), valid_bill_identified_participant()), valid_bill_identified_participant(), valid_other_bill_identified_participant())) }, Err(ValidationError::BillAlreadyPaid))]
    #[case::req_to_recourse_not_req_to_pay(BillValidateActionData { endorsee_node_id: Some(node_id_test()), bill_action: BillAction::RequestRecourse(valid_other_bill_identified_participant(), RecourseReason::Pay(500, "sat".into())), ..valid_bill_validate_action_data(add_endorse_block(add_endorse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),), valid_other_bill_identified_participant(), valid_bill_identified_participant()), valid_bill_identified_participant(), valid_other_bill_identified_participant())) }, Err(ValidationError::BillWasNotRequestedToPay))]
    #[case::req_to_recourse_not_expired_or_rejected(BillValidateActionData { endorsee_node_id: Some(node_id_test()), bill_action: BillAction::RequestRecourse(valid_other_bill_identified_participant(), RecourseReason::Pay(500, "sat".into())), ..valid_bill_validate_action_data(add_req_to_pay_block(add_endorse_block(add_endorse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),), valid_other_bill_identified_participant(), valid_bill_identified_participant()), valid_bill_identified_participant(), valid_other_bill_identified_participant()))) }, Err(ValidationError::BillIsRequestedToPayAndWaitingForPayment))]
    fn test_validate_bill_req_to_recourse_payment_errors(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::recourse(BillValidateActionData { endorsee_node_id: Some(node_id_test()), bill_action: BillAction::Recourse(valid_other_bill_identified_participant(), 500, "sat".into(), RecourseReason::Accept), ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(add_endorse_block(add_endorse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),), valid_other_bill_identified_participant(), valid_bill_identified_participant()), valid_bill_identified_participant(), valid_other_bill_identified_participant()))) }, Ok(()))]
    fn test_validate_bill_recourse_payment_valid(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::rejected_recourse_blocked(BillValidateActionData { bill_action: BillAction::Recourse(valid_bill_identified_participant(), 500, "sat".into(), RecourseReason::Accept), ..valid_bill_validate_action_data(add_reject_recourse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRejectedToRecourse))]
    #[case::last_recourse_blocked(BillValidateActionData { bill_action: BillAction::Recourse(valid_bill_identified_participant(), 500, "sat".into(), RecourseReason::Accept), ..valid_bill_validate_action_data(add_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRecoursedToTheEnd))]
    #[case::expired_req_to_recourse_blocked(BillValidateActionData { bill_action: BillAction::Recourse(valid_bill_identified_participant(), 500, "sat".into(), RecourseReason::Accept), timestamp: now().timestamp() as u64 + (RECOURSE_DEADLINE_SECONDS * 2), ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillRequestToRecourseExpired))]
    #[case::active_req_to_pay_blocked(BillValidateActionData { bill_action: BillAction::Recourse(valid_bill_identified_participant(), 500, "sat".into(), RecourseReason::Accept), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillIsRequestedToPayAndWaitingForPayment))]
    #[case::active_offer_to_sell_blocked(BillValidateActionData { bill_action: BillAction::Recourse(valid_bill_identified_participant(), 500, "sat".into(), RecourseReason::Accept), ..valid_bill_validate_action_data(add_offer_to_sell_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillIsOfferedToSellAndWaitingForPayment))]
    #[case::recourse_not_holder(BillValidateActionData { bill_action: BillAction::Recourse(valid_bill_identified_participant(), 500, "sat".into(), RecourseReason::Accept), signer_node_id: node_id_test(), ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Err(ValidationError::CallerIsNotHolder))]
    #[case::recourse_not_in_recourse(BillValidateActionData { endorsee_node_id: Some(node_id_test()), bill_action: BillAction::Recourse(valid_other_bill_identified_participant(), 500, "sat".into(), RecourseReason::Accept), ..valid_bill_validate_action_data(add_endorse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),), valid_other_bill_identified_participant(), valid_bill_identified_participant())) }, Err(ValidationError::BillIsNotRequestedToRecourseAndWaitingForPayment))]
    #[case::recourse_invalid_data_sum(BillValidateActionData { endorsee_node_id: Some(node_id_test()), bill_action: BillAction::Recourse(valid_other_bill_identified_participant(), 700, "sat".into(), RecourseReason::Accept), ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(add_endorse_block(add_endorse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),), valid_other_bill_identified_participant(), valid_bill_identified_participant()), valid_bill_identified_participant(), valid_other_bill_identified_participant()))) }, Err(ValidationError::BillRecourseDataInvalid))]
    #[case::recourse_invalid_data_currency(BillValidateActionData { endorsee_node_id: Some(node_id_test()), bill_action: BillAction::Recourse(valid_other_bill_identified_participant(), 500, "invalidcurrency".into(), RecourseReason::Accept), ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(add_endorse_block(add_endorse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),), valid_other_bill_identified_participant(), valid_bill_identified_participant()), valid_bill_identified_participant(), valid_other_bill_identified_participant()))) }, Err(ValidationError::BillRecourseDataInvalid))]
    #[case::recourse_invalid_data_reason(BillValidateActionData { endorsee_node_id: Some(node_id_test()), bill_action: BillAction::Recourse(valid_other_bill_identified_participant(), 500, "sat".into(), RecourseReason::Pay(100, "sat".into())), ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(add_endorse_block(add_endorse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),), valid_other_bill_identified_participant(), valid_bill_identified_participant()), valid_bill_identified_participant(), valid_other_bill_identified_participant()))) }, Err(ValidationError::BillRecourseDataInvalid))]
    #[case::recourse_invalid_data_recoursee(BillValidateActionData { endorsee_node_id: Some(node_id_test()), bill_action: BillAction::Recourse(valid_bill_identified_participant(), 500, "sat".into(), RecourseReason::Accept), ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(add_endorse_block(add_endorse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),), valid_other_bill_identified_participant(), valid_bill_identified_participant()), valid_bill_identified_participant(), valid_other_bill_identified_participant()))) }, Err(ValidationError::BillRecourseDataInvalid))]
    fn test_validate_bill_recourse_payment_errors(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::mint(BillValidateActionData { bill_action: BillAction::Mint(valid_other_bill_participant(), 500, "sat".into()), signer_node_id: node_id_test_other(), ..valid_bill_validate_action_data(add_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Ok(()))]
    fn test_validate_bill_mint_valid(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::rejected_recourse_blocked(BillValidateActionData { bill_action: BillAction::Mint(valid_other_bill_participant(), 500, "sat".into()), ..valid_bill_validate_action_data(add_reject_recourse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRejectedToRecourse))]
    #[case::last_recourse_blocked(BillValidateActionData { bill_action: BillAction::Mint(valid_other_bill_participant(), 500, "sat".into()), ..valid_bill_validate_action_data(add_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRecoursedToTheEnd))]
    #[case::expired_req_to_recourse_blocked(BillValidateActionData { bill_action: BillAction::Mint(valid_other_bill_participant(), 500, "sat".into()), timestamp: now().timestamp() as u64 + (RECOURSE_DEADLINE_SECONDS * 2), ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillRequestToRecourseExpired))]
    #[case::active_req_to_pay_blocked(BillValidateActionData { bill_action: BillAction::Mint(valid_other_bill_participant(), 500, "sat".into()), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillIsRequestedToPayAndWaitingForPayment))]
    #[case::active_offer_to_sell_blocked(BillValidateActionData { bill_action: BillAction::Mint(valid_other_bill_participant(), 500, "sat".into()), ..valid_bill_validate_action_data(add_offer_to_sell_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillIsOfferedToSellAndWaitingForPayment))]
    #[case::active_recourse_blocked(BillValidateActionData { bill_action: BillAction::Mint(valid_other_bill_participant(), 500, "sat".into()), ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillIsInRecourseAndWaitingForPayment))]
    #[case::rejected_to_accept_only_recourse(BillValidateActionData { bill_action: BillAction::Mint(valid_other_bill_participant(), 500, "sat".into()), ..valid_bill_validate_action_data(add_reject_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRejectedToAccept))]
    #[case::rejected_to_pay_only_recourse(BillValidateActionData { bill_action: BillAction::Mint(valid_other_bill_participant(), 500, "sat".into()), ..valid_bill_validate_action_data(add_reject_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRejectedToPay))]
    #[case::payment_expired_only_recourse(BillValidateActionData { bill_action: BillAction::Mint(valid_other_bill_participant(), 500, "sat".into()), timestamp: now().timestamp() as u64 + (PAYMENT_DEADLINE_SECONDS * 2), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillPaymentExpired))]
    #[case::acceptance_expired_only_recourse(BillValidateActionData { bill_action: BillAction::Mint(valid_other_bill_participant(), 500, "sat".into()), timestamp: now().timestamp() as u64 + (ACCEPT_DEADLINE_SECONDS * 2), ..valid_bill_validate_action_data(add_req_to_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillAcceptanceExpired))]
    #[case::mint_not_accepted(BillValidateActionData { bill_action: BillAction::Mint(valid_other_bill_participant(), 500, "sat".into()), ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Err(ValidationError::BillNotAccepted))]
    #[case::mint_not_holder(BillValidateActionData { bill_action: BillAction::Mint(valid_other_bill_participant(), 500, "sat".into()), signer_node_id: node_id_test(), ..valid_bill_validate_action_data(add_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::CallerIsNotHolder))]
    fn test_validate_bill_mint_errors(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::endorse(BillValidateActionData { bill_action: BillAction::Endorse(valid_other_bill_participant()), signer_node_id: node_id_test_other(), ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Ok(()))]
    fn test_validate_bill_endorse_valid(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::rejected_recourse_blocked(BillValidateActionData { bill_action: BillAction::Endorse(valid_other_bill_participant()), ..valid_bill_validate_action_data(add_reject_recourse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRejectedToRecourse))]
    #[case::last_recourse_blocked(BillValidateActionData { bill_action: BillAction::Endorse(valid_other_bill_participant()), ..valid_bill_validate_action_data(add_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRecoursedToTheEnd))]
    #[case::expired_req_to_recourse_blocked(BillValidateActionData { bill_action: BillAction::Endorse(valid_other_bill_participant()), timestamp: now().timestamp() as u64 + (RECOURSE_DEADLINE_SECONDS * 2), ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillRequestToRecourseExpired))]
    #[case::active_req_to_pay_blocked(BillValidateActionData { bill_action: BillAction::Endorse(valid_other_bill_participant()), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillIsRequestedToPayAndWaitingForPayment))]
    #[case::active_offer_to_sell_blocked(BillValidateActionData { bill_action: BillAction::Endorse(valid_other_bill_participant()), ..valid_bill_validate_action_data(add_offer_to_sell_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillIsOfferedToSellAndWaitingForPayment))]
    #[case::active_recourse_blocked(BillValidateActionData { bill_action: BillAction::Endorse(valid_other_bill_participant()), ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillIsInRecourseAndWaitingForPayment))]
    #[case::rejected_to_accept_only_recourse(BillValidateActionData { bill_action: BillAction::Endorse(valid_other_bill_participant()), ..valid_bill_validate_action_data(add_reject_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRejectedToAccept))]
    #[case::rejected_to_pay_only_recourse(BillValidateActionData { bill_action: BillAction::Endorse(valid_other_bill_participant()), ..valid_bill_validate_action_data(add_reject_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRejectedToPay))]
    #[case::payment_expired_only_recourse(BillValidateActionData { bill_action: BillAction::Endorse(valid_other_bill_participant()), timestamp: now().timestamp() as u64 + (PAYMENT_DEADLINE_SECONDS * 2), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillPaymentExpired))]
    #[case::acceptance_expired_only_recourse(BillValidateActionData { bill_action: BillAction::Endorse(valid_other_bill_participant()), timestamp: now().timestamp() as u64 + (ACCEPT_DEADLINE_SECONDS * 2), ..valid_bill_validate_action_data(add_req_to_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillAcceptanceExpired))]
    #[case::endorse_not_holder(BillValidateActionData { bill_action: BillAction::Endorse(valid_other_bill_participant()), signer_node_id: node_id_test(), ..valid_bill_validate_action_data(add_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::CallerIsNotHolder))]
    fn test_validate_bill_endorse_errors(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::offer_to_sell(BillValidateActionData { bill_action: BillAction::OfferToSell(valid_other_bill_participant(), 500, "sat".into()), signer_node_id: node_id_test_other(), ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Ok(()))]
    #[case::offer_to_sell_req_to_pay_expired_before_maturity(BillValidateActionData { maturity_date: "2099-11-12".into(), timestamp: now().timestamp() as u64 + (PAYMENT_DEADLINE_SECONDS * 2) ,bill_action: BillAction::OfferToSell(valid_other_bill_participant(), 500, "sat".into()), signer_node_id: node_id_test_other(), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Ok(()))]
    fn test_validate_bill_offer_to_sell_valid(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::rejected_recourse_blocked(BillValidateActionData { bill_action: BillAction::OfferToSell(valid_other_bill_participant(), 500, "sat".into()), ..valid_bill_validate_action_data(add_reject_recourse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRejectedToRecourse))]
    #[case::last_recourse_blocked(BillValidateActionData { bill_action: BillAction::OfferToSell(valid_other_bill_participant(), 500, "sat".into()), ..valid_bill_validate_action_data(add_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRecoursedToTheEnd))]
    #[case::expired_req_to_recourse_blocked(BillValidateActionData { bill_action: BillAction::OfferToSell(valid_other_bill_participant(), 500, "sat".into()), timestamp: now().timestamp() as u64 + (RECOURSE_DEADLINE_SECONDS * 2), ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillRequestToRecourseExpired))]
    #[case::active_req_to_pay_blocked(BillValidateActionData { bill_action: BillAction::OfferToSell(valid_other_bill_participant(), 500, "sat".into()), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillIsRequestedToPayAndWaitingForPayment))]
    #[case::active_offer_to_sell_blocked(BillValidateActionData { bill_action: BillAction::OfferToSell(valid_other_bill_participant(), 500, "sat".into()), ..valid_bill_validate_action_data(add_offer_to_sell_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillIsOfferedToSellAndWaitingForPayment))]
    #[case::active_recourse_blocked(BillValidateActionData { bill_action: BillAction::OfferToSell(valid_other_bill_participant(), 500, "sat".into()), ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillIsInRecourseAndWaitingForPayment))]
    #[case::rejected_to_accept_only_recourse(BillValidateActionData { bill_action: BillAction::OfferToSell(valid_other_bill_participant(), 500, "sat".into()), ..valid_bill_validate_action_data(add_reject_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRejectedToAccept))]
    #[case::rejected_to_pay_only_recourse(BillValidateActionData { bill_action: BillAction::OfferToSell(valid_other_bill_participant(), 500, "sat".into()), ..valid_bill_validate_action_data(add_reject_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRejectedToPay))]
    #[case::payment_expired_only_recourse(BillValidateActionData { bill_action: BillAction::OfferToSell(valid_other_bill_participant(), 500, "sat".into()), timestamp: now().timestamp() as u64 + (PAYMENT_DEADLINE_SECONDS * 2), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillPaymentExpired))]
    #[case::acceptance_expired_only_recourse(BillValidateActionData { bill_action: BillAction::OfferToSell(valid_other_bill_participant(), 500, "sat".into()), timestamp: now().timestamp() as u64 + (ACCEPT_DEADLINE_SECONDS * 2), ..valid_bill_validate_action_data(add_req_to_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillAcceptanceExpired))]
    #[case::offer_to_sell_not_holder(BillValidateActionData { bill_action: BillAction::OfferToSell(valid_other_bill_participant(), 500, "sat".into()), signer_node_id: node_id_test(), ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Err(ValidationError::CallerIsNotHolder))]
    fn test_validate_bill_offer_to_sell_errors(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::sell(BillValidateActionData { bill_action: BillAction::Sell(valid_bill_participant(), 500, "sat".into(), VALID_PAYMENT_ADDRESS_TESTNET.into()), signer_node_id: node_id_test_other(), ..valid_bill_validate_action_data(add_offer_to_sell_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Ok(()))]
    // minus 8 seconds so timestamp is before offer to sell expiry and after req to pay expiry
    // as every block adds 1 sec to issue block, which is now() - 10
    #[case::sell_req_to_pay_expired_before_maturity(BillValidateActionData { maturity_date: "2099-11-12".into(), timestamp: now().timestamp() as u64 + (PAYMENT_DEADLINE_SECONDS - 8), bill_action: BillAction::Sell(valid_bill_participant(), 500, "sat".into(), VALID_PAYMENT_ADDRESS_TESTNET.into()), signer_node_id: node_id_test_other(), ..valid_bill_validate_action_data(add_offer_to_sell_block(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)))) }, Ok(()))]
    fn test_validate_bill_sell_valid(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::rejected_recourse_blocked(BillValidateActionData { bill_action: BillAction::Sell(valid_other_bill_participant(), 500, "sat".into(), VALID_PAYMENT_ADDRESS_TESTNET.into()), ..valid_bill_validate_action_data(add_reject_recourse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRejectedToRecourse))]
    #[case::last_recourse_blocked(BillValidateActionData { bill_action: BillAction::Sell(valid_other_bill_participant(), 500, "sat".into(), VALID_PAYMENT_ADDRESS_TESTNET.into()), ..valid_bill_validate_action_data(add_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRecoursedToTheEnd))]
    #[case::expired_req_to_recourse_blocked(BillValidateActionData { bill_action: BillAction::Sell(valid_other_bill_participant(), 500, "sat".into(), VALID_PAYMENT_ADDRESS_TESTNET.into()), timestamp: now().timestamp() as u64 + (RECOURSE_DEADLINE_SECONDS * 2), ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillRequestToRecourseExpired))]
    #[case::active_req_to_pay_blocked(BillValidateActionData { bill_action: BillAction::Sell(valid_other_bill_participant(), 500, "sat".into(), VALID_PAYMENT_ADDRESS_TESTNET.into()), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillIsRequestedToPayAndWaitingForPayment))]
    #[case::active_recourse_blocked(BillValidateActionData { bill_action: BillAction::Sell(valid_other_bill_participant(), 500, "sat".into(), VALID_PAYMENT_ADDRESS_TESTNET.into()), ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillIsInRecourseAndWaitingForPayment))]
    #[case::rejected_to_accept_only_recourse(BillValidateActionData { bill_action: BillAction::Sell(valid_other_bill_participant(), 500, "sat".into(), VALID_PAYMENT_ADDRESS_TESTNET.into()), ..valid_bill_validate_action_data(add_reject_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRejectedToAccept))]
    #[case::rejected_to_pay_only_recourse(BillValidateActionData { bill_action: BillAction::Sell(valid_other_bill_participant(), 500, "sat".into(), VALID_PAYMENT_ADDRESS_TESTNET.into()), ..valid_bill_validate_action_data(add_reject_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRejectedToPay))]
    #[case::payment_expired_only_recourse(BillValidateActionData { bill_action: BillAction::Sell(valid_other_bill_participant(), 500, "sat".into(), VALID_PAYMENT_ADDRESS_TESTNET.into()), timestamp: now().timestamp() as u64 + (PAYMENT_DEADLINE_SECONDS * 2), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillPaymentExpired))]
    #[case::acceptance_expired_only_recourse(BillValidateActionData { bill_action: BillAction::Sell(valid_other_bill_participant(), 500, "sat".into(), VALID_PAYMENT_ADDRESS_TESTNET.into()), timestamp: now().timestamp() as u64 + (ACCEPT_DEADLINE_SECONDS * 2), ..valid_bill_validate_action_data(add_req_to_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillAcceptanceExpired))]
    #[case::sell_not_holder(BillValidateActionData { bill_action: BillAction::Sell(valid_other_bill_participant(), 500, "sat".into(), VALID_PAYMENT_ADDRESS_TESTNET.into()), signer_node_id: node_id_test(), ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Err(ValidationError::CallerIsNotHolder))]
    #[case::sell_not_offered_to_sell(BillValidateActionData { bill_action: BillAction::Sell(valid_other_bill_participant(), 500, "sat".into(), VALID_PAYMENT_ADDRESS_TESTNET.into()), signer_node_id: node_id_test_other(), ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Err(ValidationError::BillIsNotOfferToSellWaitingForPayment))]
    #[case::sell_invalid_data_sum(BillValidateActionData { bill_action: BillAction::Sell(valid_bill_participant(), 700, "sat".into(), VALID_PAYMENT_ADDRESS_TESTNET.into()), signer_node_id: node_id_test_other(), ..valid_bill_validate_action_data(add_offer_to_sell_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillSellDataInvalid))]
    #[case::sell_invalid_data_currency(BillValidateActionData { bill_action: BillAction::Sell(valid_bill_participant(), 500, "invalidcurrency".into(), VALID_PAYMENT_ADDRESS_TESTNET.into()), signer_node_id: node_id_test_other(), ..valid_bill_validate_action_data(add_offer_to_sell_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillSellDataInvalid))]
    #[case::sell_invalid_data_buyer(BillValidateActionData { bill_action: BillAction::Sell(valid_other_bill_participant(), 500, "sat".into(), VALID_PAYMENT_ADDRESS_TESTNET.into()), signer_node_id: node_id_test_other(), ..valid_bill_validate_action_data(add_offer_to_sell_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillSellDataInvalid))]
    #[case::sell_invalid_data_payment_address(BillValidateActionData { bill_action: BillAction::Sell(valid_other_bill_participant(), 500, "sat".into(), OTHER_VALID_PAYMENT_ADDRESS_TESTNET.into()), signer_node_id: node_id_test_other(), ..valid_bill_validate_action_data(add_offer_to_sell_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillSellDataInvalid))]
    fn test_validate_bill_sell_errors(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::reject_to_accept(BillValidateActionData { bill_action: BillAction::RejectAcceptance, ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Ok(()))]
    fn test_validate_bill_reject_accept_valid(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::rejected_recourse_blocked(BillValidateActionData { bill_action: BillAction::RejectAcceptance, ..valid_bill_validate_action_data(add_reject_recourse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRejectedToRecourse))]
    #[case::last_recourse_blocked(BillValidateActionData { bill_action: BillAction::RejectAcceptance, ..valid_bill_validate_action_data(add_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRecoursedToTheEnd))]
    #[case::expired_req_to_recourse_blocked(BillValidateActionData { bill_action: BillAction::RejectAcceptance, timestamp: now().timestamp() as u64 + (RECOURSE_DEADLINE_SECONDS * 2), ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillRequestToRecourseExpired))]
    #[case::active_req_to_pay_blocked(BillValidateActionData { bill_action: BillAction::RejectAcceptance, ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillIsRequestedToPayAndWaitingForPayment))]
    #[case::active_offer_to_sell_blocked(BillValidateActionData { bill_action: BillAction::RejectAcceptance, ..valid_bill_validate_action_data(add_offer_to_sell_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillIsOfferedToSellAndWaitingForPayment))]
    #[case::active_recourse_blocked(BillValidateActionData { bill_action: BillAction::RejectAcceptance, ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillIsInRecourseAndWaitingForPayment))]
    #[case::rejected_to_accept_only_recourse(BillValidateActionData { bill_action: BillAction::RejectAcceptance, ..valid_bill_validate_action_data(add_reject_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRejectedToAccept))]
    #[case::rejected_to_pay_only_recourse(BillValidateActionData { bill_action: BillAction::RejectAcceptance, ..valid_bill_validate_action_data(add_reject_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRejectedToPay))]
    #[case::payment_expired_only_recourse(BillValidateActionData { bill_action: BillAction::RejectAcceptance, timestamp: now().timestamp() as u64 + (PAYMENT_DEADLINE_SECONDS * 2), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillPaymentExpired))]
    #[case::acceptance_expired_only_recourse(BillValidateActionData { bill_action: BillAction::RejectAcceptance, timestamp: now().timestamp() as u64 + (ACCEPT_DEADLINE_SECONDS * 2), ..valid_bill_validate_action_data(add_req_to_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillAcceptanceExpired))]
    #[case::reject_to_accept_already_rejected(BillValidateActionData { bill_action: BillAction::RejectAcceptance, ..valid_bill_validate_action_data(add_reject_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRejectedToAccept))]
    #[case::reject_to_accept_not_drawee(BillValidateActionData { bill_action: BillAction::RejectAcceptance, signer_node_id: node_id_test_other(), ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Err(ValidationError::CallerIsNotDrawee))]
    #[case::reject_to_accept_accepted(BillValidateActionData { bill_action: BillAction::RejectAcceptance, ..valid_bill_validate_action_data(add_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillAlreadyAccepted))]
    fn test_validate_bill_reject_accept_errors(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::reject_to_buy_not_buyer(BillValidateActionData { bill_action: BillAction::RejectBuying, signer_node_id: node_id_test(), ..valid_bill_validate_action_data(add_offer_to_sell_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Ok(()))]
    fn test_validate_bill_reject_buying_valid(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::rejected_recourse_blocked(BillValidateActionData { bill_action: BillAction::RejectBuying, ..valid_bill_validate_action_data(add_reject_recourse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRejectedToRecourse))]
    #[case::last_recourse_blocked(BillValidateActionData { bill_action: BillAction::RejectBuying, ..valid_bill_validate_action_data(add_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRecoursedToTheEnd))]
    #[case::expired_req_to_recourse_blocked(BillValidateActionData { bill_action: BillAction::RejectBuying, timestamp: now().timestamp() as u64 + (RECOURSE_DEADLINE_SECONDS * 2), ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillRequestToRecourseExpired))]
    #[case::active_req_to_pay_blocked(BillValidateActionData { bill_action: BillAction::RejectBuying, ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillIsRequestedToPayAndWaitingForPayment))]
    #[case::active_recourse_blocked(BillValidateActionData { bill_action: BillAction::RejectBuying, ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillIsInRecourseAndWaitingForPayment))]
    #[case::rejected_to_accept_only_recourse(BillValidateActionData { bill_action: BillAction::RejectBuying, ..valid_bill_validate_action_data(add_reject_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRejectedToAccept))]
    #[case::rejected_to_pay_only_recourse(BillValidateActionData { bill_action: BillAction::RejectBuying, ..valid_bill_validate_action_data(add_reject_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRejectedToPay))]
    #[case::payment_expired_only_recourse(BillValidateActionData { bill_action: BillAction::RejectBuying, timestamp: now().timestamp() as u64 + (PAYMENT_DEADLINE_SECONDS * 2), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillPaymentExpired))]
    #[case::acceptance_expired_only_recourse(BillValidateActionData { bill_action: BillAction::RejectBuying, timestamp: now().timestamp() as u64 + (ACCEPT_DEADLINE_SECONDS * 2), ..valid_bill_validate_action_data(add_req_to_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillAcceptanceExpired))]
    #[case::reject_to_buy_already_rejected(BillValidateActionData { bill_action: BillAction::RejectBuying, ..valid_bill_validate_action_data(add_reject_buy_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::RequestAlreadyRejected))]
    #[case::reject_to_buy_not_offered_to_sell(BillValidateActionData { bill_action: BillAction::RejectBuying, ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Err(ValidationError::BillWasNotOfferedToSell))]
    #[case::reject_to_buy_not_buyer(BillValidateActionData { bill_action: BillAction::RejectBuying, signer_node_id: node_id_test_other(), ..valid_bill_validate_action_data(add_offer_to_sell_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::CallerIsNotBuyer))]
    fn test_validate_bill_reject_buying_errors(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::reject_to_pay(BillValidateActionData { bill_action: BillAction::RejectPayment, ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Ok(()))]
    #[case::reject_to_pay_maturity_not_expired(BillValidateActionData { maturity_date: format_date_string(now()),  bill_action: BillAction::RejectPayment, ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Ok(()))]
    fn test_validate_bill_reject_payment_valid(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::rejected_recourse_blocked(BillValidateActionData { bill_action: BillAction::RejectPayment, ..valid_bill_validate_action_data(add_reject_recourse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRejectedToRecourse))]
    #[case::last_recourse_blocked(BillValidateActionData { bill_action: BillAction::RejectPayment, ..valid_bill_validate_action_data(add_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRecoursedToTheEnd))]
    #[case::expired_req_to_recourse_blocked(BillValidateActionData { bill_action: BillAction::RejectPayment, timestamp: now().timestamp() as u64 + (RECOURSE_DEADLINE_SECONDS * 2), ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillRequestToRecourseExpired))]
    #[case::active_offer_to_sell_blocked(BillValidateActionData { bill_action: BillAction::RejectAcceptance, ..valid_bill_validate_action_data(add_offer_to_sell_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillIsOfferedToSellAndWaitingForPayment))]
    #[case::active_recourse_blocked(BillValidateActionData { bill_action: BillAction::RejectPayment, ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillIsInRecourseAndWaitingForPayment))]
    #[case::rejected_to_accept_only_recourse(BillValidateActionData { bill_action: BillAction::RejectPayment, ..valid_bill_validate_action_data(add_reject_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRejectedToAccept))]
    #[case::rejected_to_pay_only_recourse(BillValidateActionData { bill_action: BillAction::RejectPayment, ..valid_bill_validate_action_data(add_reject_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRejectedToPay))]
    #[case::payment_expired_only_recourse(BillValidateActionData { bill_action: BillAction::RejectPayment, timestamp: now().timestamp() as u64 + (PAYMENT_DEADLINE_SECONDS * 2), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillPaymentExpired))]
    #[case::acceptance_expired_only_recourse(BillValidateActionData { bill_action: BillAction::RejectPayment, timestamp: now().timestamp() as u64 + (ACCEPT_DEADLINE_SECONDS * 2), ..valid_bill_validate_action_data(add_req_to_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillAcceptanceExpired))]
    #[case::reject_to_pay_already_rejected(BillValidateActionData { bill_action: BillAction::RejectPayment, ..valid_bill_validate_action_data(add_reject_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRejectedToPay))]
    #[case::reject_to_pay_not_drawee(BillValidateActionData { bill_action: BillAction::RejectPayment, signer_node_id: node_id_test_other(), ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::CallerIsNotDrawee))]
    #[case::reject_to_pay_paid(BillValidateActionData { is_paid: true, bill_action: BillAction::RejectPayment, ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Err(ValidationError::BillAlreadyPaid))]
    #[case::reject_to_pay_not_req_to_pay(BillValidateActionData { bill_action: BillAction::RejectPayment, ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Err(ValidationError::BillWasNotRequestedToPay))]
    #[case::reject_to_pay_expired(BillValidateActionData { timestamp: now().timestamp() as u64 + (PAYMENT_DEADLINE_SECONDS * 2), bill_action: BillAction::RejectPayment, ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillPaymentExpired))]
    fn test_validate_bill_reject_payment_errors(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::reject_to_recourse(BillValidateActionData { signer_node_id: node_id_test_other(), bill_action: BillAction::RejectPaymentForRecourse, ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Ok(()))]
    fn test_validate_bill_reject_recourse_valid(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }

    #[rstest]
    #[case::rejected_recourse_blocked(BillValidateActionData { bill_action: BillAction::RejectPaymentForRecourse, ..valid_bill_validate_action_data(add_reject_recourse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRejectedToRecourse))]
    #[case::last_recourse_blocked(BillValidateActionData { bill_action: BillAction::RejectPaymentForRecourse, ..valid_bill_validate_action_data(add_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRecoursedToTheEnd))]
    #[case::expired_req_to_recourse_blocked(BillValidateActionData { bill_action: BillAction::RejectPaymentForRecourse, timestamp: now().timestamp() as u64 + (RECOURSE_DEADLINE_SECONDS * 2), ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillRequestToRecourseExpired))]
    #[case::active_offer_to_sell_blocked(BillValidateActionData { bill_action: BillAction::RejectAcceptance, ..valid_bill_validate_action_data(add_offer_to_sell_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillIsOfferedToSellAndWaitingForPayment))]
    #[case::active_req_to_pay_blocked(BillValidateActionData { bill_action: BillAction::RejectBuying, ..valid_bill_validate_action_data(add_req_to_pay_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillIsRequestedToPayAndWaitingForPayment))]
    #[case::reject_to_recourse_already_rejected(BillValidateActionData { bill_action: BillAction::RejectPaymentForRecourse, ..valid_bill_validate_action_data(add_reject_recourse_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillWasRejectedToRecourse))]
    #[case::reject_to_recourse_not_req_to_recourse(BillValidateActionData { bill_action: BillAction::RejectPaymentForRecourse, ..valid_bill_validate_action_data(valid_bill_blockchain_issue( valid_bill_issue_block_data(),)) }, Err(ValidationError::BillWasNotRequestedToRecourse))]
    #[case::reject_to_recourse_not_recoursee(BillValidateActionData { bill_action: BillAction::RejectPaymentForRecourse, signer_node_id: node_id_test(), ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::CallerIsNotRecoursee))]
    #[case::reject_to_recourse_expired(BillValidateActionData { timestamp: now().timestamp() as u64 + (RECOURSE_DEADLINE_SECONDS * 2), bill_action: BillAction::RejectPaymentForRecourse, ..valid_bill_validate_action_data(add_req_to_recourse_accept_block(valid_bill_blockchain_issue( valid_bill_issue_block_data(),))) }, Err(ValidationError::BillRequestToRecourseExpired))]
    fn test_validate_bill_reject_recourse_errors(
        #[case] input: BillValidateActionData,
        #[case] expected: Result<(), ValidationError>,
    ) {
        assert_eq!(input.validate(), expected);
    }
}
