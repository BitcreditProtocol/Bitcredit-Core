use std::str::FromStr;

use super::Result;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bcr_ebill_api::{
    data::{
        NodeId,
        bill::{
            BillAction, BillId, BillIssueData, BillsFilterRole, LightBitcreditBillResult,
            RecourseReason,
        },
        contact::{BillAnonParticipant, BillIdentParticipant, BillParticipant},
        identity::IdentityType,
    },
    external,
    service::{Error, bill_service::Error as BillServiceError},
    util::{
        self, BcrKeys, ValidationError, currency,
        file::{UploadFileHandler, detect_content_type_for_bytes},
    },
};
use log::error;
use wasm_bindgen::prelude::*;

use crate::{
    api::identity::get_current_identity_node_id,
    context::get_ctx,
    data::{
        Base64FileResponse, BinaryFileResponse, UploadFile, UploadFileResponse,
        bill::{
            AcceptBitcreditBillPayload, BillCombinedBitcoinKeyWeb, BillIdResponse,
            BillNumbersToWordsForSum, BillsResponse, BillsSearchFilterPayload,
            BitcreditBillPayload, BitcreditBillWeb, EndorseBitcreditBillPayload,
            EndorsementsResponse, LightBillsResponse, OfferToSellBitcreditBillPayload,
            PastEndorseesResponse, PastPaymentsResponse, RejectActionBillPayload,
            RequestRecourseForAcceptancePayload, RequestRecourseForPaymentPayload,
            RequestToAcceptBitcreditBillPayload, RequestToMintBitcreditBillPayload,
            RequestToPayBitcreditBillPayload,
        },
        mint::MintRequestStateResponse,
    },
};

use super::identity::get_current_identity;

async fn get_attachment(bill_id: &str, file_name: &str) -> Result<(Vec<u8>, String)> {
    let parsed_bill_id = BillId::from_str(bill_id)?;
    let current_timestamp = util::date::now().timestamp() as u64;
    let identity = get_ctx().identity_service.get_identity().await?;
    // get bill
    let bill = get_ctx()
        .bill_service
        .get_detail(
            &parsed_bill_id,
            &identity,
            &get_current_identity_node_id().await?,
            current_timestamp,
        )
        .await?;

    // check if this file even exists on the bill
    let file = match bill.data.files.iter().find(|f| f.name == file_name) {
        Some(f) => f,
        None => {
            return Err(bcr_ebill_api::service::bill_service::Error::NotFound.into());
        }
    };

    // fetch the attachment
    let keys = get_ctx()
        .bill_service
        .get_bill_keys(&parsed_bill_id)
        .await?;
    let file_bytes = get_ctx()
        .bill_service
        .open_and_decrypt_attached_file(&parsed_bill_id, file, &keys.private_key)
        .await?;

    let content_type = detect_content_type_for_bytes(&file_bytes)
        .ok_or(Error::Validation(ValidationError::InvalidContentType))?;
    Ok((file_bytes, content_type))
}

#[wasm_bindgen]
pub struct Bill;

#[wasm_bindgen]
impl Bill {
    #[wasm_bindgen]
    pub fn new() -> Self {
        Bill
    }

    #[wasm_bindgen(unchecked_return_type = "EndorsementsResponse")]
    pub async fn endorsements(&self, id: &str) -> Result<JsValue> {
        let bill_id = BillId::from_str(id)?;
        let result = get_ctx()
            .bill_service
            .get_endorsements(&bill_id, &get_current_identity_node_id().await?)
            .await?;
        let res = serde_wasm_bindgen::to_value(&EndorsementsResponse {
            endorsements: result.into_iter().map(|e| e.into()).collect(),
        })?;
        Ok(res)
    }

    #[wasm_bindgen(unchecked_return_type = "PastPaymentsResponse")]
    pub async fn past_payments(&self, id: &str) -> Result<JsValue> {
        let bill_id = BillId::from_str(id)?;
        let (caller_public_data, caller_keys) = get_signer_public_data_and_keys().await?;
        let result = get_ctx()
            .bill_service
            .get_past_payments(
                &bill_id,
                &caller_public_data,
                &caller_keys,
                util::date::now().timestamp() as u64,
            )
            .await?;
        let res = serde_wasm_bindgen::to_value(&PastPaymentsResponse {
            past_payments: result.into_iter().map(|e| e.into()).collect(),
        })?;
        Ok(res)
    }

    #[wasm_bindgen(unchecked_return_type = "PastEndorseesResponse")]
    pub async fn past_endorsees(&self, id: &str) -> Result<JsValue> {
        let bill_id = BillId::from_str(id)?;
        let result = get_ctx()
            .bill_service
            .get_past_endorsees(&bill_id, &get_current_identity_node_id().await?)
            .await?;
        let res = serde_wasm_bindgen::to_value(&PastEndorseesResponse {
            past_endorsees: result.into_iter().map(|e| e.into()).collect(),
        })?;
        Ok(res)
    }

    #[wasm_bindgen(unchecked_return_type = "BillCombinedBitcoinKeyWeb")]
    pub async fn bitcoin_key(&self, id: &str) -> Result<JsValue> {
        let bill_id = BillId::from_str(id)?;
        let (caller_public_data, caller_keys) = get_signer_public_data_and_keys().await?;
        let combined_key = get_ctx()
            .bill_service
            .get_combined_bitcoin_key_for_bill(&bill_id, &caller_public_data, &caller_keys)
            .await?;
        let res = serde_wasm_bindgen::to_value::<BillCombinedBitcoinKeyWeb>(&combined_key.into())?;
        Ok(res)
    }

    #[wasm_bindgen(unchecked_return_type = "BinaryFileResponse")]
    pub async fn attachment(&self, bill_id: &str, file_name: &str) -> Result<JsValue> {
        let (file_bytes, content_type) = get_attachment(bill_id, file_name).await?;
        let res = serde_wasm_bindgen::to_value(&BinaryFileResponse {
            data: file_bytes,
            name: file_name.to_owned(),
            content_type,
        })?;
        Ok(res)
    }

    #[wasm_bindgen(unchecked_return_type = "Base64FileResponse")]
    pub async fn attachment_base64(&self, bill_id: &str, file_name: &str) -> Result<JsValue> {
        let (file_bytes, content_type) = get_attachment(bill_id, file_name).await?;
        let res = serde_wasm_bindgen::to_value(&Base64FileResponse {
            data: STANDARD.encode(&file_bytes),
            name: file_name.to_owned(),
            content_type,
        })?;
        Ok(res)
    }

    #[wasm_bindgen(unchecked_return_type = "UploadFileResponse")]
    pub async fn upload(
        &self,
        #[wasm_bindgen(unchecked_param_type = "UploadFile")] payload: JsValue,
    ) -> Result<JsValue> {
        let upload_file: UploadFile = serde_wasm_bindgen::from_value(payload)?;
        let upload_file_handler: &dyn UploadFileHandler = &upload_file as &dyn UploadFileHandler;

        get_ctx()
            .file_upload_service
            .validate_attached_file(upload_file_handler)
            .await?;

        let file_upload_response = get_ctx()
            .file_upload_service
            .upload_file(upload_file_handler)
            .await?;

        let res = serde_wasm_bindgen::to_value::<UploadFileResponse>(&file_upload_response.into())?;
        Ok(res)
    }

    #[wasm_bindgen(unchecked_return_type = "LightBillsResponse")]
    pub async fn search(
        &self,
        #[wasm_bindgen(unchecked_param_type = "BillsSearchFilterPayload")] payload: JsValue,
    ) -> Result<JsValue> {
        let filter_payload: BillsSearchFilterPayload = serde_wasm_bindgen::from_value(payload)?;
        let filter = filter_payload.filter;

        let (from, to) = match filter.date_range {
            None => (None, None),
            Some(date_range) => {
                let from = util::date::date_string_to_timestamp(&date_range.from, None)?;
                // Change the date to the end of the day, so we collect bills during the day as well
                let to = util::date::date_string_to_timestamp(&date_range.to, None)
                    .map(util::date::end_of_day_as_timestamp)?;
                (Some(from), Some(to))
            }
        };
        let bills = get_ctx()
            .bill_service
            .search_bills(
                &filter.currency,
                &filter.search_term,
                from,
                to,
                &BillsFilterRole::from(filter.role),
                &get_current_identity_node_id().await?,
            )
            .await?;

        let res = serde_wasm_bindgen::to_value(&LightBillsResponse {
            bills: bills.into_iter().map(|b| b.into()).collect(),
        })?;
        Ok(res)
    }

    #[wasm_bindgen(unchecked_return_type = "LightBillsResponse")]
    pub async fn list_light(&self) -> Result<JsValue> {
        let bills: Vec<LightBitcreditBillResult> = get_ctx()
            .bill_service
            .get_bills(&get_current_identity_node_id().await?)
            .await?
            .into_iter()
            .map(|b| b.into())
            .collect();
        let res = serde_wasm_bindgen::to_value(&LightBillsResponse {
            bills: bills.into_iter().map(|b| b.into()).collect(),
        })?;
        Ok(res)
    }

    #[wasm_bindgen(unchecked_return_type = "BillsResponse")]
    pub async fn list(&self) -> Result<JsValue> {
        let bills = get_ctx()
            .bill_service
            .get_bills(&get_current_identity_node_id().await?)
            .await?;
        let res = serde_wasm_bindgen::to_value(&BillsResponse {
            bills: bills.into_iter().map(|b| b.into()).collect(),
        })?;
        Ok(res)
    }

    #[wasm_bindgen(unchecked_return_type = "BillNumbersToWordsForSum")]
    pub async fn numbers_to_words_for_sum(&self, id: &str) -> Result<JsValue> {
        let bill_id = BillId::from_str(id)?;
        let current_timestamp = util::date::now().timestamp() as u64;
        let identity = get_ctx().identity_service.get_identity().await?;
        let bill = get_ctx()
            .bill_service
            .get_detail(
                &bill_id,
                &identity,
                &get_current_identity_node_id().await?,
                current_timestamp,
            )
            .await?;
        let sum = bill.data.sum;
        let parsed_sum = currency::parse_sum(&sum)?;
        let sum_as_words = util::numbers_to_words::encode(&parsed_sum);
        let res = serde_wasm_bindgen::to_value(&BillNumbersToWordsForSum {
            sum: parsed_sum,
            sum_as_words,
        })?;
        Ok(res)
    }

    #[wasm_bindgen(unchecked_return_type = "BitcreditBillWeb")]
    pub async fn detail(&self, id: &str) -> Result<JsValue> {
        let bill_id = BillId::from_str(id)?;
        let current_timestamp = util::date::now().timestamp() as u64;
        let identity = get_ctx().identity_service.get_identity().await?;
        let bill_detail = get_ctx()
            .bill_service
            .get_detail(
                &bill_id,
                &identity,
                &get_current_identity_node_id().await?,
                current_timestamp,
            )
            .await?;

        let res = serde_wasm_bindgen::to_value::<BitcreditBillWeb>(&bill_detail.into())?;
        Ok(res)
    }

    #[wasm_bindgen]
    pub async fn check_payment_for_bill(&self, id: &str) -> Result<()> {
        let bill_id = BillId::from_str(id)?;
        let identity = get_ctx().identity_service.get_full_identity().await?;
        if let Err(e) = get_ctx()
            .bill_service
            .check_payment_for_bill(&bill_id, &identity.identity)
            .await
        {
            error!("Error while checking bill payment for {id}: {e}");
        }

        if let Err(e) = get_ctx()
            .bill_service
            .check_offer_to_sell_payment_for_bill(&bill_id, &identity)
            .await
        {
            error!("Error while checking bill offer to sell payment for {id}: {e}");
        }

        if let Err(e) = get_ctx()
            .bill_service
            .check_recourse_payment_for_bill(&bill_id, &identity)
            .await
        {
            error!("Error while checking bill recourse payment for {id}: {e}");
        }
        Ok(())
    }

    #[wasm_bindgen]
    pub async fn check_payment(&self) -> Result<()> {
        if let Err(e) = get_ctx().bill_service.check_bills_payment().await {
            error!("Error while checking bills payment: {e}");
        }

        if let Err(e) = get_ctx()
            .bill_service
            .check_bills_offer_to_sell_payment()
            .await
        {
            error!("Error while checking bills offer to sell payment: {e}");
        }

        if let Err(e) = get_ctx()
            .bill_service
            .check_bills_in_recourse_payment()
            .await
        {
            error!("Error while checking bills recourse payment: {e}");
        }
        Ok(())
    }

    async fn issue_bill(
        &self,
        bill_payload: BitcreditBillPayload,
        timestamp: u64,
        blank_issue: bool,
    ) -> Result<BillId> {
        let (drawer_public_data, drawer_keys) = get_signer_public_data_and_keys().await?;

        let bill = get_ctx()
            .bill_service
            .issue_new_bill(BillIssueData {
                t: bill_payload.t,
                country_of_issuing: bill_payload.country_of_issuing.to_owned(),
                city_of_issuing: bill_payload.city_of_issuing.to_owned(),
                issue_date: bill_payload.issue_date.to_owned(),
                maturity_date: bill_payload.maturity_date.to_owned(),
                drawee: NodeId::from_str(&bill_payload.drawee)?,
                payee: NodeId::from_str(&bill_payload.payee)?,
                sum: bill_payload.sum.to_owned(),
                currency: bill_payload.currency.to_owned(),
                country_of_payment: bill_payload.country_of_payment.to_owned(),
                city_of_payment: bill_payload.city_of_payment.to_owned(),
                language: bill_payload.language.to_owned(),
                file_upload_ids: bill_payload.file_upload_ids.to_owned(),
                drawer_public_data: drawer_public_data.clone(),
                drawer_keys: drawer_keys.clone(),
                timestamp,
                blank_issue,
            })
            .await?;

        Ok(bill.id)
    }

    #[wasm_bindgen(unchecked_return_type = "BillIdResponse")]
    pub async fn issue(
        &self,
        #[wasm_bindgen(unchecked_param_type = "BitcreditBillPayload")] payload: JsValue,
    ) -> Result<JsValue> {
        let bill_payload: BitcreditBillPayload = serde_wasm_bindgen::from_value(payload)?;
        let timestamp = external::time::TimeApi::get_atomic_time().await.timestamp;
        let bill_id = self.issue_bill(bill_payload, timestamp, false).await?;
        let res = serde_wasm_bindgen::to_value(&BillIdResponse { id: bill_id })?;
        Ok(res)
    }

    #[wasm_bindgen(unchecked_return_type = "BillIdResponse")]
    pub async fn issue_blank(
        &self,
        #[wasm_bindgen(unchecked_param_type = "BitcreditBillPayload")] payload: JsValue,
    ) -> Result<JsValue> {
        let bill_payload: BitcreditBillPayload = serde_wasm_bindgen::from_value(payload)?;
        let timestamp = external::time::TimeApi::get_atomic_time().await.timestamp;
        let bill_id = self.issue_bill(bill_payload, timestamp, true).await?;
        let res = serde_wasm_bindgen::to_value(&BillIdResponse { id: bill_id })?;
        Ok(res)
    }

    async fn offer_to_sell_bill(
        &self,
        payload: OfferToSellBitcreditBillPayload,
        buyer: BillParticipant,
        timestamp: u64,
        sum: u64,
    ) -> Result<()> {
        let (signer_public_data, signer_keys) = get_signer_public_data_and_keys().await?;

        get_ctx()
            .bill_service
            .execute_bill_action(
                &payload.bill_id,
                BillAction::OfferToSell(buyer.clone(), sum, payload.currency.clone()),
                &signer_public_data,
                &signer_keys,
                timestamp,
            )
            .await?;

        Ok(())
    }

    #[wasm_bindgen]
    pub async fn offer_to_sell(
        &self,
        #[wasm_bindgen(unchecked_param_type = "OfferToSellBitcreditBillPayload")] payload: JsValue,
    ) -> Result<()> {
        let offer_to_sell_payload: OfferToSellBitcreditBillPayload =
            serde_wasm_bindgen::from_value(payload)?;
        let public_data_buyer = match get_ctx()
            .contact_service
            .get_identity_by_node_id(&offer_to_sell_payload.buyer)
            .await
        {
            Ok(Some(buyer)) => buyer,
            Ok(None) | Err(_) => {
                return Err(BillServiceError::BuyerNotInContacts.into());
            }
        };

        let sum = currency::parse_sum(&offer_to_sell_payload.sum)?;
        let timestamp = external::time::TimeApi::get_atomic_time().await.timestamp;
        self.offer_to_sell_bill(offer_to_sell_payload, public_data_buyer, timestamp, sum)
            .await
    }

    /// Blank offer to sell - the contact doesn't have to be an anonymous contact
    #[wasm_bindgen]
    pub async fn offer_to_sell_blank(
        &self,
        #[wasm_bindgen(unchecked_param_type = "OfferToSellBitcreditBillPayload")] payload: JsValue,
    ) -> Result<()> {
        let offer_to_sell_payload: OfferToSellBitcreditBillPayload =
            serde_wasm_bindgen::from_value(payload)?;
        let public_data_buyer: BillAnonParticipant = match get_ctx()
            .contact_service
            .get_identity_by_node_id(&offer_to_sell_payload.buyer)
            .await
        {
            Ok(Some(buyer)) => buyer.into(), // turn contact into anonymous participant
            Ok(None) | Err(_) => {
                return Err(BillServiceError::BuyerNotInContacts.into());
            }
        };

        let sum = currency::parse_sum(&offer_to_sell_payload.sum)?;
        let timestamp = external::time::TimeApi::get_atomic_time().await.timestamp;
        self.offer_to_sell_bill(
            offer_to_sell_payload,
            BillParticipant::Anon(public_data_buyer),
            timestamp,
            sum,
        )
        .await
    }

    async fn endorse(
        &self,
        payload: EndorseBitcreditBillPayload,
        endorsee: BillParticipant,
        timestamp: u64,
    ) -> Result<()> {
        let (signer_public_data, signer_keys) = get_signer_public_data_and_keys().await?;
        get_ctx()
            .bill_service
            .execute_bill_action(
                &payload.bill_id,
                BillAction::Endorse(endorsee),
                &signer_public_data,
                &signer_keys,
                timestamp,
            )
            .await?;
        Ok(())
    }

    #[wasm_bindgen]
    pub async fn endorse_bill(
        &self,
        #[wasm_bindgen(unchecked_param_type = "EndorseBitcreditBillPayload")] payload: JsValue,
    ) -> Result<()> {
        let endorse_bill_payload: EndorseBitcreditBillPayload =
            serde_wasm_bindgen::from_value(payload)?;
        let public_data_endorsee = match get_ctx()
            .contact_service
            .get_identity_by_node_id(&NodeId::from_str(&endorse_bill_payload.endorsee)?)
            .await
        {
            Ok(Some(endorsee)) => endorsee,
            Ok(None) | Err(_) => {
                return Err(BillServiceError::EndorseeNotInContacts.into());
            }
        };
        let timestamp = external::time::TimeApi::get_atomic_time().await.timestamp;
        self.endorse(endorse_bill_payload, public_data_endorsee, timestamp)
            .await
    }

    /// Blank endorsement - the contact doesn't have to be an anonymous contact
    #[wasm_bindgen]
    pub async fn endorse_bill_blank(
        &self,
        #[wasm_bindgen(unchecked_param_type = "EndorseBitcreditBillPayload")] payload: JsValue,
    ) -> Result<()> {
        let endorse_bill_payload: EndorseBitcreditBillPayload =
            serde_wasm_bindgen::from_value(payload)?;
        let public_data_endorsee_blank: BillAnonParticipant = match get_ctx()
            .contact_service
            .get_identity_by_node_id(&NodeId::from_str(&endorse_bill_payload.endorsee)?)
            .await
        {
            Ok(Some(endorsee)) => endorsee.into(), // turn contact into anonymous participant
            Ok(None) | Err(_) => {
                return Err(BillServiceError::EndorseeNotInContacts.into());
            }
        };
        let timestamp = external::time::TimeApi::get_atomic_time().await.timestamp;
        self.endorse(
            endorse_bill_payload,
            BillParticipant::Anon(public_data_endorsee_blank),
            timestamp,
        )
        .await
    }

    #[wasm_bindgen]
    pub async fn request_to_pay(
        &self,
        #[wasm_bindgen(unchecked_param_type = "RequestToPayBitcreditBillPayload")] payload: JsValue,
    ) -> Result<()> {
        let request_to_pay_bill_payload: RequestToPayBitcreditBillPayload =
            serde_wasm_bindgen::from_value(payload)?;

        let timestamp = external::time::TimeApi::get_atomic_time().await.timestamp;
        let (signer_public_data, signer_keys) = get_signer_public_data_and_keys().await?;

        get_ctx()
            .bill_service
            .execute_bill_action(
                &request_to_pay_bill_payload.bill_id,
                BillAction::RequestToPay(request_to_pay_bill_payload.currency.clone()),
                &signer_public_data,
                &signer_keys,
                timestamp,
            )
            .await?;

        Ok(())
    }

    #[wasm_bindgen]
    pub async fn request_to_accept(
        &self,
        #[wasm_bindgen(unchecked_param_type = "RequestToAcceptBitcreditBillPayload")]
        payload: JsValue,
    ) -> Result<()> {
        let request_to_accept_bill_payload: RequestToAcceptBitcreditBillPayload =
            serde_wasm_bindgen::from_value(payload)?;

        let timestamp = external::time::TimeApi::get_atomic_time().await.timestamp;
        let (signer_public_data, signer_keys) = get_signer_public_data_and_keys().await?;

        get_ctx()
            .bill_service
            .execute_bill_action(
                &request_to_accept_bill_payload.bill_id,
                BillAction::RequestAcceptance,
                &signer_public_data,
                &signer_keys,
                timestamp,
            )
            .await?;

        Ok(())
    }

    #[wasm_bindgen]
    pub async fn accept(
        &self,
        #[wasm_bindgen(unchecked_param_type = "AcceptBitcreditBillPayload")] payload: JsValue,
    ) -> Result<()> {
        let accept_bill_payload: AcceptBitcreditBillPayload =
            serde_wasm_bindgen::from_value(payload)?;

        let timestamp = external::time::TimeApi::get_atomic_time().await.timestamp;
        let (signer_public_data, signer_keys) = get_signer_public_data_and_keys().await?;

        get_ctx()
            .bill_service
            .execute_bill_action(
                &accept_bill_payload.bill_id,
                BillAction::Accept,
                &signer_public_data,
                &signer_keys,
                timestamp,
            )
            .await?;

        Ok(())
    }

    #[wasm_bindgen]
    pub async fn request_to_mint(
        &self,
        #[wasm_bindgen(unchecked_param_type = "RequestToMintBitcreditBillPayload")]
        payload: JsValue,
    ) -> Result<()> {
        let request_to_mint_bill_payload: RequestToMintBitcreditBillPayload =
            serde_wasm_bindgen::from_value(payload)?;
        let timestamp = external::time::TimeApi::get_atomic_time().await.timestamp;
        let (signer_public_data, signer_keys) = get_signer_public_data_and_keys().await?;
        get_ctx()
            .bill_service
            .request_to_mint(
                &request_to_mint_bill_payload.bill_id,
                &NodeId::from_str(&request_to_mint_bill_payload.mint_node)?,
                &signer_public_data,
                &signer_keys,
                timestamp,
            )
            .await?;

        Ok(())
    }

    #[wasm_bindgen(unchecked_return_type = "MintRequestStateResponse")]
    pub async fn mint_state(&self, id: &str) -> Result<JsValue> {
        let bill_id = BillId::from_str(id)?;
        let result = get_ctx()
            .bill_service
            .get_mint_state(&bill_id, &get_current_identity_node_id().await?)
            .await?;
        let res = serde_wasm_bindgen::to_value(&MintRequestStateResponse {
            request_states: result.into_iter().map(|e| e.into()).collect(),
        })?;
        Ok(res)
    }

    #[wasm_bindgen]
    pub async fn check_mint_state(&self, id: &str) -> Result<()> {
        let bill_id = BillId::from_str(id)?;
        get_ctx()
            .bill_service
            .check_mint_state(&bill_id, &get_current_identity_node_id().await?)
            .await?;
        Ok(())
    }

    #[wasm_bindgen]
    pub async fn cancel_request_to_mint(&self, mint_request_id: &str) -> Result<()> {
        get_ctx()
            .bill_service
            .cancel_request_to_mint(mint_request_id, &get_current_identity_node_id().await?)
            .await?;
        Ok(())
    }

    #[wasm_bindgen]
    pub async fn accept_mint_offer(&self, mint_request_id: &str) -> Result<()> {
        let timestamp = external::time::TimeApi::get_atomic_time().await.timestamp;
        let (signer_public_data, signer_keys) = get_signer_public_data_and_keys().await?;
        get_ctx()
            .bill_service
            .accept_mint_offer(
                mint_request_id,
                &signer_public_data,
                &signer_keys,
                timestamp,
            )
            .await?;
        Ok(())
    }

    #[wasm_bindgen]
    pub async fn reject_mint_offer(&self, mint_request_id: &str) -> Result<()> {
        get_ctx()
            .bill_service
            .reject_mint_offer(mint_request_id, &get_current_identity_node_id().await?)
            .await?;
        Ok(())
    }

    #[wasm_bindgen]
    pub async fn reject_to_accept(
        &self,
        #[wasm_bindgen(unchecked_param_type = "RejectActionBillPayload")] payload: JsValue,
    ) -> Result<()> {
        let reject_payload: RejectActionBillPayload = serde_wasm_bindgen::from_value(payload)?;

        let timestamp = external::time::TimeApi::get_atomic_time().await.timestamp;
        let (signer_public_data, signer_keys) = get_signer_public_data_and_keys().await?;

        get_ctx()
            .bill_service
            .execute_bill_action(
                &reject_payload.bill_id,
                BillAction::RejectAcceptance,
                &signer_public_data,
                &signer_keys,
                timestamp,
            )
            .await?;

        Ok(())
    }

    #[wasm_bindgen]
    pub async fn reject_to_pay(
        &self,
        #[wasm_bindgen(unchecked_param_type = "RejectActionBillPayload")] payload: JsValue,
    ) -> Result<()> {
        let reject_payload: RejectActionBillPayload = serde_wasm_bindgen::from_value(payload)?;

        let timestamp = external::time::TimeApi::get_atomic_time().await.timestamp;
        let (signer_public_data, signer_keys) = get_signer_public_data_and_keys().await?;

        get_ctx()
            .bill_service
            .execute_bill_action(
                &reject_payload.bill_id,
                BillAction::RejectPayment,
                &signer_public_data,
                &signer_keys,
                timestamp,
            )
            .await?;

        Ok(())
    }

    #[wasm_bindgen]
    pub async fn reject_to_buy(
        &self,
        #[wasm_bindgen(unchecked_param_type = "RejectActionBillPayload")] payload: JsValue,
    ) -> Result<()> {
        let reject_payload: RejectActionBillPayload = serde_wasm_bindgen::from_value(payload)?;

        let timestamp = external::time::TimeApi::get_atomic_time().await.timestamp;
        let (signer_public_data, signer_keys) = get_signer_public_data_and_keys().await?;

        get_ctx()
            .bill_service
            .execute_bill_action(
                &reject_payload.bill_id,
                BillAction::RejectBuying,
                &signer_public_data,
                &signer_keys,
                timestamp,
            )
            .await?;

        Ok(())
    }

    #[wasm_bindgen]
    pub async fn reject_to_pay_recourse(
        &self,
        #[wasm_bindgen(unchecked_param_type = "RejectActionBillPayload")] payload: JsValue,
    ) -> Result<()> {
        let reject_payload: RejectActionBillPayload = serde_wasm_bindgen::from_value(payload)?;

        let timestamp = external::time::TimeApi::get_atomic_time().await.timestamp;
        let (signer_public_data, signer_keys) = get_signer_public_data_and_keys().await?;

        get_ctx()
            .bill_service
            .execute_bill_action(
                &reject_payload.bill_id,
                BillAction::RejectPaymentForRecourse,
                &signer_public_data,
                &signer_keys,
                timestamp,
            )
            .await?;

        Ok(())
    }

    #[wasm_bindgen]
    pub async fn request_to_recourse_bill_payment(
        &self,
        #[wasm_bindgen(unchecked_param_type = "RequestRecourseForPaymentPayload")] payload: JsValue,
    ) -> Result<()> {
        let request_recourse_payload: RequestRecourseForPaymentPayload =
            serde_wasm_bindgen::from_value(payload)?;
        let sum = currency::parse_sum(&request_recourse_payload.sum)?;
        request_recourse(
            RecourseReason::Pay(sum, request_recourse_payload.currency.clone()),
            &request_recourse_payload.bill_id,
            &request_recourse_payload.recoursee,
        )
        .await
    }

    #[wasm_bindgen]
    pub async fn request_to_recourse_bill_acceptance(
        &self,
        #[wasm_bindgen(unchecked_param_type = "RequestRecourseForPaymentPayload")] payload: JsValue,
    ) -> Result<()> {
        let request_recourse_payload: RequestRecourseForAcceptancePayload =
            serde_wasm_bindgen::from_value(payload)?;

        request_recourse(
            RecourseReason::Accept,
            &request_recourse_payload.bill_id,
            &request_recourse_payload.recoursee,
        )
        .await
    }

    #[wasm_bindgen]
    pub async fn clear_bill_cache(&self) -> Result<()> {
        get_ctx().bill_service.clear_bill_cache().await?;
        Ok(())
    }
}

async fn request_recourse(
    recourse_reason: RecourseReason,
    bill_id: &BillId,
    recoursee_node_id: &NodeId,
) -> Result<()> {
    let timestamp = external::time::TimeApi::get_atomic_time().await.timestamp;
    let (signer_public_data, signer_keys) = get_signer_public_data_and_keys().await?;

    let public_data_recoursee = match get_ctx()
        .contact_service
        .get_identity_by_node_id(recoursee_node_id)
        .await
    {
        Ok(Some(BillParticipant::Ident(recoursee))) => recoursee,
        Ok(Some(BillParticipant::Anon(_))) => {
            // recoursee has to be identified
            return Err(
                BillServiceError::Validation(ValidationError::ContactIsAnonymous(
                    recoursee_node_id.to_string(),
                ))
                .into(),
            );
        }
        Ok(None) | Err(_) => {
            return Err(BillServiceError::RecourseeNotInContacts.into());
        }
    };

    get_ctx()
        .bill_service
        .execute_bill_action(
            bill_id,
            BillAction::RequestRecourse(public_data_recoursee, recourse_reason),
            &signer_public_data,
            &signer_keys,
            timestamp,
        )
        .await?;

    Ok(())
}

impl Default for Bill {
    fn default() -> Self {
        Bill
    }
}

pub(super) async fn get_signer_public_data_and_keys() -> Result<(BillParticipant, BcrKeys)> {
    let current_identity = get_current_identity().await?;
    let local_node_id = current_identity.personal;
    let (signer_public_data, signer_keys) = match current_identity.company {
        None => {
            let identity = get_ctx().identity_service.get_full_identity().await?;
            match identity.identity.t {
                IdentityType::Ident => {
                    match BillIdentParticipant::new(identity.identity) {
                        Ok(identity_public_data) => (
                            BillParticipant::Ident(identity_public_data),
                            identity.key_pair,
                        ),
                        Err(_) => {
                            // only non-anon bill issuers with a postal address can sign a bill
                            return Err(
                                Error::Validation(ValidationError::DrawerIsNotBillIssuer).into()
                            );
                        }
                    }
                }
                IdentityType::Anon => (
                    BillParticipant::Anon(BillAnonParticipant::new(identity.identity)),
                    identity.key_pair,
                ),
            }
        }
        Some(company_node_id) => {
            let (company, keys) = get_ctx()
                .company_service
                .get_company_and_keys_by_id(&company_node_id)
                .await?;
            if !company.signatories.contains(&local_node_id) {
                return Err(Error::Validation(ValidationError::NotASignatory(
                    local_node_id.to_string(),
                ))
                .into());
            }
            (
                BillParticipant::Ident(BillIdentParticipant::from(company)),
                BcrKeys::from_private_key(&keys.private_key).map_err(Error::CryptoUtil)?,
            )
        }
    };
    Ok((signer_public_data, signer_keys))
}
