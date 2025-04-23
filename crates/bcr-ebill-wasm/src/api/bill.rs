use super::Result;
use bcr_ebill_api::{
    data::{
        bill::{
            BillAction, BillIssueData, BillsFilterRole, LightBitcreditBillResult, RecourseReason,
        },
        contact::{BillAnonParticipant, BillIdentParticipant, BillParticipant},
        identity::IdentityType,
    },
    external,
    service::{Error, bill_service::error::Error as BillServiceError},
    util::{
        self, BcrKeys, ValidationError, currency,
        file::{UploadFileHandler, detect_content_type_for_bytes},
    },
};
use log::{error, info};
use wasm_bindgen::prelude::*;

use crate::{
    api::identity::get_current_identity_node_id,
    context::get_ctx,
    data::{
        BinaryFileResponse, FromWeb, IntoWeb, UploadFile,
        bill::{
            AcceptBitcreditBillPayload, BillId, BillNumbersToWordsForSum, BillsResponse,
            BillsSearchFilterPayload, BitcreditBillPayload, EndorseBitcreditBillPayload,
            EndorsementsResponse, LightBillsResponse, MintBitcreditBillPayload,
            OfferToSellBitcreditBillPayload, PastEndorseesResponse, PastPaymentsResponse,
            RejectActionBillPayload, RequestRecourseForAcceptancePayload,
            RequestRecourseForPaymentPayload, RequestToAcceptBitcreditBillPayload,
            RequestToMintBitcreditBillPayload, RequestToPayBitcreditBillPayload,
        },
    },
};

use super::identity::get_current_identity;

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
        let result = get_ctx()
            .bill_service
            .get_endorsements(id, &get_current_identity_node_id().await?)
            .await?;
        let res = serde_wasm_bindgen::to_value(&EndorsementsResponse {
            endorsements: result.into_iter().map(|e| e.into_web()).collect(),
        })?;
        Ok(res)
    }

    #[wasm_bindgen(unchecked_return_type = "PastPaymentsResponse")]
    pub async fn past_payments(&self, id: &str) -> Result<JsValue> {
        let (caller_public_data, caller_keys) = get_signer_public_data_and_keys().await?;
        let result = get_ctx()
            .bill_service
            .get_past_payments(
                id,
                &caller_public_data,
                &caller_keys,
                util::date::now().timestamp() as u64,
            )
            .await?;
        let res = serde_wasm_bindgen::to_value(&PastPaymentsResponse {
            past_payments: result.into_iter().map(|e| e.into_web()).collect(),
        })?;
        Ok(res)
    }

    #[wasm_bindgen(unchecked_return_type = "PastEndorseesResponse")]
    pub async fn past_endorsees(&self, id: &str) -> Result<JsValue> {
        let result = get_ctx()
            .bill_service
            .get_past_endorsees(id, &get_current_identity_node_id().await?)
            .await?;
        let res = serde_wasm_bindgen::to_value(&PastEndorseesResponse {
            past_endorsees: result.into_iter().map(|e| e.into_web()).collect(),
        })?;
        Ok(res)
    }

    #[wasm_bindgen(unchecked_return_type = "BillCombinedBitcoinKeyWeb")]
    pub async fn bitcoin_key(&self, id: &str) -> Result<JsValue> {
        let (caller_public_data, caller_keys) = get_signer_public_data_and_keys().await?;
        let combined_key = get_ctx()
            .bill_service
            .get_combined_bitcoin_key_for_bill(id, &caller_public_data, &caller_keys)
            .await?;
        let res = serde_wasm_bindgen::to_value(&combined_key.into_web())?;
        Ok(res)
    }

    #[wasm_bindgen(unchecked_return_type = "BinaryFileResponse")]
    pub async fn attachment(&self, bill_id: &str, file_name: &str) -> Result<JsValue> {
        let keys = get_ctx().bill_service.get_bill_keys(bill_id).await?;
        let file_bytes = get_ctx()
            .bill_service
            .open_and_decrypt_attached_file(bill_id, file_name, &keys.private_key)
            .await?;

        let content_type = detect_content_type_for_bytes(&file_bytes)
            .ok_or(Error::Validation(ValidationError::InvalidContentType))?;

        let res = serde_wasm_bindgen::to_value(&BinaryFileResponse {
            data: file_bytes,
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

        let res = serde_wasm_bindgen::to_value(&file_upload_response.into_web())?;
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
                &BillsFilterRole::from_web(filter.role),
                &get_current_identity_node_id().await?,
            )
            .await?;

        let res = serde_wasm_bindgen::to_value(&LightBillsResponse {
            bills: bills.into_iter().map(|b| b.into_web()).collect(),
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
            bills: bills.into_iter().map(|b| b.into_web()).collect(),
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
            bills: bills.into_iter().map(|b| b.into_web()).collect(),
        })?;
        Ok(res)
    }

    #[wasm_bindgen(unchecked_return_type = "BillNumbersToWordsForSum")]
    pub async fn numbers_to_words_for_sum(&self, id: &str) -> Result<JsValue> {
        let current_timestamp = util::date::now().timestamp() as u64;
        let identity = get_ctx().identity_service.get_identity().await?;
        let bill = get_ctx()
            .bill_service
            .get_detail(
                id,
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
        let current_timestamp = util::date::now().timestamp() as u64;
        let identity = get_ctx().identity_service.get_identity().await?;
        let bill_detail = get_ctx()
            .bill_service
            .get_detail(
                id,
                &identity,
                &get_current_identity_node_id().await?,
                current_timestamp,
            )
            .await?;

        let res = serde_wasm_bindgen::to_value(&bill_detail.into_web())?;
        Ok(res)
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
        Ok(())
    }

    #[wasm_bindgen(unchecked_return_type = "BillId")]
    pub async fn issue(
        &self,
        #[wasm_bindgen(unchecked_param_type = "BitcreditBillPayload")] payload: JsValue,
    ) -> Result<JsValue> {
        let bill_payload: BitcreditBillPayload = serde_wasm_bindgen::from_value(payload)?;
        let (drawer_public_data, drawer_keys) = get_signer_public_data_and_keys().await?;
        let timestamp = external::time::TimeApi::get_atomic_time().await.timestamp;

        let bill = get_ctx()
            .bill_service
            .issue_new_bill(BillIssueData {
                t: bill_payload.t,
                country_of_issuing: bill_payload.country_of_issuing.to_owned(),
                city_of_issuing: bill_payload.city_of_issuing.to_owned(),
                issue_date: bill_payload.issue_date.to_owned(),
                maturity_date: bill_payload.maturity_date.to_owned(),
                drawee: bill_payload.drawee.to_owned(),
                payee: bill_payload.payee.to_owned(),
                sum: bill_payload.sum.to_owned(),
                currency: bill_payload.currency.to_owned(),
                country_of_payment: bill_payload.country_of_payment.to_owned(),
                city_of_payment: bill_payload.city_of_payment.to_owned(),
                language: bill_payload.language.to_owned(),
                file_upload_ids: bill_payload.file_upload_ids.to_owned(),
                drawer_public_data: drawer_public_data.clone(),
                drawer_keys: drawer_keys.clone(),
                timestamp,
            })
            .await?;

        let res = serde_wasm_bindgen::to_value(&BillId {
            id: bill.id.clone(),
        })?;
        Ok(res)
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
        let (signer_public_data, signer_keys) = get_signer_public_data_and_keys().await?;

        get_ctx()
            .bill_service
            .execute_bill_action(
                &offer_to_sell_payload.bill_id,
                BillAction::OfferToSell(
                    public_data_buyer.clone(),
                    sum,
                    offer_to_sell_payload.currency.clone(),
                ),
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
            .get_identity_by_node_id(&endorse_bill_payload.endorsee)
            .await
        {
            Ok(Some(endorsee)) => endorsee,
            Ok(None) | Err(_) => {
                return Err(BillServiceError::EndorseeNotInContacts.into());
            }
        };

        let timestamp = external::time::TimeApi::get_atomic_time().await.timestamp;
        let (signer_public_data, signer_keys) = get_signer_public_data_and_keys().await?;
        get_ctx()
            .bill_service
            .execute_bill_action(
                &endorse_bill_payload.bill_id,
                BillAction::Endorse(public_data_endorsee.clone()),
                &signer_public_data,
                &signer_keys,
                timestamp,
            )
            .await?;
        Ok(())
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
        info!(
            "request to mint bill called with payload {} {} - not implemented",
            request_to_mint_bill_payload.mint_node, request_to_mint_bill_payload.bill_id
        );

        Ok(())
    }

    #[wasm_bindgen]
    pub async fn mint_bill(
        &self,
        #[wasm_bindgen(unchecked_param_type = "MintBitcreditBillPayload")] payload: JsValue,
    ) -> Result<()> {
        let mint_bill_payload: MintBitcreditBillPayload = serde_wasm_bindgen::from_value(payload)?;
        info!("mint bill called with payload {mint_bill_payload:?} - not implemented");

        let timestamp = external::time::TimeApi::get_atomic_time().await.timestamp;
        let sum = currency::parse_sum(&mint_bill_payload.sum)?;

        let public_mint_node = match get_ctx()
            .contact_service
            .get_identity_by_node_id(&mint_bill_payload.mint_node)
            .await
        {
            Ok(Some(drawee)) => drawee,
            Ok(None) | Err(_) => {
                return Err(BillServiceError::MintNotInContacts.into());
            }
        };
        let (signer_public_data, signer_keys) = get_signer_public_data_and_keys().await?;

        get_ctx()
            .bill_service
            .execute_bill_action(
                &mint_bill_payload.bill_id,
                BillAction::Mint(public_mint_node, sum, mint_bill_payload.currency.clone()),
                &signer_public_data,
                &signer_keys,
                timestamp,
            )
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
    bill_id: &str,
    recoursee_node_id: &str,
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
                    recoursee_node_id.to_owned(),
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

async fn get_signer_public_data_and_keys() -> Result<(BillParticipant, BcrKeys)> {
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
                    local_node_id.to_owned(),
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
