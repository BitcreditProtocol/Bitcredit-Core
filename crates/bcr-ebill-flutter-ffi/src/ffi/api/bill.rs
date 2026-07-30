use base64::{Engine as _, engine::general_purpose::STANDARD};
use bcr_common::core::{BillId, NodeId};
use bcr_ebill_core::{
    application::{
        ValidationError,
        bill::{BillsFilterRole, LightBitcreditBillResult},
    },
    protocol::{
        BitcoinAddress, City, Country, Currency, Date, Name, ProtocolValidationError, Sum,
        Timestamp,
        blockchain::{
            bill::{
                BillAction, BillIssueData, RecourseReason,
                participant::{BillAnonParticipant, BillIdentParticipant, BillParticipant},
            },
            identity::IdentityType,
        },
        crypto::BcrKeys,
    },
};
use flutter_rust_bridge::frb;
use log::error;
use std::str::FromStr;
use uuid::Uuid;

use bcr_ebill_api::service::{
    Error,
    bill_service::Error as BillServiceError,
    file_upload_service::{UploadFileHandler, detect_content_type_for_bytes},
};

use crate::ffi::{
    api::identity::{get_current_identity, get_current_identity_node_id},
    context::get_ctx,
    data::{
        Base64FileResponse, BinaryFileResponse, UploadFile, UploadFileResponse,
        bill::{
            AcceptBitcreditBillPayload, BillCheckSweepBTCFundsPayload, BillCombinedBitcoinKeyFfi,
            BillHistoryResponse, BillIdResponse, BillSweepBTCEstimateFfi, BillSweepBTCFundsPayload,
            BillSweepBTCFundsResultFfi, BillsResponse, BillsSearchFilterPayload, BitcreditBillFfi,
            BitcreditBillPayload, EndorseBitcreditBillPayload, EndorsementsResponse,
            LightBillsResponse, OfferToSellBitcreditBillPayload, PastEndorseesResponse,
            PastPaymentsResponse, RejectActionBillPayload, RequestRecourseForAcceptancePayload,
            RequestRecourseForPaymentPayload, RequestToAcceptBitcreditBillPayload,
            RequestToMintBitcreditBillPayload, RequestToPayAsMintBitcreditBillPayload,
            RequestToPayBitcreditBillPayload, ResyncBillPayload, ShareBillWithCourtPayload,
        },
        mint::MintRequestStateResponse,
        parse_deadline_string,
    },
    error::EbillFfiError,
};

async fn get_attachment(
    bill_id: &str,
    file_name: &Name,
) -> Result<(Vec<u8>, String), EbillFfiError> {
    let parsed_bill_id = BillId::from_str(bill_id).map_err(ProtocolValidationError::from)?;
    let current_timestamp = Timestamp::now();
    let identity = get_ctx().await.identity_service.get_identity().await?;
    let (caller_public_data, caller_keys) = get_signer_public_data_and_keys().await?;
    // get bill
    let bill = get_ctx()
        .await
        .bill_service
        .get_detail(
            &parsed_bill_id,
            &identity,
            &caller_public_data,
            &caller_keys,
            current_timestamp,
        )
        .await?;

    // check if this file even exists on the bill
    let file = match bill.data.files.iter().find(|f| &f.name == file_name) {
        Some(f) => f,
        None => {
            return Err(bcr_ebill_api::service::bill_service::Error::NotFound.into());
        }
    };

    // fetch the attachment
    let keys = get_ctx()
        .await
        .bill_service
        .get_bill_keys(&parsed_bill_id)
        .await?;
    let file_bytes = get_ctx()
        .await
        .bill_service
        .open_and_decrypt_attached_file(&parsed_bill_id, file, &keys.get_private_key())
        .await?;

    let content_type = detect_content_type_for_bytes(&file_bytes).ok_or(Error::Validation(
        ProtocolValidationError::InvalidContentType.into(),
    ))?;
    Ok((file_bytes, content_type))
}

#[frb]
pub async fn endorsements(id: &str) -> Result<EndorsementsResponse, EbillFfiError> {
    let bill_id = BillId::from_str(id).map_err(ProtocolValidationError::from)?;
    let current_timestamp = Timestamp::now();
    let identity = get_ctx().await.identity_service.get_identity().await?;
    let (caller_public_data, caller_keys) = get_signer_public_data_and_keys().await?;
    let result = get_ctx()
        .await
        .bill_service
        .get_endorsements(
            &bill_id,
            &identity,
            &caller_public_data,
            &caller_keys,
            current_timestamp,
        )
        .await?;
    Ok(EndorsementsResponse {
        endorsements: result.into_iter().map(|e| e.into()).collect(),
    })
}

#[frb]
pub async fn past_payments(id: &str) -> Result<PastPaymentsResponse, EbillFfiError> {
    let bill_id = BillId::from_str(id).map_err(ProtocolValidationError::from)?;
    let (caller_public_data, caller_keys) = get_signer_public_data_and_keys().await?;
    let result = get_ctx()
        .await
        .bill_service
        .get_past_payments(
            &bill_id,
            &caller_public_data,
            &caller_keys,
            Timestamp::now(),
        )
        .await?;
    Ok(PastPaymentsResponse {
        past_payments: result.into_iter().map(|e| e.into()).collect(),
    })
}

#[frb]
pub async fn past_endorsees(id: &str) -> Result<PastEndorseesResponse, EbillFfiError> {
    let bill_id = BillId::from_str(id).map_err(ProtocolValidationError::from)?;
    let result = get_ctx()
        .await
        .bill_service
        .get_past_endorsees(&bill_id, &get_current_identity_node_id().await?)
        .await?;
    Ok(PastEndorseesResponse {
        past_endorsees: result.into_iter().map(|e| e.into()).collect(),
    })
}

#[frb]
pub async fn bitcoin_keys(id: &str) -> Result<Vec<BillCombinedBitcoinKeyFfi>, EbillFfiError> {
    let bill_id = BillId::from_str(id).map_err(ProtocolValidationError::from)?;
    let (caller_public_data, caller_keys) = get_signer_public_data_and_keys().await?;
    let combined_keys = get_ctx()
        .await
        .bill_service
        .get_combined_bitcoin_keys_for_bill(&bill_id, &caller_public_data, &caller_keys)
        .await?;
    Ok(combined_keys.into_iter().map(|ck| ck.into()).collect())
}

#[frb]
pub async fn attachment(
    bill_id: &str,
    file_name: &str,
) -> Result<BinaryFileResponse, EbillFfiError> {
    let name = Name::new(file_name)?;
    let (file_bytes, content_type) = get_attachment(bill_id, &name).await?;
    Ok(BinaryFileResponse {
        data: file_bytes,
        name: name.to_string(),
        content_type,
    })
}

#[frb]
pub async fn attachment_base64(
    bill_id: &str,
    file_name: &str,
) -> Result<Base64FileResponse, EbillFfiError> {
    let name = Name::new(file_name)?;
    let (file_bytes, content_type) = get_attachment(bill_id, &name).await?;
    Ok(Base64FileResponse {
        data: STANDARD.encode(&file_bytes),
        name: name.to_string(),
        content_type,
    })
}

#[frb]
pub async fn upload(upload_file: UploadFile) -> Result<UploadFileResponse, EbillFfiError> {
    let upload_file_handler: &dyn UploadFileHandler = &upload_file as &dyn UploadFileHandler;

    get_ctx()
        .await
        .file_upload_service
        .validate_attached_file(upload_file_handler)
        .await?;

    let file_upload_response = get_ctx()
        .await
        .file_upload_service
        .upload_file(upload_file_handler)
        .await?;

    Ok(file_upload_response.into())
}

#[frb]
pub async fn search(
    filter_payload: BillsSearchFilterPayload,
) -> Result<LightBillsResponse, EbillFfiError> {
    let filter = filter_payload.filter;

    let (from, to) = match filter.date_range {
        None => (None, None),
        Some(date_range) => {
            let from = Date::new(&date_range.from)?.to_timestamp();
            // Change the date to the end of the day, so we collect bills during the day as well
            let to = Date::new(&date_range.to)
                .map(|d| d.to_timestamp())
                .map(|ts| ts.end_of_day())?;
            (Some(from), Some(to))
        }
    };
    let (caller_public_data, caller_keys) = get_signer_public_data_and_keys().await?;
    let parts: Vec<NodeId> = filter
        .participants
        .into_iter()
        .map(|n| NodeId::from_str(&n))
        .collect::<Result<_, _>>()
        .map_err(ProtocolValidationError::from)?;
    let bills = get_ctx()
        .await
        .bill_service
        .search_bills(
            &Currency::sat(),
            &filter.search_term,
            from,
            to,
            &BillsFilterRole::from(filter.role),
            &parts,
            &caller_public_data,
            &caller_keys,
        )
        .await?;

    Ok(LightBillsResponse {
        bills: bills.into_iter().map(|b| b.into()).collect(),
    })
}

#[frb]
pub async fn list_light() -> Result<LightBillsResponse, EbillFfiError> {
    let (caller_public_data, caller_keys) = get_signer_public_data_and_keys().await?;
    let bills: Vec<LightBitcreditBillResult> = get_ctx()
        .await
        .bill_service
        .get_bills(&caller_public_data, &caller_keys)
        .await?
        .into_iter()
        .map(|b| b.into())
        .collect();
    Ok(LightBillsResponse {
        bills: bills.into_iter().map(|b| b.into()).collect(),
    })
}

#[frb]
pub async fn list() -> Result<BillsResponse, EbillFfiError> {
    let (caller_public_data, caller_keys) = get_signer_public_data_and_keys().await?;
    let bills = get_ctx()
        .await
        .bill_service
        .get_bills(&caller_public_data, &caller_keys)
        .await?;
    Ok(BillsResponse {
        bills: bills.into_iter().map(|b| b.into()).collect(),
    })
}

#[frb]
pub async fn detail(id: &str) -> Result<BitcreditBillFfi, EbillFfiError> {
    let bill_id = BillId::from_str(id).map_err(ProtocolValidationError::from)?;
    let current_timestamp = Timestamp::now();
    let identity = get_ctx().await.identity_service.get_identity().await?;

    let (caller_public_data, caller_keys) = get_signer_public_data_and_keys().await?;
    let bill_detail = get_ctx()
        .await
        .bill_service
        .get_detail(
            &bill_id,
            &identity,
            &caller_public_data,
            &caller_keys,
            current_timestamp,
        )
        .await?;

    Ok(bill_detail.into())
}

#[frb]
pub async fn check_payment_for_bill(id: &str) -> Result<(), EbillFfiError> {
    let bill_id = BillId::from_str(id).map_err(ProtocolValidationError::from)?;
    let identity = get_ctx().await.identity_service.get_full_identity().await?;
    if let Err(e) = get_ctx()
        .await
        .bill_service
        .check_payment_for_bill(&bill_id, &identity.identity)
        .await
    {
        error!("Error while checking bill payment for {id}: {e}");
    }

    if let Err(e) = get_ctx()
        .await
        .bill_service
        .check_offer_to_sell_payment_for_bill(&bill_id, &identity)
        .await
    {
        error!("Error while checking bill offer to sell payment for {id}: {e}");
    }

    if let Err(e) = get_ctx()
        .await
        .bill_service
        .check_recourse_payment_for_bill(&bill_id, &identity)
        .await
    {
        error!("Error while checking bill recourse payment for {id}: {e}");
    }
    Ok(())
}

#[frb]
pub async fn check_payment() -> Result<(), EbillFfiError> {
    if let Err(e) = get_ctx().await.bill_service.check_bills_payment().await {
        error!("Error while checking bills payment: {e}");
    }

    if let Err(e) = get_ctx()
        .await
        .bill_service
        .check_bills_offer_to_sell_payment()
        .await
    {
        error!("Error while checking bills offer to sell payment: {e}");
    }

    if let Err(e) = get_ctx()
        .await
        .bill_service
        .check_bills_in_recourse_payment()
        .await
    {
        error!("Error while checking bills recourse payment: {e}");
    }
    Ok(())
}

#[frb]
pub async fn issue(bill_payload: BitcreditBillPayload) -> Result<BillIdResponse, EbillFfiError> {
    let timestamp = Timestamp::now();
    let bill_id = issue_bill(bill_payload, timestamp, false).await?;
    Ok(BillIdResponse {
        id: bill_id.to_string(),
    })
}

#[frb]
pub async fn issue_blank(
    bill_payload: BitcreditBillPayload,
) -> Result<BillIdResponse, EbillFfiError> {
    let timestamp = Timestamp::now();
    let bill_id = issue_bill(bill_payload, timestamp, true).await?;
    Ok(BillIdResponse {
        id: bill_id.to_string(),
    })
}

async fn issue_bill(
    bill_payload: BitcreditBillPayload,
    timestamp: Timestamp,
    blank_issue: bool,
) -> Result<BillId, EbillFfiError> {
    let (drawer_public_data, drawer_keys) = get_signer_public_data_and_keys().await?;

    let mut parsed_file_upload_ids: Vec<Uuid> =
        Vec::with_capacity(bill_payload.file_upload_ids.len());

    for file_upload_id in bill_payload.file_upload_ids.iter() {
        parsed_file_upload_ids.push(
            Uuid::from_str(file_upload_id)
                .map_err(|_| ProtocolValidationError::InvalidFileUploadId)?,
        );
    }

    let bill = get_ctx()
        .await
        .bill_service
        .issue_new_bill(BillIssueData {
            t: bill_payload.t,
            country_of_issuing: Country::parse(&bill_payload.country_of_issuing)?,
            city_of_issuing: City::new(bill_payload.city_of_issuing)?,
            issue_date: Date::new(bill_payload.issue_date)?,
            maturity_date: Date::new(bill_payload.maturity_date)?,
            drawee: NodeId::from_str(&bill_payload.drawee)
                .map_err(ProtocolValidationError::from)?,
            payee: NodeId::from_str(&bill_payload.payee).map_err(ProtocolValidationError::from)?,
            sum: Sum::new_sat_from_str(&bill_payload.sum)?,
            country_of_payment: Country::parse(&bill_payload.country_of_payment)?,
            city_of_payment: City::new(bill_payload.city_of_payment)?,
            file_upload_ids: parsed_file_upload_ids,
            drawer_public_data: drawer_public_data.clone(),
            drawer_keys: drawer_keys.clone(),
            timestamp,
            blank_issue,
        })
        .await?;

    Ok(bill.id)
}

async fn offer_to_sell_bill(
    payload: OfferToSellBitcreditBillPayload,
    buyer: BillParticipant,
    timestamp: Timestamp,
    sum: Sum,
    buying_deadline_timestamp: Timestamp,
) -> Result<(), EbillFfiError> {
    let (signer_public_data, signer_keys) = get_signer_public_data_and_keys().await?;

    get_ctx()
        .await
        .bill_service
        .execute_bill_action(
            &BillId::from_str(&payload.bill_id).map_err(ProtocolValidationError::from)?,
            BillAction::OfferToSell(buyer.clone(), sum, buying_deadline_timestamp),
            &signer_public_data,
            &signer_keys,
            timestamp,
        )
        .await?;

    Ok(())
}

#[frb]
pub async fn offer_to_sell(
    offer_to_sell_payload: OfferToSellBitcreditBillPayload,
) -> Result<(), EbillFfiError> {
    let public_data_buyer = match get_ctx()
        .await
        .contact_service
        .get_identity_by_node_id(
            &NodeId::from_str(&offer_to_sell_payload.buyer)
                .map_err(ProtocolValidationError::from)?,
        )
        .await
    {
        Ok(Some(buyer)) => buyer,
        Ok(None) | Err(_) => {
            return Err(BillServiceError::Validation(ValidationError::BuyerNotInContacts).into());
        }
    };

    let sum = Sum::new_sat_from_str(&offer_to_sell_payload.sum)?;
    let timestamp = Timestamp::now();
    let deadline_ts = Date::new(&offer_to_sell_payload.buying_deadline)?.to_timestamp();
    offer_to_sell_bill(
        offer_to_sell_payload,
        public_data_buyer,
        timestamp,
        sum,
        deadline_ts,
    )
    .await
}

#[frb]
pub async fn offer_to_sell_blank(
    offer_to_sell_payload: OfferToSellBitcreditBillPayload,
) -> Result<(), EbillFfiError> {
    let public_data_buyer: BillAnonParticipant = match get_ctx()
        .await
        .contact_service
        .get_identity_by_node_id(
            &NodeId::from_str(&offer_to_sell_payload.buyer)
                .map_err(ProtocolValidationError::from)?,
        )
        .await
    {
        Ok(Some(buyer)) => buyer.into(), // turn contact into anonymous participant
        Ok(None) | Err(_) => {
            return Err(BillServiceError::Validation(ValidationError::BuyerNotInContacts).into());
        }
    };

    let sum = Sum::new_sat_from_str(&offer_to_sell_payload.sum)?;
    let timestamp = Timestamp::now();
    let deadline_ts = parse_deadline_string(&offer_to_sell_payload.buying_deadline)?;
    offer_to_sell_bill(
        offer_to_sell_payload,
        BillParticipant::Anon(public_data_buyer),
        timestamp,
        sum,
        deadline_ts,
    )
    .await
}

async fn endorse(
    payload: EndorseBitcreditBillPayload,
    endorsee: BillParticipant,
    timestamp: Timestamp,
) -> Result<(), EbillFfiError> {
    let (signer_public_data, signer_keys) = get_signer_public_data_and_keys().await?;
    get_ctx()
        .await
        .bill_service
        .execute_bill_action(
            &BillId::from_str(&payload.bill_id).map_err(ProtocolValidationError::from)?,
            BillAction::Endorse(endorsee),
            &signer_public_data,
            &signer_keys,
            timestamp,
        )
        .await?;
    Ok(())
}

#[frb]
pub async fn endorse_bill(
    endorse_bill_payload: EndorseBitcreditBillPayload,
) -> Result<(), EbillFfiError> {
    let public_data_endorsee = match get_ctx()
        .await
        .contact_service
        .get_identity_by_node_id(
            &NodeId::from_str(&endorse_bill_payload.endorsee)
                .map_err(ProtocolValidationError::from)?,
        )
        .await
    {
        Ok(Some(endorsee)) => endorsee,
        Ok(None) | Err(_) => {
            return Err(
                BillServiceError::Validation(ValidationError::EndorseeNotInContacts).into(),
            );
        }
    };
    let timestamp = Timestamp::now();
    endorse(endorse_bill_payload, public_data_endorsee, timestamp).await
}

#[frb]
pub async fn endorse_bill_blank(
    endorse_bill_payload: EndorseBitcreditBillPayload,
) -> Result<(), EbillFfiError> {
    let public_data_endorsee_blank: BillAnonParticipant = match get_ctx()
        .await
        .contact_service
        .get_identity_by_node_id(
            &NodeId::from_str(&endorse_bill_payload.endorsee)
                .map_err(ProtocolValidationError::from)?,
        )
        .await
    {
        Ok(Some(endorsee)) => endorsee.into(), // turn contact into anonymous participant
        Ok(None) | Err(_) => {
            return Err(
                BillServiceError::Validation(ValidationError::EndorseeNotInContacts).into(),
            );
        }
    };
    let timestamp = Timestamp::now();
    endorse(
        endorse_bill_payload,
        BillParticipant::Anon(public_data_endorsee_blank),
        timestamp,
    )
    .await
}

#[frb]
pub async fn request_to_pay(
    request_to_pay_bill_payload: RequestToPayBitcreditBillPayload,
) -> Result<(), EbillFfiError> {
    let timestamp = Timestamp::now();
    let (signer_public_data, signer_keys) = get_signer_public_data_and_keys().await?;

    get_ctx()
        .await
        .bill_service
        .execute_bill_action(
            &BillId::from_str(&request_to_pay_bill_payload.bill_id)
                .map_err(ProtocolValidationError::from)?,
            BillAction::RequestToPay(
                Currency::sat(), // TODO (currency): parse and use given currency
                parse_deadline_string(&request_to_pay_bill_payload.payment_deadline)?,
                None,
            ),
            &signer_public_data,
            &signer_keys,
            timestamp,
        )
        .await?;

    Ok(())
}

#[frb]
pub async fn request_to_pay_as_mint(
    request_to_pay_bill_payload: RequestToPayAsMintBitcreditBillPayload,
) -> Result<(), EbillFfiError> {
    let timestamp = Timestamp::now();
    let (signer_public_data, signer_keys) = get_signer_public_data_and_keys().await?;

    get_ctx()
        .await
        .bill_service
        .execute_bill_action(
            &BillId::from_str(&request_to_pay_bill_payload.bill_id)
                .map_err(ProtocolValidationError::from)?,
            BillAction::RequestToPay(
                Currency::sat(), // TODO (currency): parse and use given currency
                parse_deadline_string(&request_to_pay_bill_payload.payment_deadline)?,
                Some(
                    BitcoinAddress::from_str(&request_to_pay_bill_payload.payment_address)
                        .map_err(|_| ProtocolValidationError::InvalidBitcoinAddress)?,
                ),
            ),
            &signer_public_data,
            &signer_keys,
            timestamp,
        )
        .await?;

    Ok(())
}

#[frb]
pub async fn request_to_accept(
    request_to_accept_bill_payload: RequestToAcceptBitcreditBillPayload,
) -> Result<(), EbillFfiError> {
    let timestamp = Timestamp::now();
    let (signer_public_data, signer_keys) = get_signer_public_data_and_keys().await?;

    get_ctx()
        .await
        .bill_service
        .execute_bill_action(
            &BillId::from_str(&request_to_accept_bill_payload.bill_id)
                .map_err(ProtocolValidationError::from)?,
            BillAction::RequestAcceptance(parse_deadline_string(
                &request_to_accept_bill_payload.acceptance_deadline,
            )?),
            &signer_public_data,
            &signer_keys,
            timestamp,
        )
        .await?;

    Ok(())
}

#[frb]
pub async fn accept(accept_bill_payload: AcceptBitcreditBillPayload) -> Result<(), EbillFfiError> {
    let timestamp = Timestamp::now();
    let (signer_public_data, signer_keys) = get_signer_public_data_and_keys().await?;

    get_ctx()
        .await
        .bill_service
        .execute_bill_action(
            &BillId::from_str(&accept_bill_payload.bill_id)
                .map_err(ProtocolValidationError::from)?,
            BillAction::Accept,
            &signer_public_data,
            &signer_keys,
            timestamp,
        )
        .await?;

    Ok(())
}

#[frb]
pub async fn request_to_mint(
    request_to_mint_bill_payload: RequestToMintBitcreditBillPayload,
) -> Result<(), EbillFfiError> {
    let timestamp = Timestamp::now();
    let (signer_public_data, signer_keys) = get_signer_public_data_and_keys().await?;
    get_ctx()
        .await
        .bill_service
        .request_to_mint(
            &BillId::from_str(&request_to_mint_bill_payload.bill_id)
                .map_err(ProtocolValidationError::from)?,
            &NodeId::from_str(&request_to_mint_bill_payload.mint_node)
                .map_err(ProtocolValidationError::from)?,
            &signer_public_data,
            &signer_keys,
            timestamp,
        )
        .await?;

    Ok(())
}

#[frb]
pub async fn mint_state(id: &str) -> Result<MintRequestStateResponse, EbillFfiError> {
    let bill_id = BillId::from_str(id).map_err(ProtocolValidationError::from)?;
    let result = get_ctx()
        .await
        .bill_service
        .get_mint_state(&bill_id, &get_current_identity_node_id().await?)
        .await?;
    Ok(MintRequestStateResponse {
        request_states: result.into_iter().map(|e| e.into()).collect(),
    })
}

#[frb]
pub async fn check_mint_state(id: &str) -> Result<(), EbillFfiError> {
    let bill_id = BillId::from_str(id).map_err(ProtocolValidationError::from)?;
    get_ctx()
        .await
        .bill_service
        .check_mint_state(&bill_id, &get_current_identity_node_id().await?)
        .await?;
    Ok(())
}

#[frb]
pub async fn cancel_request_to_mint(mint_request_id: &str) -> Result<(), EbillFfiError> {
    let parsed_id = Uuid::from_str(mint_request_id)
        .map_err(|_| ProtocolValidationError::InvalidMintRequestId)?;
    get_ctx()
        .await
        .bill_service
        .cancel_request_to_mint(&parsed_id, &get_current_identity_node_id().await?)
        .await?;
    Ok(())
}

#[frb]
pub async fn accept_mint_offer(mint_request_id: &str) -> Result<(), EbillFfiError> {
    let timestamp = Timestamp::now();
    let (signer_public_data, signer_keys) = get_signer_public_data_and_keys().await?;
    let parsed_id = Uuid::from_str(mint_request_id)
        .map_err(|_| ProtocolValidationError::InvalidMintRequestId)?;
    get_ctx()
        .await
        .bill_service
        .accept_mint_offer(&parsed_id, &signer_public_data, &signer_keys, timestamp)
        .await?;
    Ok(())
}

#[frb]
pub async fn reject_mint_offer(mint_request_id: &str) -> Result<(), EbillFfiError> {
    let parsed_id = Uuid::from_str(mint_request_id)
        .map_err(|_| ProtocolValidationError::InvalidMintRequestId)?;
    get_ctx()
        .await
        .bill_service
        .reject_mint_offer(&parsed_id, &get_current_identity_node_id().await?)
        .await?;
    Ok(())
}

#[frb]
pub async fn reject_to_accept(
    reject_payload: RejectActionBillPayload,
) -> Result<(), EbillFfiError> {
    let timestamp = Timestamp::now();
    let (signer_public_data, signer_keys) = get_signer_public_data_and_keys().await?;

    get_ctx()
        .await
        .bill_service
        .execute_bill_action(
            &BillId::from_str(&reject_payload.bill_id).map_err(ProtocolValidationError::from)?,
            BillAction::RejectAcceptance,
            &signer_public_data,
            &signer_keys,
            timestamp,
        )
        .await?;

    Ok(())
}

#[frb]
pub async fn reject_to_pay(reject_payload: RejectActionBillPayload) -> Result<(), EbillFfiError> {
    let timestamp = Timestamp::now();
    let (signer_public_data, signer_keys) = get_signer_public_data_and_keys().await?;

    get_ctx()
        .await
        .bill_service
        .execute_bill_action(
            &BillId::from_str(&reject_payload.bill_id).map_err(ProtocolValidationError::from)?,
            BillAction::RejectPayment,
            &signer_public_data,
            &signer_keys,
            timestamp,
        )
        .await?;

    Ok(())
}

#[frb]
pub async fn reject_to_buy(reject_payload: RejectActionBillPayload) -> Result<(), EbillFfiError> {
    let timestamp = Timestamp::now();
    let (signer_public_data, signer_keys) = get_signer_public_data_and_keys().await?;

    get_ctx()
        .await
        .bill_service
        .execute_bill_action(
            &BillId::from_str(&reject_payload.bill_id).map_err(ProtocolValidationError::from)?,
            BillAction::RejectBuying,
            &signer_public_data,
            &signer_keys,
            timestamp,
        )
        .await?;

    Ok(())
}

#[frb]
pub async fn reject_to_pay_recourse(
    reject_payload: RejectActionBillPayload,
) -> Result<(), EbillFfiError> {
    let timestamp = Timestamp::now();
    let (signer_public_data, signer_keys) = get_signer_public_data_and_keys().await?;

    get_ctx()
        .await
        .bill_service
        .execute_bill_action(
            &BillId::from_str(&reject_payload.bill_id).map_err(ProtocolValidationError::from)?,
            BillAction::RejectPaymentForRecourse,
            &signer_public_data,
            &signer_keys,
            timestamp,
        )
        .await?;

    Ok(())
}

#[frb]
pub async fn request_to_recourse_bill_payment(
    request_recourse_payload: RequestRecourseForPaymentPayload,
) -> Result<(), EbillFfiError> {
    let sum = Sum::new_sat_from_str(&request_recourse_payload.sum)?;

    request_recourse(
        RecourseReason::Pay(sum),
        &BillId::from_str(&request_recourse_payload.bill_id)
            .map_err(ProtocolValidationError::from)?,
        &NodeId::from_str(&request_recourse_payload.recoursee)
            .map_err(ProtocolValidationError::from)?,
        parse_deadline_string(&request_recourse_payload.recourse_deadline)?,
    )
    .await
}

#[frb]
pub async fn request_to_recourse_bill_acceptance(
    request_recourse_payload: RequestRecourseForAcceptancePayload,
) -> Result<(), EbillFfiError> {
    request_recourse(
        RecourseReason::Accept,
        &BillId::from_str(&request_recourse_payload.bill_id)
            .map_err(ProtocolValidationError::from)?,
        &NodeId::from_str(&request_recourse_payload.recoursee)
            .map_err(ProtocolValidationError::from)?,
        parse_deadline_string(&request_recourse_payload.recourse_deadline)?,
    )
    .await
}

#[frb]
pub async fn clear_bill_cache() -> Result<(), EbillFfiError> {
    get_ctx().await.bill_service.clear_bill_cache().await?;
    Ok(())
}

#[frb]
pub async fn sync_bill_chain(payload: ResyncBillPayload) -> Result<(), EbillFfiError> {
    let bill_id = BillId::from_str(&payload.bill_id).map_err(ProtocolValidationError::from)?;
    get_ctx()
        .await
        .transport_service
        .block_transport()
        .resync_bill_chain(&bill_id, payload.from_nostr.unwrap_or(false))
        .await?;
    Ok(())
}

#[frb]
pub async fn dev_mode_get_full_bill_chain(bill_id: &str) -> Result<Vec<String>, EbillFfiError> {
    let parsed_bill_id = BillId::from_str(bill_id).map_err(ProtocolValidationError::from)?;
    let plaintext_chain = get_ctx()
        .await
        .bill_service
        .dev_mode_get_full_bill_chain(&parsed_bill_id, &get_current_identity_node_id().await?)
        .await?;
    let json_string_chain: Result<Vec<String>, EbillFfiError> = plaintext_chain
        .into_iter()
        .map(|plaintext_block| {
            plaintext_block
                .to_json_text()
                .map_err(|e| EbillFfiError::from(Error::Protocol(e.into())))
        })
        .collect();

    json_string_chain
}

#[frb]
pub async fn share_bill_with_court(
    payload: ShareBillWithCourtPayload,
) -> Result<(), EbillFfiError> {
    let parsed_bill_id =
        BillId::from_str(&payload.bill_id).map_err(ProtocolValidationError::from)?;
    let parsed_node_id =
        NodeId::from_str(&payload.court_node_id).map_err(ProtocolValidationError::from)?;
    let (signer_public_data, signer_keys) = get_signer_public_data_and_keys().await?;
    get_ctx()
        .await
        .bill_service
        .share_bill_with_court(
            &parsed_bill_id,
            &signer_public_data,
            &signer_keys,
            &parsed_node_id,
        )
        .await?;
    Ok(())
}

#[frb]
pub async fn bill_history(bill_id: &str) -> Result<BillHistoryResponse, EbillFfiError> {
    let parsed_bill_id = BillId::from_str(bill_id).map_err(ProtocolValidationError::from)?;
    let current_timestamp = Timestamp::now();
    let identity = get_ctx().await.identity_service.get_identity().await?;
    let (caller_public_data, caller_keys) = get_signer_public_data_and_keys().await?;
    let res: BillHistoryResponse = get_ctx()
        .await
        .bill_service
        .get_bill_history(
            &parsed_bill_id,
            &identity,
            &caller_public_data,
            &caller_keys,
            current_timestamp,
        )
        .await?
        .into();
    Ok(res)
}

#[frb]
pub async fn check_and_estimate_btc_sweep(
    payload: BillCheckSweepBTCFundsPayload,
) -> Result<BillSweepBTCEstimateFfi, EbillFfiError> {
    let (caller_public_data, caller_keys) = get_signer_public_data_and_keys().await?;
    let parsed_bill_id =
        BillId::from_str(&payload.bill_id).map_err(ProtocolValidationError::from)?;
    let estimate = get_ctx()
        .await
        .bill_service
        .check_and_estimate_btc_sweep(
            &parsed_bill_id,
            &caller_public_data,
            &caller_keys,
            &BitcoinAddress::from_str(&payload.source_address)
                .map_err(|_| ProtocolValidationError::InvalidBitcoinAddress)?,
            &BitcoinAddress::from_str(&payload.destination_address)
                .map_err(|_| ProtocolValidationError::InvalidBitcoinAddress)?,
        )
        .await?;
    Ok(estimate.into())
}

#[frb]
pub async fn sweep_btc_funds(
    payload: BillSweepBTCFundsPayload,
) -> Result<BillSweepBTCFundsResultFfi, EbillFfiError> {
    let parsed_bill_id =
        BillId::from_str(&payload.bill_id).map_err(ProtocolValidationError::from)?;
    let (caller_public_data, caller_keys) = get_signer_public_data_and_keys().await?;
    let res = get_ctx()
        .await
        .bill_service
        .btc_sweep(
            &parsed_bill_id,
            &caller_public_data,
            &caller_keys,
            &BitcoinAddress::from_str(&payload.source_address)
                .map_err(|_| ProtocolValidationError::InvalidBitcoinAddress)?,
            &BitcoinAddress::from_str(&payload.destination_address)
                .map_err(|_| ProtocolValidationError::InvalidBitcoinAddress)?,
            payload.fee,
        )
        .await?;
    Ok(res.into())
}

#[frb(ignore)]
pub(super) async fn get_signer_public_data_and_keys()
-> Result<(BillParticipant, BcrKeys), EbillFfiError> {
    let current_identity = get_current_identity().await?;
    let local_node_id = current_identity.personal;
    let identity = get_ctx().await.identity_service.get_full_identity().await?;
    let (signer_public_data, signer_keys) = match current_identity.company {
        None => {
            match identity.identity.t {
                IdentityType::Ident => {
                    match BillIdentParticipant::new(identity.identity) {
                        Ok(identity_public_data) => (
                            BillParticipant::Ident(identity_public_data),
                            identity.key_pair,
                        ),
                        Err(_) => {
                            // only non-anon bill issuers can sign a bill
                            return Err(Error::Validation(
                                ProtocolValidationError::SignerCantBeAnon.into(),
                            )
                            .into());
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
                .await
                .company_service
                .get_company_and_keys_by_id(&company_node_id)
                .await?;
            if !company
                .signatories
                .iter()
                .any(|s| s.node_id == local_node_id)
            {
                return Err(Error::Validation(
                    ProtocolValidationError::NotASignatory(local_node_id.to_string()).into(),
                )
                .into());
            }
            let mut as_ident = BillIdentParticipant::from(company);
            // use nostr relays from personal identity
            as_ident.nostr_relays = identity.identity.nostr_relays;
            (
                BillParticipant::Ident(as_ident),
                BcrKeys::from_private_key(&keys.get_private_key()),
            )
        }
    };
    Ok((signer_public_data, signer_keys))
}

async fn request_recourse(
    recourse_reason: RecourseReason,
    bill_id: &BillId,
    recoursee_node_id: &NodeId,
    recourse_deadline_timestamp: Timestamp,
) -> Result<(), EbillFfiError> {
    let timestamp = Timestamp::now();
    let (signer_public_data, signer_keys) = get_signer_public_data_and_keys().await?;

    // we fetch the nostr contact first to know where we have to send
    let nostr_contact = match get_ctx()
        .await
        .contact_service
        .get_nostr_contact_by_node_id(recoursee_node_id)
        .await
    {
        Ok(Some(nc)) => nc,
        Ok(None) | Err(_) => {
            return Err(
                BillServiceError::Validation(ValidationError::RecourseeNotInContacts).into(),
            );
        }
    };

    // fetch past endorsees to validate the recoursee is in there and to get their data
    let past_endorsees = get_ctx()
        .await
        .bill_service
        .get_past_endorsees(bill_id, &get_current_identity_node_id().await?)
        .await?;

    // create public recourse data from past endorsees and our nostr contacts
    let mut public_data_recoursee = match past_endorsees
        .iter()
        .find(|pe| &pe.pay_to_the_order_of.node_id == recoursee_node_id)
    {
        Some(found_pe) => found_pe.pay_to_the_order_of.clone(),
        None => {
            return Err(BillServiceError::Validation(
                ProtocolValidationError::RecourseeNotPastHolder.into(),
            )
            .into());
        }
    };
    public_data_recoursee.nostr_relays = nostr_contact.relays;

    get_ctx()
        .await
        .bill_service
        .execute_bill_action(
            bill_id,
            BillAction::RequestRecourse(
                public_data_recoursee,
                recourse_reason,
                recourse_deadline_timestamp,
            ),
            &signer_public_data,
            &signer_keys,
            timestamp,
        )
        .await?;

    Ok(())
}
