use crate::ffi::{
    api::bill::get_signer_public_data_and_keys,
    context::get_ctx,
    data::{
        BalanceResponse, BinaryFileResponse, BtcAddressAndSumPayload, BtcAddressPayload,
        CurrenciesResponse, CurrencyResponse, GeneralSearchFilterPayload, GeneralSearchResponse,
        LinkToPayResponse, MempoolLinkResponse, OverviewBalanceResponse, OverviewResponse,
        StatusResponse,
    },
    error::EbillFfiError,
};
use bcr_common::core::BillId;
use bcr_ebill_api::service::{Error, file_upload_service::detect_content_type_for_bytes};
use bcr_ebill_core::{
    application::GeneralSearchFilterItemType,
    protocol::{
        BitcoinAddress, Currency, ProtocolValidationError, Sum, constants::VALID_CURRENCIES,
    },
};
use flutter_rust_bridge::frb;
use std::str::FromStr;
use uuid::Uuid;

pub const VERSION: &str = env!("CRATE_VERSION");

#[frb]
pub async fn get_status() -> Result<StatusResponse, EbillFfiError> {
    let transport_connected = crate::ffi::EBILL_RUNTIME
        .lock()
        .await
        .is_transport_connected();
    let ctx = get_ctx().await;
    Ok(StatusResponse {
        app_version: VERSION.to_owned(),
        bitcoin_network: ctx.cfg.bitcoin_network.clone(),
        connected: transport_connected && ctx.nostr_client.has_connected_relays().await,
    })
}

#[frb]
pub async fn currencies() -> Result<CurrenciesResponse, EbillFfiError> {
    Ok(CurrenciesResponse {
        currencies: VALID_CURRENCIES
            .iter()
            .map(|vc| CurrencyResponse {
                code: vc.to_string(),
            })
            .collect(),
    })
}

#[frb]
pub async fn temp_file(file_upload_id: &str) -> Result<BinaryFileResponse, EbillFfiError> {
    if file_upload_id.is_empty() {
        return Err(Error::Validation(ProtocolValidationError::InvalidFileUploadId.into()).into());
    }
    let parsed_id =
        Uuid::from_str(file_upload_id).map_err(|_| ProtocolValidationError::InvalidFileUploadId)?;
    match get_ctx()
        .await
        .file_upload_service
        .get_temp_file(&parsed_id)
        .await
    {
        Ok(Some((file_name, file_bytes))) => {
            let content_type = detect_content_type_for_bytes(&file_bytes).ok_or(
                Error::Validation(ProtocolValidationError::InvalidContentType.into()),
            )?;

            Ok(BinaryFileResponse {
                data: file_bytes,
                name: file_name.to_string(),
                content_type,
            })
        }
        Ok(None) => Err(Error::NotFound.into()),
        Err(e) => Err(e.into()),
    }
}

#[frb]
pub async fn overview(currency: &str) -> Result<OverviewResponse, EbillFfiError> {
    let Ok(currency) = Currency::validated(currency) else {
        return Err(Error::Validation(ProtocolValidationError::InvalidCurrency.into()).into());
    };

    let parsed_currency = Currency::sat();
    let (caller_public_data, caller_keys) = get_signer_public_data_and_keys().await?;
    let result = get_ctx()
        .await
        .bill_service
        .get_bill_balances(&parsed_currency, &caller_public_data, &caller_keys)
        .await?;

    Ok(OverviewResponse {
        currency,
        balances: OverviewBalanceResponse {
            payee: BalanceResponse {
                sum: result.payee.sum.as_sat_string(),
            },
            payer: BalanceResponse {
                sum: result.payer.sum.as_sat_string(),
            },
            contingent: BalanceResponse {
                sum: result.contingent.sum.as_sat_string(),
            },
        },
    })
}

#[frb]
pub async fn search(
    search_filter: GeneralSearchFilterPayload,
) -> Result<GeneralSearchResponse, EbillFfiError> {
    let filters: Vec<GeneralSearchFilterItemType> = search_filter
        .filter
        .clone()
        .item_types
        .into_iter()
        .map(GeneralSearchFilterItemType::from)
        .collect();
    let (caller_public_data, caller_keys) = get_signer_public_data_and_keys().await?;
    let result = get_ctx()
        .await
        .search_service
        .search(
            &search_filter.filter.search_term,
            &Currency::sat(),
            &filters,
            &caller_public_data,
            &caller_keys,
        )
        .await?;

    Ok(result.into())
}

#[frb]
pub async fn link_to_pay(pl: BtcAddressAndSumPayload) -> Result<LinkToPayResponse, EbillFfiError> {
    let parsed_addr = BitcoinAddress::from_str(&pl.address)
        .map_err(|_| ProtocolValidationError::InvalidBitcoinAddress)?;
    let parsed_sum = Sum::new_sat_from_str(&pl.sum)?;
    let parsed_bill_id = BillId::from_str(&pl.bill_id).map_err(ProtocolValidationError::from)?;
    let result =
        get_ctx()
            .await
            .bill_service
            .link_to_pay(&parsed_addr, &parsed_sum, &parsed_bill_id);
    Ok(LinkToPayResponse {
        link_to_pay: result,
    })
}

#[frb]
pub async fn mempool_link(pl: BtcAddressPayload) -> Result<MempoolLinkResponse, EbillFfiError> {
    let parsed_addr = BitcoinAddress::from_str(&pl.address)
        .map_err(|_| ProtocolValidationError::InvalidBitcoinAddress)?;
    Ok(MempoolLinkResponse {
        mempool_link: get_ctx().await.bill_service.mempool_link(&parsed_addr),
    })
}
