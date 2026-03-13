use std::str::FromStr;

use super::Result;
use bcr_ebill_api::service::{Error, file_upload_service::detect_content_type_for_bytes};
use bcr_ebill_core::{
    application::GeneralSearchFilterItemType,
    protocol::{
        BitcoinAddress, Currency, ProtocolValidationError, Sum, constants::VALID_CURRENCIES,
    },
};
use uuid::Uuid;
use wasm_bindgen::prelude::*;

use crate::{
    TSResult,
    api::bill::get_signer_public_data_and_keys,
    context::get_ctx,
    data::{
        BalanceResponse, BinaryFileResponse, BtcAddressAndSumPayload, BtcAddressPayload,
        CurrenciesResponse, CurrencyResponse, GeneralSearchFilterPayload, GeneralSearchResponse,
        LinkToPayResponse, MempoolLinkResponse, OverviewBalanceResponse, OverviewResponse,
        StatusResponse,
    },
    is_transport_connected,
};

pub const VERSION: &str = env!("CRATE_VERSION");

#[wasm_bindgen]
pub struct General;

#[wasm_bindgen]
impl General {
    #[wasm_bindgen]
    pub fn new() -> Self {
        General
    }

    #[wasm_bindgen(unchecked_return_type = "TSResult<StatusResponse>")]
    pub async fn status(&self) -> JsValue {
        let res: Result<StatusResponse> = async {
            let connected =
                is_transport_connected() && get_ctx().nostr_client.has_connected_relays().await;
            Ok(StatusResponse {
                bitcoin_network: get_ctx().cfg.bitcoin_network.clone(),
                app_version: VERSION.to_owned(),
                connected,
            })
        }
        .await;
        TSResult::res_to_js(res)
    }

    #[wasm_bindgen(unchecked_return_type = "TSResult<CurrenciesResponse>")]
    pub async fn currencies(&self) -> JsValue {
        let res: Result<CurrenciesResponse> = async {
            Ok(CurrenciesResponse {
                currencies: VALID_CURRENCIES
                    .iter()
                    .map(|vc| CurrencyResponse {
                        code: vc.to_string(),
                    })
                    .collect(),
            })
        }
        .await;
        TSResult::res_to_js(res)
    }

    #[wasm_bindgen(unchecked_return_type = "TSResult<BinaryFileResponse>")]
    pub async fn temp_file(&self, file_upload_id: &str) -> JsValue {
        let res: Result<BinaryFileResponse> = async {
            if file_upload_id.is_empty() {
                return Err(
                    Error::Validation(ProtocolValidationError::InvalidFileUploadId.into()).into(),
                );
            }
            let parsed_id = Uuid::from_str(file_upload_id)
                .map_err(|_| ProtocolValidationError::InvalidFileUploadId)?;
            match get_ctx()
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
                        name: file_name.to_owned(),
                        content_type,
                    })
                }
                Ok(None) => Err(Error::NotFound.into()),
                Err(e) => Err(e.into()),
            }
        }
        .await;
        TSResult::res_to_js(res)
    }

    #[wasm_bindgen(unchecked_return_type = "TSResult<OverviewResponse>")]
    pub async fn overview(&self, currency: &str) -> JsValue {
        let res: Result<OverviewResponse> = async {
            let Ok(currency) = Currency::validated(currency) else {
                return Err(
                    Error::Validation(ProtocolValidationError::InvalidCurrency.into()).into(),
                );
            };

            let parsed_currency = Currency::sat();
            let (caller_public_data, caller_keys) = get_signer_public_data_and_keys().await?;
            let result = get_ctx()
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
        .await;
        TSResult::res_to_js(res)
    }

    #[wasm_bindgen(unchecked_return_type = "TSResult<GeneralSearchResponse>")]
    pub async fn search(
        &self,
        #[wasm_bindgen(unchecked_param_type = "GeneralSearchFilterPayload")] payload: JsValue,
    ) -> JsValue {
        let res: Result<GeneralSearchResponse> = async {
            let search_filter: GeneralSearchFilterPayload =
                serde_wasm_bindgen::from_value(payload)?;
            let filters: Vec<GeneralSearchFilterItemType> = search_filter
                .filter
                .clone()
                .item_types
                .into_iter()
                .map(GeneralSearchFilterItemType::from)
                .collect();
            let (caller_public_data, caller_keys) = get_signer_public_data_and_keys().await?;
            let result = get_ctx()
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
        .await;
        TSResult::res_to_js(res)
    }

    #[wasm_bindgen(unchecked_return_type = "TSResult<LinkToPayResponse>")]
    pub async fn link_to_pay(
        &self,
        #[wasm_bindgen(unchecked_param_type = "BtcAddressAndSumPayload")] payload: JsValue,
    ) -> JsValue {
        let res: Result<LinkToPayResponse> = async {
            let pl: BtcAddressAndSumPayload = serde_wasm_bindgen::from_value(payload)?;
            let parsed_addr = BitcoinAddress::from_str(&pl.address)
                .map_err(|_| ProtocolValidationError::InvalidBitcoinAddress)?;
            let parsed_sum = Sum::new_sat_from_str(&pl.sum)?;
            Ok(LinkToPayResponse {
                link_to_pay: get_ctx().bill_service.link_to_pay(
                    &parsed_addr,
                    &parsed_sum,
                    &pl.bill_id,
                ),
            })
        }
        .await;
        TSResult::res_to_js(res)
    }

    #[wasm_bindgen(unchecked_return_type = "TSResult<MempoolLinkResponse>")]
    pub async fn mempool_link(
        &self,
        #[wasm_bindgen(unchecked_param_type = "BtcAddressPayload")] payload: JsValue,
    ) -> JsValue {
        let res: Result<MempoolLinkResponse> = async {
            let pl: BtcAddressPayload = serde_wasm_bindgen::from_value(payload)?;
            let parsed_addr = BitcoinAddress::from_str(&pl.address)
                .map_err(|_| ProtocolValidationError::InvalidBitcoinAddress)?;
            Ok(MempoolLinkResponse {
                mempool_link: get_ctx().bill_service.mempool_link(&parsed_addr),
            })
        }
        .await;
        TSResult::res_to_js(res)
    }
}

impl Default for General {
    fn default() -> Self {
        General
    }
}
