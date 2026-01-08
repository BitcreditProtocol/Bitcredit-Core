use std::str::FromStr;

use super::Result;
use bcr_ebill_api::service::{Error, file_upload_service::detect_content_type_for_bytes};
use bcr_ebill_core::{
    application::GeneralSearchFilterItemType,
    protocol::{Currency, ProtocolValidationError, constants::VALID_CURRENCIES},
};
use uuid::Uuid;
use wasm_bindgen::prelude::*;

use crate::{
    TSResult,
    api::identity::get_current_identity_node_id,
    context::get_ctx,
    data::{
        BalanceResponse, BinaryFileResponse, CurrenciesResponse, CurrencyResponse,
        GeneralSearchFilterPayload, GeneralSearchResponse, OverviewBalanceResponse,
        OverviewResponse, StatusResponse,
    },
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
            Ok(StatusResponse {
                bitcoin_network: get_ctx().cfg.bitcoin_network.clone(),
                app_version: VERSION.to_owned(),
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
            // Make currency comparison case-insensitive
            let currency = currency.to_uppercase();
            if !VALID_CURRENCIES.contains(&currency.as_str()) {
                return Err(
                    Error::Validation(ProtocolValidationError::InvalidCurrency.into()).into(),
                );
            }
            let parsed_currency = Currency::sat();
            let result = get_ctx()
                .bill_service
                .get_bill_balances(&parsed_currency, &get_current_identity_node_id().await?)
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
            let result = get_ctx()
                .search_service
                .search(
                    &search_filter.filter.search_term,
                    &Currency::sat(),
                    &filters,
                    &get_current_identity_node_id().await?,
                )
                .await?;

            Ok(result.into())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_currency_case_insensitive() {
        // Test that currency validation is case-insensitive
        let valid_currencies = ["SAT", "sat", "Sat", "sAt", "SaT"];

        for currency in valid_currencies.iter() {
            let currency_upper = currency.to_uppercase();
            assert!(
                VALID_CURRENCIES.contains(&currency_upper.as_str()),
                "Currency '{}' (uppercase: '{}') should be valid",
                currency,
                currency_upper
            );
        }

        // Test invalid currency
        let invalid_currencies = ["USD", "eur", "BTC"];
        for currency in invalid_currencies.iter() {
            let currency_upper = currency.to_uppercase();
            assert!(
                !VALID_CURRENCIES.contains(&currency_upper.as_str()),
                "Currency '{}' (uppercase: '{}') should be invalid",
                currency,
                currency_upper
            );
        }
    }
}
