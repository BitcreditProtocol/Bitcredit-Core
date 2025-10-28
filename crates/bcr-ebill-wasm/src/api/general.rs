use super::Result;
use bcr_ebill_api::{
    data::GeneralSearchFilterItemType,
    service::Error,
    util::{VALID_CURRENCIES, ValidationError, file::detect_content_type_for_bytes},
};
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
                return Err(Error::Validation(ValidationError::InvalidFileUploadId).into());
            }
            match get_ctx()
                .file_upload_service
                .get_temp_file(file_upload_id)
                .await
            {
                Ok(Some((file_name, file_bytes))) => {
                    let content_type = detect_content_type_for_bytes(&file_bytes)
                        .ok_or(Error::Validation(ValidationError::InvalidContentType))?;

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
            if !VALID_CURRENCIES.contains(&currency) {
                return Err(Error::Validation(ValidationError::InvalidCurrency).into());
            }
            let result = get_ctx()
                .bill_service
                .get_bill_balances(currency, &get_current_identity_node_id().await?)
                .await?;

            Ok(OverviewResponse {
                currency: currency.to_owned(),
                balances: OverviewBalanceResponse {
                    payee: BalanceResponse {
                        sum: result.payee.sum,
                    },
                    payer: BalanceResponse {
                        sum: result.payer.sum,
                    },
                    contingent: BalanceResponse {
                        sum: result.contingent.sum,
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
                    &search_filter.filter.currency,
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
