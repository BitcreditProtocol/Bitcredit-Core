use super::Result;
use bcr_ebill_api::{
    data::GeneralSearchFilterItemType,
    service::Error,
    util::{VALID_CURRENCIES, ValidationError, file::detect_content_type_for_bytes},
};
use wasm_bindgen::prelude::*;

use crate::{
    api::identity::get_current_identity_node_id,
    context::get_ctx,
    data::{
        BalanceResponse, BinaryFileResponse, CurrenciesResponse, CurrencyResponse, FromWeb,
        GeneralSearchFilterPayload, IntoWeb, OverviewBalanceResponse, OverviewResponse,
        StatusResponse,
    },
};

#[wasm_bindgen]
pub struct General;

#[wasm_bindgen]
impl General {
    #[wasm_bindgen]
    pub fn new() -> Self {
        General
    }

    #[wasm_bindgen(unchecked_return_type = "StatusResponse")]
    pub async fn status(&self) -> Result<JsValue> {
        let res = serde_wasm_bindgen::to_value(&StatusResponse {
            bitcoin_network: get_ctx().cfg.bitcoin_network.clone(),
            app_version: String::from("0.3.0"),
        })?;
        Ok(res)
    }

    #[wasm_bindgen(unchecked_return_type = "CurrenciesResponse")]
    pub async fn currencies(&self) -> Result<JsValue> {
        let res = serde_wasm_bindgen::to_value(&CurrenciesResponse {
            currencies: VALID_CURRENCIES
                .iter()
                .map(|vc| CurrencyResponse {
                    code: vc.to_string(),
                })
                .collect(),
        })?;
        Ok(res)
    }

    #[wasm_bindgen(unchecked_return_type = "BinaryFileResponse")]
    pub async fn temp_file(&self, file_upload_id: &str) -> Result<JsValue> {
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

                let res = serde_wasm_bindgen::to_value(&BinaryFileResponse {
                    data: file_bytes,
                    name: file_name.to_owned(),
                    content_type,
                })?;
                Ok(res)
            }
            _ => Err(Error::NotFound.into()),
        }
    }

    #[wasm_bindgen(unchecked_return_type = "OverviewResponse")]
    pub async fn overview(&self, currency: &str) -> Result<JsValue> {
        if !VALID_CURRENCIES.contains(&currency) {
            return Err(Error::Validation(ValidationError::InvalidCurrency).into());
        }
        let result = get_ctx()
            .bill_service
            .get_bill_balances(currency, &get_current_identity_node_id().await?)
            .await?;

        let res = serde_wasm_bindgen::to_value(&OverviewResponse {
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
        })?;
        Ok(res)
    }

    #[wasm_bindgen(unchecked_return_type = "GeneralSearchResponse")]
    pub async fn search(
        &self,
        #[wasm_bindgen(unchecked_param_type = "GeneralSearchFilterPayload")] payload: JsValue,
    ) -> Result<JsValue> {
        let search_filter: GeneralSearchFilterPayload = serde_wasm_bindgen::from_value(payload)?;
        let filters: Vec<GeneralSearchFilterItemType> = search_filter
            .filter
            .clone()
            .item_types
            .into_iter()
            .map(GeneralSearchFilterItemType::from_web)
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

        let res = serde_wasm_bindgen::to_value(&result.into_web())?;
        Ok(res)
    }
}

impl Default for General {
    fn default() -> Self {
        General
    }
}
