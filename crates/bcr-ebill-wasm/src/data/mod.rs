use async_trait::async_trait;
use bcr_ebill_api::{
    NotificationFilter,
    data::{
        File, GeneralSearchFilterItemType, GeneralSearchResult, NodeId, OptionalPostalAddress,
        PostalAddress, UploadFileResult,
    },
    util::file::{UploadFileHandler, detect_content_type_for_bytes},
};
use bill::LightBitcreditBillWeb;
use company::CompanyWeb;
use contact::ContactWeb;
use serde::{Deserialize, Serialize};
use tsify::Tsify;
use wasm_bindgen::prelude::*;

pub mod bill;
pub mod company;
pub mod contact;
pub mod identity;
pub mod identity_proof;
pub mod mint;
pub mod notification;

#[derive(Tsify, Debug, Serialize)]
#[tsify(into_wasm_abi)]
pub struct StatusResponse {
    pub bitcoin_network: String,
    pub app_version: String,
}

#[derive(Tsify, Debug, Serialize)]
#[tsify(into_wasm_abi)]
pub struct GeneralSearchResponse {
    pub bills: Vec<LightBitcreditBillWeb>,
    pub contacts: Vec<ContactWeb>,
    pub companies: Vec<CompanyWeb>,
}

impl From<GeneralSearchResult> for GeneralSearchResponse {
    fn from(val: GeneralSearchResult) -> Self {
        GeneralSearchResponse {
            bills: val.bills.into_iter().map(|b| b.into()).collect(),
            contacts: val.contacts.into_iter().map(|c| c.into()).collect(),
            companies: val.companies.into_iter().map(|c| c.into()).collect(),
        }
    }
}

#[derive(Tsify, Debug, Clone, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct GeneralSearchFilterPayload {
    pub filter: GeneralSearchFilter,
}

#[derive(Tsify, Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub enum GeneralSearchFilterItemTypeWeb {
    Company,
    Bill,
    Contact,
}

impl From<GeneralSearchFilterItemTypeWeb> for GeneralSearchFilterItemType {
    fn from(value: GeneralSearchFilterItemTypeWeb) -> Self {
        match value {
            GeneralSearchFilterItemTypeWeb::Company => GeneralSearchFilterItemType::Company,
            GeneralSearchFilterItemTypeWeb::Bill => GeneralSearchFilterItemType::Bill,
            GeneralSearchFilterItemTypeWeb::Contact => GeneralSearchFilterItemType::Contact,
        }
    }
}

#[derive(Tsify, Debug, Clone, Serialize, Deserialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct GeneralSearchFilter {
    pub search_term: String,
    pub currency: String,
    pub item_types: Vec<GeneralSearchFilterItemTypeWeb>,
}

#[derive(Tsify, Debug, Clone, Serialize)]
#[tsify(into_wasm_abi)]
pub struct OverviewResponse {
    pub currency: String,
    pub balances: OverviewBalanceResponse,
}

#[derive(Tsify, Debug, Clone, Serialize)]
#[tsify(into_wasm_abi)]
pub struct OverviewBalanceResponse {
    pub payee: BalanceResponse,
    pub payer: BalanceResponse,
    pub contingent: BalanceResponse,
}

#[derive(Tsify, Debug, Clone, Serialize)]
#[tsify(into_wasm_abi)]
pub struct BalanceResponse {
    pub sum: String,
}

#[derive(Tsify, Debug, Clone, Serialize)]
#[tsify(into_wasm_abi)]
pub struct CurrenciesResponse {
    pub currencies: Vec<CurrencyResponse>,
}

#[derive(Tsify, Debug, Clone, Serialize)]
#[tsify(into_wasm_abi)]
pub struct CurrencyResponse {
    pub code: String,
}

#[derive(Tsify, Debug, Clone, Serialize, Deserialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct OptionalPostalAddressWeb {
    pub country: Option<String>,
    pub city: Option<String>,
    pub zip: Option<String>,
    pub address: Option<String>,
}

impl OptionalPostalAddressWeb {
    pub fn is_none(&self) -> bool {
        self.country.is_none()
            && self.city.is_none()
            && self.zip.is_none()
            && self.address.is_none()
    }
}

impl From<OptionalPostalAddressWeb> for OptionalPostalAddress {
    fn from(value: OptionalPostalAddressWeb) -> Self {
        Self {
            country: value.country,
            city: value.city,
            zip: value.zip,
            address: value.address,
        }
    }
}

impl From<OptionalPostalAddress> for OptionalPostalAddressWeb {
    fn from(value: OptionalPostalAddress) -> Self {
        Self {
            country: value.country,
            city: value.city,
            zip: value.zip,
            address: value.address,
        }
    }
}

#[derive(Tsify, Debug, Clone, Serialize, Deserialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct PostalAddressWeb {
    pub country: String,
    pub city: String,
    pub zip: Option<String>,
    pub address: String,
}

impl From<PostalAddressWeb> for PostalAddress {
    fn from(value: PostalAddressWeb) -> Self {
        Self {
            country: value.country,
            city: value.city,
            zip: value.zip,
            address: value.address,
        }
    }
}

impl From<PostalAddress> for PostalAddressWeb {
    fn from(val: PostalAddress) -> Self {
        PostalAddressWeb {
            country: val.country,
            city: val.city,
            zip: val.zip,
            address: val.address,
        }
    }
}

#[derive(Tsify, Debug, Clone, Serialize, Deserialize, Default)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct NotificationFilters {
    pub active: Option<bool>,
    pub reference_id: Option<String>,
    pub notification_type: Option<String>,
    #[tsify(type = "string[] | undefined")]
    pub node_ids: Option<Vec<NodeId>>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

impl From<NotificationFilters> for NotificationFilter {
    fn from(value: NotificationFilters) -> Self {
        Self {
            active: value.active,
            reference_id: value.reference_id,
            notification_type: value.notification_type,
            node_ids: value.node_ids.unwrap_or_default(),
            limit: value.limit,
            offset: value.offset,
        }
    }
}

#[derive(Tsify, Debug, Clone, Serialize, Deserialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct FileWeb {
    pub name: String,
    pub hash: String,
    pub nostr_hash: String,
}

impl From<FileWeb> for File {
    fn from(value: FileWeb) -> Self {
        Self {
            name: value.name,
            hash: value.hash,
            nostr_hash: value.nostr_hash,
        }
    }
}

impl From<File> for FileWeb {
    fn from(val: File) -> Self {
        FileWeb {
            name: val.name,
            hash: val.hash,
            nostr_hash: val.nostr_hash,
        }
    }
}

#[derive(Tsify, Debug, Clone, Serialize, Deserialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct BinaryFileResponse {
    pub data: Vec<u8>,
    pub name: String,
    pub content_type: String,
}

#[derive(Tsify, Debug, Clone, Serialize, Deserialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct Base64FileResponse {
    pub data: String,
    pub name: String,
    pub content_type: String,
}

#[derive(Tsify, Debug, Clone, Serialize, Deserialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct UploadFile {
    pub data: Vec<u8>,
    pub extension: Option<String>,
    pub name: String,
}

#[async_trait]
impl UploadFileHandler for UploadFile {
    async fn get_contents(&self) -> std::io::Result<Vec<u8>> {
        Ok(self.data.clone())
    }

    fn extension(&self) -> Option<String> {
        self.extension.clone()
    }

    fn name(&self) -> Option<String> {
        Some(self.name.clone())
    }

    fn len(&self) -> usize {
        self.data.len()
    }
    async fn detect_content_type(&self) -> std::io::Result<Option<String>> {
        Ok(detect_content_type_for_bytes(&self.data))
    }
}

#[derive(Tsify, Debug, Serialize, Clone)]
#[tsify(into_wasm_abi)]
pub struct UploadFileResponse {
    pub file_upload_id: String,
}

impl From<UploadFileResult> for UploadFileResponse {
    fn from(val: UploadFileResult) -> Self {
        UploadFileResponse {
            file_upload_id: val.file_upload_id,
        }
    }
}

pub fn has_field(js_value: &JsValue, field: &str) -> bool {
    js_sys::Reflect::has(js_value, &JsValue::from_str(field)).unwrap_or(false)
}
