use async_trait::async_trait;
use bcr_ebill_api::{
    NotificationFilter,
    data::{
        File, GeneralSearchFilterItemType, GeneralSearchResult, OptionalPostalAddress,
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
pub mod notification;

pub trait IntoWeb<T> {
    fn into_web(self) -> T;
}

pub trait FromWeb<T> {
    fn from_web(value: T) -> Self;
}

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

impl IntoWeb<GeneralSearchResponse> for GeneralSearchResult {
    fn into_web(self) -> GeneralSearchResponse {
        GeneralSearchResponse {
            bills: self.bills.into_iter().map(|b| b.into_web()).collect(),
            contacts: self.contacts.into_iter().map(|c| c.into_web()).collect(),
            companies: self.companies.into_iter().map(|c| c.into_web()).collect(),
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

impl FromWeb<GeneralSearchFilterItemTypeWeb> for GeneralSearchFilterItemType {
    fn from_web(value: GeneralSearchFilterItemTypeWeb) -> Self {
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

impl FromWeb<OptionalPostalAddressWeb> for OptionalPostalAddress {
    fn from_web(value: OptionalPostalAddressWeb) -> Self {
        Self {
            country: value.country,
            city: value.city,
            zip: value.zip,
            address: value.address,
        }
    }
}

impl IntoWeb<OptionalPostalAddressWeb> for OptionalPostalAddress {
    fn into_web(self) -> OptionalPostalAddressWeb {
        OptionalPostalAddressWeb {
            country: self.country,
            city: self.city,
            zip: self.zip,
            address: self.address,
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

impl FromWeb<PostalAddressWeb> for PostalAddress {
    fn from_web(value: PostalAddressWeb) -> Self {
        Self {
            country: value.country,
            city: value.city,
            zip: value.zip,
            address: value.address,
        }
    }
}

impl IntoWeb<PostalAddressWeb> for PostalAddress {
    fn into_web(self) -> PostalAddressWeb {
        PostalAddressWeb {
            country: self.country,
            city: self.city,
            zip: self.zip,
            address: self.address,
        }
    }
}

#[derive(Tsify, Debug, Clone, Serialize, Deserialize, Default)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct NotificationFilters {
    pub active: Option<bool>,
    pub reference_id: Option<String>,
    pub notification_type: Option<String>,
    pub node_ids: Option<Vec<String>>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

impl FromWeb<NotificationFilters> for NotificationFilter {
    fn from_web(value: NotificationFilters) -> Self {
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
}

impl FromWeb<FileWeb> for File {
    fn from_web(value: FileWeb) -> Self {
        Self {
            name: value.name,
            hash: value.hash,
        }
    }
}

impl IntoWeb<FileWeb> for File {
    fn into_web(self) -> FileWeb {
        FileWeb {
            name: self.name,
            hash: self.hash,
        }
    }
}

/// Just a wrapper struct to allow setting a content disposition header
#[derive(Tsify, Debug, Clone, Serialize, Deserialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct BinaryFileResponse {
    pub data: Vec<u8>,
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

    fn len(&self) -> u64 {
        self.data.len() as u64
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

impl IntoWeb<UploadFileResponse> for UploadFileResult {
    fn into_web(self) -> UploadFileResponse {
        UploadFileResponse {
            file_upload_id: self.file_upload_id,
        }
    }
}
