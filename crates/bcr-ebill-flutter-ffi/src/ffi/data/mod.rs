use std::str::FromStr;

use async_trait::async_trait;
use bcr_common::core::NodeId;
use bcr_ebill_api::service::file_upload_service::{
    UploadFileHandler, detect_content_type_for_bytes,
};
use bcr_ebill_core::{
    application::{
        GeneralSearchFilterItemType, GeneralSearchResult, UploadFileResult, ValidationError,
    },
    protocol::{
        Address, City, Country, Date, EditOptionalFieldMode, File, Name, OptionalPostalAddress,
        PostalAddress, ProtocolValidationError, Sha256Hash, Timestamp, Zip,
    },
};
use bcr_ebill_persistence::notification::NotificationFilter;
use flutter_rust_bridge::frb;
use nostr::hashes::sha256::Hash as Sha256HexHash;

use crate::ffi::data::{bill::LightBitcreditBillFfi, company::CompanyFfi, contact::ContactFfi};

pub mod bill;
pub mod company;
pub mod contact;
pub mod identity;
pub mod mint;
pub mod notification;

#[derive(Debug, Clone)]
pub struct StatusResponse {
    /// Name of the currently configured Bitcoin network (e.g. `mainnet`, `testnet`).
    pub bitcoin_network: String,
    /// `true` if the app has an active connection to at least one configured Nostr relay.
    ///
    /// This reflects the status of the Nostr transport layer, not general internet
    /// connectivity or backend/database availability. When `connected` is `false`,
    /// operations that require Nostr (such as bill synchronization with other peers,
    /// sending or receiving notifications, or other relay-based messaging) will not
    /// be able to communicate over the network and may fall back to local-only state.
    pub connected: bool,
    /// Semantic version of the running E-Bills application backend.
    pub app_version: String,
}

#[derive(Debug)]
pub struct GeneralSearchResponse {
    pub bills: Vec<LightBitcreditBillFfi>,
    pub contacts: Vec<ContactFfi>,
    pub companies: Vec<CompanyFfi>,
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

#[derive(Debug, Clone)]
pub struct GeneralSearchFilterPayload {
    pub filter: GeneralSearchFilter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeneralSearchFilterItemTypeFfi {
    Company,
    Bill,
    Contact,
}

impl From<GeneralSearchFilterItemTypeFfi> for GeneralSearchFilterItemType {
    fn from(value: GeneralSearchFilterItemTypeFfi) -> Self {
        match value {
            GeneralSearchFilterItemTypeFfi::Company => GeneralSearchFilterItemType::Company,
            GeneralSearchFilterItemTypeFfi::Bill => GeneralSearchFilterItemType::Bill,
            GeneralSearchFilterItemTypeFfi::Contact => GeneralSearchFilterItemType::Contact,
        }
    }
}

#[derive(Debug, Clone)]
pub struct GeneralSearchFilter {
    pub search_term: String,
    pub currency: String,
    pub item_types: Vec<GeneralSearchFilterItemTypeFfi>,
}

#[derive(Debug, Clone)]
pub struct OverviewResponse {
    pub currency: String,
    pub balances: OverviewBalanceResponse,
}

#[derive(Debug, Clone)]
pub struct OverviewBalanceResponse {
    pub payee: BalanceResponse,
    pub payer: BalanceResponse,
    pub contingent: BalanceResponse,
}

#[derive(Debug, Clone)]
pub struct BalanceResponse {
    pub sum: String,
}

#[derive(Debug, Clone)]
pub struct CurrenciesResponse {
    pub currencies: Vec<CurrencyResponse>,
}

#[derive(Debug, Clone)]
pub struct CurrencyResponse {
    pub code: String,
}

#[derive(Debug, Clone)]
pub struct BtcAddressAndSumPayload {
    pub bill_id: String,
    pub address: String,
    pub sum: String,
}

#[derive(Debug, Clone)]
pub struct LinkToPayResponse {
    pub link_to_pay: String,
}

#[derive(Debug, Clone)]
pub struct BtcAddressPayload {
    pub address: String,
}

#[derive(Debug, Clone)]
pub struct MempoolLinkResponse {
    pub mempool_link: String,
}

#[derive(Debug, Clone)]
pub struct CreateOptionalPostalAddressFfi {
    pub country: Option<String>,
    pub city: Option<String>,
    pub zip: Option<String>,
    pub address: Option<String>,
}

impl CreateOptionalPostalAddressFfi {
    pub fn is_none(&self) -> bool {
        self.country.is_none()
            && self.city.is_none()
            && self.zip.is_none()
            && self.address.is_none()
    }
}

impl TryFrom<CreateOptionalPostalAddressFfi> for OptionalPostalAddressFfi {
    type Error = ValidationError;

    fn try_from(value: CreateOptionalPostalAddressFfi) -> Result<Self, Self::Error> {
        Ok(OptionalPostalAddressFfi {
            country: value
                .country
                .map(|c| Country::parse(&c))
                .transpose()?
                .map(|c| c.to_string()),
            city: value
                .city
                .map(City::new)
                .transpose()?
                .map(|c| c.to_string()),
            zip: value.zip.map(Zip::new).transpose()?.map(|c| c.to_string()),
            address: value
                .address
                .map(Address::new)
                .transpose()?
                .map(|c| c.to_string()),
        })
    }
}

#[derive(Debug, Clone)]
pub struct OptionalPostalAddressFfi {
    pub country: Option<String>,
    pub city: Option<String>,
    pub zip: Option<String>,
    pub address: Option<String>,
}

impl OptionalPostalAddressFfi {
    pub fn is_none(&self) -> bool {
        self.country.is_none()
            && self.city.is_none()
            && self.zip.is_none()
            && self.address.is_none()
    }
}

impl TryFrom<OptionalPostalAddressFfi> for OptionalPostalAddress {
    type Error = ProtocolValidationError;
    fn try_from(value: OptionalPostalAddressFfi) -> Result<Self, Self::Error> {
        Ok(Self {
            country: value.country.map(|c| Country::parse(&c)).transpose()?,
            city: value.city.map(City::new).transpose()?,
            zip: value.zip.map(Zip::new).transpose()?,
            address: value.address.map(Address::new).transpose()?,
        })
    }
}

impl From<OptionalPostalAddress> for OptionalPostalAddressFfi {
    fn from(value: OptionalPostalAddress) -> Self {
        Self {
            country: value.country.map(|c| c.to_string()),
            city: value.city.map(|c| c.to_string()),
            zip: value.zip.map(|c| c.to_string()),
            address: value.address.map(|c| c.to_string()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CreatePostalAddressFfi {
    pub country: String,
    pub city: String,
    pub zip: Option<String>,
    pub address: String,
}

#[derive(Debug, Clone)]
pub struct PostalAddressFfi {
    pub country: String,
    pub city: String,
    pub zip: Option<String>,
    pub address: String,
}

impl TryFrom<CreatePostalAddressFfi> for PostalAddressFfi {
    type Error = ValidationError;

    fn try_from(value: CreatePostalAddressFfi) -> Result<Self, Self::Error> {
        Ok(PostalAddressFfi {
            country: Country::parse(&value.country)?.to_string(),
            city: City::new(&value.city)?.to_string(),
            zip: value.zip.map(Zip::new).transpose()?.map(|c| c.to_string()),
            address: Address::new(&value.address)?.to_string(),
        })
    }
}

impl TryFrom<PostalAddressFfi> for PostalAddress {
    type Error = ProtocolValidationError;
    fn try_from(value: PostalAddressFfi) -> Result<Self, Self::Error> {
        Ok(Self {
            country: Country::parse(&value.country)?,
            city: City::new(&value.city)?,
            zip: value.zip.map(Zip::new).transpose()?,
            address: Address::new(&value.address)?,
        })
    }
}

impl From<PostalAddress> for PostalAddressFfi {
    fn from(val: PostalAddress) -> Self {
        PostalAddressFfi {
            country: val.country.to_string(),
            city: val.city.to_string(),
            zip: val.zip.map(|c| c.to_string()),
            address: val.address.to_string(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct NotificationFiltersFfi {
    pub active: Option<bool>,
    pub reference_id: Option<String>,
    pub notification_type: Option<String>,
    pub level: Option<String>,
    pub node_ids: Option<Vec<String>>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

impl TryFrom<NotificationFiltersFfi> for NotificationFilter {
    type Error = ProtocolValidationError;
    fn try_from(value: NotificationFiltersFfi) -> Result<Self, Self::Error> {
        Ok(Self {
            active: value.active,
            reference_id: value.reference_id,
            notification_type: value.notification_type,
            node_ids: match value.node_ids {
                Some(node_ids) => node_ids
                    .into_iter()
                    .map(|ni| NodeId::from_str(&ni))
                    .collect::<Result<_, _>>()?,
                None => vec![],
            },
            event_id: None,
            level: value.level,
            limit: value.limit,
            offset: value.offset,
        })
    }
}

#[derive(Debug, Clone)]
pub struct FileFfi {
    pub name: String,
    pub hash: String,
    pub nostr_hash: String,
}

impl TryFrom<FileFfi> for File {
    type Error = ProtocolValidationError;

    fn try_from(value: FileFfi) -> Result<Self, Self::Error> {
        Ok(Self {
            name: Name::new(value.name)?,
            hash: Sha256Hash::from_str(&value.hash)?,
            nostr_hash: Sha256HexHash::from_str(&value.nostr_hash)
                .map_err(|_| ProtocolValidationError::InvalidHash)?,
        })
    }
}

impl From<File> for FileFfi {
    fn from(val: File) -> Self {
        FileFfi {
            name: val.name.to_string(),
            hash: val.hash.to_string(),
            nostr_hash: val.nostr_hash.to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BinaryFileResponse {
    pub data: Vec<u8>,
    pub name: String,
    pub content_type: String,
}

#[derive(Debug, Clone)]
pub struct Base64FileResponse {
    pub data: String,
    pub name: String,
    pub content_type: String,
}

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
pub struct UploadFileResponse {
    pub file_upload_id: String,
}

impl From<UploadFileResult> for UploadFileResponse {
    fn from(val: UploadFileResult) -> Self {
        UploadFileResponse {
            file_upload_id: val.file_upload_id.to_string(),
        }
    }
}

/// Parses the given date of format YYYY-mm-dd to a UTC end-of-day timestamp
#[frb(ignore)]
pub fn parse_deadline_string(deadline_date: &str) -> Result<Timestamp, ValidationError> {
    let ts = Date::new(deadline_date)?.to_timestamp().end_of_day();
    Ok(ts)
}

#[derive(Debug, Clone)]
pub enum EditOptionalFieldModeFfi {
    Set(String),
    Unset,
    Ignore,
}

impl EditOptionalFieldModeFfi {
    pub fn try_map<U, E>(
        self,
        f: impl FnOnce(String) -> Result<U, E>,
    ) -> Result<EditOptionalFieldMode<U>, E> {
        match self {
            EditOptionalFieldModeFfi::Set(value) => f(value).map(EditOptionalFieldMode::Set),
            EditOptionalFieldModeFfi::Unset => Ok(EditOptionalFieldMode::Unset),
            EditOptionalFieldModeFfi::Ignore => Ok(EditOptionalFieldMode::Ignore),
        }
    }
}
