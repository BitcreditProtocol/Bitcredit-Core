use std::str::FromStr;

use async_trait::async_trait;
use bcr_ebill_core::{
    PostalAddress, ServiceTraitBounds,
    bill::BitcreditBill,
    contact::{BillAnonParticipant, BillIdentParticipant, BillParticipant, ContactType},
    util::{BcrKeys, date::DateTimeUtc},
};
use bcr_wdc_quote_client::QuoteClient;
use bcr_wdc_webapi::quotes::{BillInfo, ResolveOffer, StatusReply};
use cashu::{nut01 as cdk01, nut02 as cdk02};
use thiserror::Error;

/// Generic result type
pub type Result<T> = std::result::Result<T, super::Error>;

/// Generic error type
#[derive(Debug, Error)]
pub enum Error {
    /// all errors originating from interacting with the web api
    #[error("External Mint Web API error: {0}")]
    Api(#[from] reqwest::Error),
    /// all errors originating from parsing public keys
    #[error("External Mint Public Key Error")]
    PubKey,
    /// all errors originating from creating signatures
    #[error("External Mint Signature Error")]
    Signature,
    /// all errors originating from invalid dates
    #[error("External Mint Invalid Date Error")]
    InvalidDate,
    /// all errors originating from invalid mint urls
    #[error("External Mint Invalid Mint Url Error")]
    InvalidMintUrl,
    /// all errors originating from invalid mint request ids
    #[error("External Mint Invalid Mint Request Id Error")]
    InvalidMintRequestId,
    /// all errors originating from the quote client
    #[error("External Mint Quote Client Error")]
    QuoteClient,
}

#[cfg(test)]
use mockall::automock;

use crate::util;

#[cfg_attr(test, automock)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait MintClientApi: ServiceTraitBounds {
    /// Request to mint a bill with a given mint
    async fn enquire_mint_quote(
        &self,
        mint_url: &str,
        requester_keys: &BcrKeys,
        bill: &BitcreditBill,
        endorsees: &[BillParticipant],
    ) -> Result<String>;
    /// Look up a quote for a mint
    async fn lookup_quote_for_mint(
        &self,
        mint_url: &str,
        quote_id: &str,
    ) -> Result<QuoteStatusReply>;
    /// Resolve quote from mint
    async fn resolve_quote_for_mint(
        &self,
        mint_url: &str,
        quote_id: &str,
        resolve: ResolveMintOffer,
    ) -> Result<()>;
    /// Cancel request to mint
    async fn cancel_quote_for_mint(&self, mint_url: &str, quote_id: &str) -> Result<()>;
}

#[derive(Debug, Clone, Default)]
pub struct MintClient {}

impl ServiceTraitBounds for MintClient {}

#[cfg(test)]
impl ServiceTraitBounds for MockMintClientApi {}

impl MintClient {
    pub fn new() -> Self {
        Self {}
    }

    pub fn quote_client(&self, mint_url: &str) -> Result<QuoteClient> {
        let quote_client = bcr_wdc_quote_client::QuoteClient::new(
            reqwest::Url::parse(mint_url).map_err(|_| Error::InvalidMintUrl)?,
        );
        Ok(quote_client)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl MintClientApi for MintClient {
    async fn enquire_mint_quote(
        &self,
        mint_url: &str,
        requester_keys: &BcrKeys,
        bill: &BitcreditBill,
        endorsees: &[BillParticipant],
    ) -> Result<String> {
        let bill_info = BillInfo {
            id: bill.id.clone(),
            drawee: map_bill_ident_participant(bill.drawee.to_owned()),
            drawer: map_bill_ident_participant(bill.drawer.to_owned()),
            payee: map_bill_participant(bill.payee.to_owned()),
            endorsees: endorsees
                .iter()
                .map(|e| map_bill_participant(e.to_owned()))
                .collect(),
            sum: bill.sum,
            maturity_date: util::date::date_string_to_rfc3339(&bill.maturity_date)
                .map_err(|_| Error::InvalidDate)?,
        };
        let public_key = cdk01::PublicKey::from_hex(requester_keys.get_public_key())
            .map_err(|_| Error::PubKey)?;

        let mint_request_id = self
            .quote_client(mint_url)?
            .enquire(bill_info, public_key, &requester_keys.get_key_pair())
            .await
            .map_err(|e| {
                log::error!("Error enquiring to mint {mint_url}: {e}");
                Error::QuoteClient
            })?;
        Ok(mint_request_id.to_string())
    }

    async fn lookup_quote_for_mint(
        &self,
        mint_url: &str,
        quote_id: &str,
    ) -> Result<QuoteStatusReply> {
        let reply = self
            .quote_client(mint_url)?
            .lookup(uuid::Uuid::from_str(quote_id).map_err(|_| Error::InvalidMintRequestId)?)
            .await
            .map_err(|e| {
                log::error!("Error looking up request on mint {mint_url}: {e}");
                Error::QuoteClient
            })?;
        Ok(reply.into())
    }

    async fn resolve_quote_for_mint(
        &self,
        mint_url: &str,
        quote_id: &str,
        resolve: ResolveMintOffer,
    ) -> Result<()> {
        self.quote_client(mint_url)?
            .resolve(
                uuid::Uuid::from_str(quote_id).map_err(|_| Error::InvalidMintRequestId)?,
                resolve.into(),
            )
            .await
            .map_err(|e| {
                log::error!("Error resolving request on mint {mint_url}: {e}");
                Error::QuoteClient
            })?;
        Ok(())
    }

    async fn cancel_quote_for_mint(&self, mint_url: &str, quote_id: &str) -> Result<()> {
        self.quote_client(mint_url)?
            .cancel(uuid::Uuid::from_str(quote_id).map_err(|_| Error::InvalidMintRequestId)?)
            .await
            .map_err(|e| {
                log::error!("Error cancelling request on mint {mint_url}: {e}");
                Error::QuoteClient
            })?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum ResolveMintOffer {
    Accept,
    Reject,
}

impl From<ResolveMintOffer> for ResolveOffer {
    fn from(value: ResolveMintOffer) -> Self {
        match value {
            ResolveMintOffer::Accept => ResolveOffer::Accept,
            ResolveMintOffer::Reject => ResolveOffer::Reject,
        }
    }
}

#[derive(Debug, Clone)]
pub enum QuoteStatusReply {
    Pending,
    Denied {
        tstamp: DateTimeUtc,
    },
    Offered {
        keyset_id: cdk02::Id,
        expiration_date: DateTimeUtc,
        discounted: bitcoin::Amount,
    },
    Accepted {
        keyset_id: cdk02::Id,
    },
    Rejected {
        tstamp: DateTimeUtc,
    },
    Cancelled {
        tstamp: DateTimeUtc,
    },
    Expired {
        tstamp: DateTimeUtc,
    },
}

impl From<StatusReply> for QuoteStatusReply {
    fn from(value: StatusReply) -> Self {
        match value {
            StatusReply::Pending => QuoteStatusReply::Pending,
            StatusReply::Denied { tstamp } => QuoteStatusReply::Denied { tstamp },
            StatusReply::Offered {
                keyset_id,
                expiration_date,
                discounted,
            } => QuoteStatusReply::Offered {
                keyset_id,
                expiration_date,
                discounted,
            },
            StatusReply::Accepted { keyset_id } => QuoteStatusReply::Accepted { keyset_id },
            StatusReply::Rejected { tstamp } => QuoteStatusReply::Rejected { tstamp },
            StatusReply::Canceled { tstamp } => QuoteStatusReply::Cancelled { tstamp },
            StatusReply::OfferExpired { tstamp } => QuoteStatusReply::Expired { tstamp },
        }
    }
}

// These are needed for now, because we use different `bcr-ebill-core` versions in wildcat and here
// this should be remediated, once we're stable on both sides

fn map_bill_participant(part: BillParticipant) -> bcr_wdc_webapi::bill::BillParticipant {
    match part {
        BillParticipant::Ident(data) => {
            bcr_wdc_webapi::bill::BillParticipant::Ident(map_bill_ident_participant(data))
        }
        BillParticipant::Anon(data) => {
            bcr_wdc_webapi::bill::BillParticipant::Anon(map_bill_anon_participant(data))
        }
    }
}

fn map_bill_anon_participant(
    ident: BillAnonParticipant,
) -> bcr_wdc_webapi::bill::BillAnonParticipant {
    bcr_wdc_webapi::bill::BillAnonParticipant {
        node_id: ident.node_id,
        email: ident.email,
        nostr_relays: ident.nostr_relays,
    }
}

fn map_bill_ident_participant(
    ident: BillIdentParticipant,
) -> bcr_wdc_webapi::bill::BillIdentParticipant {
    bcr_wdc_webapi::bill::BillIdentParticipant {
        t: map_contact_type(ident.t),
        node_id: ident.node_id,
        name: ident.name,
        postal_address: map_postal_address(ident.postal_address),
        email: ident.email,
        nostr_relays: ident.nostr_relays,
    }
}

fn map_contact_type(ct: ContactType) -> bcr_wdc_webapi::contact::ContactType {
    match ct {
        ContactType::Person => bcr_wdc_webapi::contact::ContactType::Person,
        ContactType::Company => bcr_wdc_webapi::contact::ContactType::Company,
        ContactType::Anon => bcr_wdc_webapi::contact::ContactType::Anon,
    }
}

fn map_postal_address(pa: PostalAddress) -> bcr_wdc_webapi::identity::PostalAddress {
    bcr_wdc_webapi::identity::PostalAddress {
        country: pa.country,
        city: pa.city,
        zip: pa.zip,
        address: pa.address,
    }
}
