use async_trait::async_trait;
use bcr_ebill_core::{
    PostalAddress, ServiceTraitBounds,
    bill::BitcreditBill,
    contact::{BillAnonParticipant, BillIdentParticipant, BillParticipant, ContactType},
    util::{BcrKeys, date::DateTimeUtc},
};
use bcr_wdc_webapi::quotes::{BillInfo, EnquireReply, EnquireRequest, StatusReply};
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
    /// all errors originating invalid dates
    #[error("External Mint Invalid Date Error")]
    InvalidDate,
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
}

#[derive(Debug, Clone, Default)]
pub struct MintClient {
    cl: reqwest::Client,
}

impl ServiceTraitBounds for MintClient {}

#[cfg(test)]
impl ServiceTraitBounds for MockMintClientApi {}

impl MintClient {
    pub fn new() -> Self {
        Self {
            cl: reqwest::Client::new(),
        }
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

        let signature = bcr_wdc_utils::keys::schnorr_sign_borsh_msg_with_key(
            &bill_info,
            &requester_keys.get_key_pair(),
        )
        .map_err(|_| Error::Signature)?;

        let payload: EnquireRequest = EnquireRequest {
            content: bill_info,
            signature,
            public_key,
        };
        let url = format!("{}/v1/mint/credit/quote", mint_url);
        let res = self
            .cl
            .post(&url)
            .json(&payload)
            .send()
            .await
            .map_err(Error::from)?;
        let reply: EnquireReply = res.json().await.map_err(Error::from)?;
        Ok(reply.id.to_string())
    }

    async fn lookup_quote_for_mint(
        &self,
        mint_url: &str,
        quote_id: &str,
    ) -> Result<QuoteStatusReply> {
        let url = format!("{}/v1/mint/credit/quote/{quote_id}", mint_url);
        let res = self.cl.get(&url).send().await.map_err(Error::from)?;
        let reply: StatusReply = res.json().await.map_err(Error::from)?;
        Ok(reply.into())
    }
}

#[derive(Debug, Clone)]
pub enum QuoteStatusReply {
    Pending,
    Denied,
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
}

impl From<StatusReply> for QuoteStatusReply {
    fn from(value: StatusReply) -> Self {
        match value {
            StatusReply::Pending => QuoteStatusReply::Pending,
            StatusReply::Denied => QuoteStatusReply::Denied,
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
