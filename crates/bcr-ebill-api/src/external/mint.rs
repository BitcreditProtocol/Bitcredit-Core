use std::str::FromStr;

use async_trait::async_trait;
use bcr_ebill_core::{
    PostalAddress, ServiceTraitBounds,
    bill::BitcreditBill,
    contact::{BillAnonParticipant, BillIdentParticipant, BillParticipant, ContactType},
    util::{BcrKeys, date::DateTimeUtc},
};
use bcr_wdc_key_client::KeyClient;
use bcr_wdc_quote_client::QuoteClient;
use bcr_wdc_webapi::quotes::{BillInfo, ResolveOffer, StatusReply};
use cashu::{nut00 as cdk00, nut01 as cdk01, nut02 as cdk02};
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
    /// all errors originating from parsing private keys
    #[error("External Mint Private Key Error")]
    PrivateKey,
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
    /// all errors originating from invalid keyset ids
    #[error("External Mint Invalid KeySet Id Error")]
    InvalidKeySetId,
    /// all errors originating from blind message generation
    #[error("External Mint BlindMessage Error")]
    BlindMessage,
    /// all errors originating from the quote client
    #[error("External Mint Quote Client Error")]
    QuoteClient,
    /// all errors originating from the key client
    #[error("External Mint Key Client Error")]
    KeyClient,
}

#[cfg(test)]
use mockall::automock;

use crate::{constants::CURRENCY_CRSAT, util};

#[cfg_attr(test, automock)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait MintClientApi: ServiceTraitBounds {
    /// Mint and return encoded token
    async fn mint(
        &self,
        mint_url: &str,
        keyset: cdk02::KeySet,
        discounted_amount: u64,
        quote_id: &str,
        private_key: &str,
    ) -> Result<String>;
    /// Check keyset info for a given keyset id with a given mint
    async fn get_keyset_info(&self, mint_url: &str, keyset_id: &str) -> Result<cdk02::KeySet>;
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

    pub fn key_client(&self, mint_url: &str) -> Result<KeyClient> {
        let key_client = bcr_wdc_key_client::KeyClient::new(
            reqwest::Url::parse(mint_url).map_err(|_| Error::InvalidMintUrl)?,
        );
        Ok(key_client)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl MintClientApi for MintClient {
    async fn mint(
        &self,
        mint_url: &str,
        keyset: cdk02::KeySet,
        discounted_amount: u64,
        quote_id: &str,
        private_key: &str,
    ) -> Result<String> {
        let secret_key = cdk01::SecretKey::from_hex(private_key).map_err(|_| Error::PrivateKey)?;
        let qid = uuid::Uuid::from_str(quote_id).map_err(|_| Error::InvalidMintRequestId)?;

        // create blinded messages
        let amounts: Vec<cashu::Amount> = cashu::Amount::from(discounted_amount).split();
        let blinds = generate_blinds(keyset.id, &amounts)?;
        let blinded_messages = blinds.iter().map(|b| b.0.clone()).collect::<Vec<_>>();

        // mint
        let blinded_signatures = self
            .key_client(mint_url)?
            .mint(qid, blinded_messages, secret_key)
            .await
            .map_err(|e| {
                log::error!("Error minting at mint {mint_url}: {e}");
                Error::KeyClient
            })?;

        // create proofs
        let secrets = blinds.iter().map(|b| b.1.clone()).collect::<Vec<_>>();
        let rs = blinds.iter().map(|b| b.2.clone()).collect::<Vec<_>>();
        let proofs =
            cashu::dhke::construct_proofs(blinded_signatures, rs, secrets, &keyset.keys).unwrap();

        // generate token from proofs
        let mint_url = cashu::MintUrl::from_str(mint_url).map_err(|_| Error::InvalidMintUrl)?;
        let token = cdk00::Token::new(
            mint_url,
            proofs,
            None,
            cashu::CurrencyUnit::Custom(CURRENCY_CRSAT.into()),
        );

        Ok(token.to_v3_string())
    }

    async fn get_keyset_info(&self, mint_url: &str, keyset_id: &str) -> Result<cdk02::KeySet> {
        let base = reqwest::Url::parse(mint_url).map_err(|_| Error::InvalidMintUrl)?;
        let url = base
            .join(&format!("/v1/keys/{}", keyset_id))
            .expect("keys relative path");
        let res = reqwest::Client::new().get(url).send().await.map_err(|e| {
            log::error!("Error getting keyset info from mint {mint_url}: {e}");
            Error::KeyClient
        })?;
        let json: cdk01::KeysResponse = res.json().await.map_err(|e| {
            log::error!("Error deserializing keyset info: {e}");
            Error::KeyClient
        })?;
        json.keysets.first().map(|k| k.to_owned()).ok_or_else(|| {
            log::error!("Empty keyset");
            Error::KeyClient.into()
        })
    }

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

pub fn generate_blinds(
    keyset_id: cashu::Id,
    amounts: &[cashu::Amount],
) -> Result<
    Vec<(
        cashu::BlindedMessage,
        cashu::secret::Secret,
        cashu::SecretKey,
    )>,
> {
    let mut blinds = Vec::new();
    for amount in amounts {
        let blind = generate_blind(keyset_id, *amount)?;
        blinds.push(blind);
    }
    Ok(blinds)
}

pub fn generate_blind(
    kid: cashu::Id,
    amount: cashu::Amount,
) -> Result<(
    cashu::BlindedMessage,
    cashu::secret::Secret,
    cashu::SecretKey,
)> {
    let secret = cashu::secret::Secret::new(rand::random::<u64>().to_string());
    let (b_, r) =
        cashu::dhke::blind_message(secret.as_bytes(), None).map_err(|_| Error::BlindMessage)?;
    Ok((cashu::BlindedMessage::new(amount, kid, b_), secret, r))
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
