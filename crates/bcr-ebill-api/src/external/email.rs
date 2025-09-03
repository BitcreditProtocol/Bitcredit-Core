use async_trait::async_trait;
use bcr_ebill_core::{NodeId, ServiceTraitBounds, bill::BillId, notification::BillEventType};
use borsh_derive::BorshSerialize;
use nostr::hashes::Hash;
use nostr::util::SECP256K1;
use nostr::{hashes::sha256, nips::nip19::ToBech32};
use secp256k1::{Keypair, Message};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Generic result type
pub type Result<T> = std::result::Result<T, super::Error>;

/// Generic error type
#[derive(Debug, Error)]
pub enum Error {
    /// all errors originating from interacting with the web api
    #[error("External Email Web API error: {0}")]
    Api(#[from] reqwest::Error),
    /// all errors originating from invalid urls
    #[error("External Email Invalid Relay Url Error")]
    InvalidRelayUrl,
    /// all hex errors
    #[error("External Email Hex Error: {0}")]
    Hex(#[from] hex::FromHexError),
    /// all signature errors
    #[error("External Email Signature Error: {0}")]
    Signature(#[from] secp256k1::Error),
    /// all nostr key  errors
    #[error("External Email Nostr Key Error")]
    NostrKey,
    /// all borsh errors
    #[error("External Email Borsh Error")]
    Borsh(#[from] borsh::io::Error),
}

#[cfg(test)]
use mockall::automock;

use crate::{external::file_storage::to_url, get_config};

#[cfg_attr(test, automock)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait EmailClientApi: ServiceTraitBounds {
    /// Start register flow, receiving a challenge string
    async fn start(&self, relay_url: &str, npub: &str) -> Result<StartEmailRegisterResponse>;
    /// Register for email notifications
    async fn register(
        &self,
        relay_url: &str,
        email: &str,
        private_key: &nostr::SecretKey,
        challenge: &str,
    ) -> Result<RegisterEmailNotificationResponse>;
    /// Send a bill notification email
    async fn send_bill_notification(
        &self,
        relay_url: &str,
        kind: BillEventType,
        id: &BillId,
        receiver: &NodeId,
        private_key: &nostr::SecretKey,
    ) -> Result<()>;
}

#[derive(Debug, Clone, Default)]
pub struct EmailClient {
    cl: reqwest::Client,
}

impl ServiceTraitBounds for EmailClient {}

#[cfg(test)]
impl ServiceTraitBounds for MockEmailClientApi {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl EmailClientApi for EmailClient {
    async fn start(&self, relay_url: &str, npub: &str) -> Result<StartEmailRegisterResponse> {
        let req = StartEmailRegisterRequest {
            npub: npub.to_owned(),
        };

        let resp: StartEmailRegisterResponse = self
            .cl
            .post(to_url(relay_url, "notifications/v1/start")?)
            .json(&req)
            .send()
            .await?
            .json()
            .await?;

        Ok(resp)
    }

    async fn register(
        &self,
        relay_url: &str,
        email: &str,
        private_key: &nostr::SecretKey,
        challenge: &str,
    ) -> Result<RegisterEmailNotificationResponse> {
        let key_pair = Keypair::from_secret_key(SECP256K1, private_key);
        let msg = Message::from_digest_slice(&hex::decode(challenge).map_err(Error::Hex)?)
            .map_err(Error::Signature)?;
        let signed_challenge = SECP256K1.sign_schnorr(&msg, &key_pair).to_string();

        let npub = nostr::Keys::new(private_key.clone())
            .public_key()
            .to_bech32()
            .map_err(|_| Error::NostrKey)?;

        let req = RegisterEmailNotificationRequest {
            email: email.to_owned(),
            ebill_url: get_config().app_url.to_owned(),
            npub,
            signed_challenge,
        };

        let resp: RegisterEmailNotificationResponse = self
            .cl
            .post(to_url(relay_url, "notifications/v1/register")?)
            .json(&req)
            .send()
            .await?
            .json()
            .await?;

        Ok(resp)
    }

    async fn send_bill_notification(
        &self,
        relay_url: &str,
        kind: BillEventType,
        id: &BillId,
        receiver: &NodeId,
        private_key: &nostr::SecretKey,
    ) -> Result<()> {
        let sender_npub = nostr::Keys::new(private_key.clone())
            .public_key()
            .to_bech32()
            .map_err(|_| Error::NostrKey)?;

        let payload = SendEmailNotificationPayload {
            kind: kind.to_string(),
            id: id.to_string(),
            sender: sender_npub,
            receiver: receiver.npub().to_bech32().map_err(|_| Error::NostrKey)?,
        };

        let key_pair = Keypair::from_secret_key(SECP256K1, private_key);
        let serialized = borsh::to_vec(&payload).map_err(Error::Borsh)?;
        let hash: sha256::Hash = sha256::Hash::hash(&serialized);
        let msg = Message::from_digest(*hash.as_ref());

        let signature = SECP256K1.sign_schnorr(&msg, &key_pair).to_string();

        let req = SendEmailNotificationRequest { payload, signature };

        self.cl
            .post(to_url(relay_url, "notifications/v1/send")?)
            .json(&req)
            .send()
            .await?
            .error_for_status()?;

        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub struct StartEmailRegisterRequest {
    pub npub: String,
}

#[derive(Debug, Deserialize)]
pub struct StartEmailRegisterResponse {
    pub challenge: String,
    pub ttl_seconds: u32,
}

#[derive(Debug, Serialize)]
pub struct RegisterEmailNotificationRequest {
    pub email: String,
    pub ebill_url: url::Url,
    pub npub: String,
    pub signed_challenge: String,
}

#[derive(Debug, Deserialize)]
pub struct RegisterEmailNotificationResponse {
    pub preferences_token: String,
}

#[derive(Debug, Serialize)]
pub struct SendEmailNotificationRequest {
    pub payload: SendEmailNotificationPayload,
    pub signature: String,
}

#[derive(Debug, Serialize, BorshSerialize)]
pub struct SendEmailNotificationPayload {
    pub kind: String,
    pub id: String,
    pub sender: String,
    pub receiver: String,
}
