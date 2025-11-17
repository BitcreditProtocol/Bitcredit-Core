use async_trait::async_trait;
use bcr_common::core::{BillId, NodeId};
use bcr_ebill_core::application::ServiceTraitBounds;
use bcr_ebill_core::protocol::{Email, event::bill_events::BillEventType, mint::MintSignature};
use bitcoin::{XOnlyPublicKey, base58};
use borsh_derive::BorshSerialize;
use nostr::hashes::Hash;
use nostr::hashes::sha256;
use nostr::util::SECP256K1;
use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, Message, SecretKey};
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
    #[error("External Email Base58 Error: {0}")]
    Base58(#[from] base58::InvalidCharacterError),
    /// all signature errors
    #[error("External Email Signature Error: {0}")]
    Signature(#[from] secp256k1::Error),
    /// all borsh errors
    #[error("External Email Borsh Error")]
    Borsh(#[from] borsh::io::Error),
    #[error("External Email Invalid Mint Id Error")]
    InvalidMintId,
    #[error("External Email Invalid Mint Signature Error")]
    InvalidMintSignature,
}

#[cfg(test)]
use mockall::automock;

use crate::external::file_storage::to_url;

#[cfg_attr(test, automock)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait EmailClientApi: ServiceTraitBounds {
    /// Register for email notifications, returning an email preferences link
    async fn register(
        &self,
        mint_url: &url::Url,
        node_id: &NodeId,
        company_node_id: &Option<NodeId>,
        email: &Email,
        private_key: &SecretKey,
    ) -> Result<()>;
    /// Confirm email registration
    async fn confirm(
        &self,
        mint_url: &url::Url,
        mint_node_id: &NodeId,
        node_id: &NodeId,
        company_node_id: &Option<NodeId>,
        confirmation_code: &str,
        private_key: &SecretKey,
    ) -> Result<MintSignature>;
    /// Send a bill notification email
    async fn send_bill_notification(
        &self,
        mint_url: &url::Url,
        kind: BillEventType,
        id: &BillId,
        receiver: &NodeId,
        receiver_company_node_id: &Option<NodeId>,
        sender: &NodeId,
        private_key: &SecretKey,
    ) -> Result<()>;
    /// Get email preferences link
    async fn get_email_preferences_link(
        &self,
        mint_url: &url::Url,
        node_id: &NodeId,
        company_node_id: &Option<NodeId>,
        private_key: &SecretKey,
    ) -> Result<url::Url>;
}

#[derive(Debug, Clone, Default)]
pub struct EmailClient {
    cl: reqwest::Client,
}

impl EmailClient {
    pub fn new() -> Self {
        Self {
            cl: reqwest::Client::new(),
        }
    }

    async fn get_eic_challenge(&self, mint_url: &url::Url, node_id: &NodeId) -> Result<String> {
        let req = StartEmailRegisterRequest {
            node_id: node_id.to_owned(),
        };

        let resp: StartEmailRegisterResponse = self
            .cl
            .post(to_url(mint_url, "v1/eic/challenge")?)
            .json(&req)
            .send()
            .await?
            .json()
            .await?;

        Ok(resp.challenge)
    }

    async fn get_ens_challenge(&self, mint_url: &url::Url, node_id: &NodeId) -> Result<String> {
        let req = StartEmailRegisterRequest {
            node_id: node_id.to_owned(),
        };

        let resp: StartEmailRegisterResponse = self
            .cl
            .post(to_url(mint_url, "v1/ens/challenge")?)
            .json(&req)
            .send()
            .await?
            .json()
            .await?;

        Ok(resp.challenge)
    }
}

impl ServiceTraitBounds for EmailClient {}

#[cfg(test)]
impl ServiceTraitBounds for MockEmailClientApi {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl EmailClientApi for EmailClient {
    async fn register(
        &self,
        mint_url: &url::Url,
        node_id: &NodeId,
        company_node_id: &Option<NodeId>,
        email: &Email,
        private_key: &SecretKey,
    ) -> Result<()> {
        let challenge = self.get_eic_challenge(mint_url, node_id).await?;
        let decoded_challenge = base58::decode(&challenge).map_err(Error::Base58)?;

        let key_pair = Keypair::from_secret_key(SECP256K1, private_key);
        let msg = Message::from_digest_slice(&decoded_challenge).map_err(Error::Signature)?;
        let signed_challenge = SECP256K1.sign_schnorr(&msg, &key_pair);

        let req = RegisterEmailRequest {
            node_id: node_id.to_owned(),
            company_node_id: company_node_id.to_owned(),
            email: email.to_owned(),
            signed_challenge,
        };

        self.cl
            .post(to_url(mint_url, "v1/eic/email/register")?)
            .json(&req)
            .send()
            .await?
            .error_for_status()?;

        Ok(())
    }

    async fn confirm(
        &self,
        mint_url: &url::Url,
        mint_node_id: &NodeId,
        node_id: &NodeId,
        company_node_id: &Option<NodeId>,
        confirmation_code: &str,
        private_key: &SecretKey,
    ) -> Result<MintSignature> {
        let pl = EmailConfirmPayload {
            node_id: node_id.to_owned(),
            company_node_id: company_node_id.to_owned(),
            confirmation_code: confirmation_code.to_owned(),
        };

        let serialized = borsh::to_vec(&pl).map_err(Error::Borsh)?;
        let signature = sign_payload(&serialized, private_key);
        let payload = base58::encode(&serialized);

        let req = EmailConfirmRequest { payload, signature };

        let res: EmailConfirmResponse = self
            .cl
            .post(to_url(mint_url, "v1/eic/email/confirm")?)
            .json(&req)
            .send()
            .await?
            .json()
            .await?;

        if &res.mint_node_id != mint_node_id {
            return Err(Error::InvalidMintId.into());
        }

        let decoded_mint_sig = base58::decode(&res.payload).map_err(Error::Base58)?;

        if !verify_request(
            &decoded_mint_sig,
            &res.signature,
            &mint_node_id.pub_key().x_only_public_key().0,
        )? {
            return Err(Error::InvalidMintSignature.into());
        }

        let mint_sig: MintSignature = borsh::from_slice(&decoded_mint_sig).map_err(Error::Borsh)?;

        Ok(mint_sig)
    }

    async fn send_bill_notification(
        &self,
        mint_url: &url::Url,
        kind: BillEventType,
        id: &BillId,
        receiver: &NodeId,
        receiver_company_node_id: &Option<NodeId>,
        sender: &NodeId,
        private_key: &SecretKey,
    ) -> Result<()> {
        let pl = NotificationSendPayload {
            kind: kind.to_string(),
            id: id.to_string(),
            receiver_node_id: receiver.to_owned(),
            receiver_company_node_id: receiver_company_node_id.to_owned(),
            sender_node_id: sender.to_owned(),
        };

        let serialized = borsh::to_vec(&pl).map_err(Error::Borsh)?;
        let signature = sign_payload(&serialized, private_key);
        let payload = base58::encode(&serialized);

        let req = NotificationSendRequest { payload, signature };

        self.cl
            .post(to_url(mint_url, "notifications/v1/send")?)
            .json(&req)
            .send()
            .await?
            .error_for_status()?;

        Ok(())
    }

    async fn get_email_preferences_link(
        &self,
        mint_url: &url::Url,
        node_id: &NodeId,
        company_node_id: &Option<NodeId>,
        private_key: &SecretKey,
    ) -> Result<url::Url> {
        let challenge = self.get_ens_challenge(mint_url, node_id).await?;
        let decoded_challenge = base58::decode(&challenge).map_err(Error::Base58)?;

        let key_pair = Keypair::from_secret_key(SECP256K1, private_key);
        let msg = Message::from_digest_slice(&decoded_challenge).map_err(Error::Signature)?;
        let signed_challenge = SECP256K1.sign_schnorr(&msg, &key_pair);

        let req = GetEmailPreferencesLinkRequest {
            node_id: node_id.to_owned(),
            company_node_id: company_node_id.to_owned(),
            signed_challenge,
        };

        let res: GetEmailPreferencesLinkResponse = self
            .cl
            .post(to_url(mint_url, "v1/ens/email/preferences/link")?)
            .json(&req)
            .send()
            .await?
            .json()
            .await?;

        Ok(res.preferences_link)
    }
}

pub fn sign_payload(req: &[u8], private_key: &SecretKey) -> Signature {
    let key_pair = Keypair::from_secret_key(SECP256K1, private_key);
    let hash: sha256::Hash = sha256::Hash::hash(req);
    let req = Message::from_digest(*hash.as_ref());

    SECP256K1.sign_schnorr(&req, &key_pair)
}

pub fn verify_request(payload: &[u8], signature: &Signature, key: &XOnlyPublicKey) -> Result<bool> {
    let hash = sha256::Hash::hash(payload);
    let msg = Message::from_digest(*hash.as_ref());
    Ok(SECP256K1.verify_schnorr(signature, &msg, key).is_ok())
}

#[derive(Debug, Serialize)]
pub struct StartEmailRegisterRequest {
    pub node_id: NodeId,
}

#[derive(Debug, Deserialize)]
pub struct StartEmailRegisterResponse {
    pub challenge: String,
    pub ttl_seconds: u32,
}

#[derive(Debug, Serialize)]
pub struct RegisterEmailRequest {
    pub node_id: NodeId,
    pub company_node_id: Option<NodeId>,
    pub email: Email,
    pub signed_challenge: Signature,
}

#[derive(Debug, Serialize)]
pub struct EmailConfirmRequest {
    /// A borsh-encoded EmailConfirmPayload
    pub payload: String,
    /// The signature
    pub signature: Signature,
}

#[derive(Debug, BorshSerialize)]
pub struct EmailConfirmPayload {
    pub node_id: NodeId,
    pub company_node_id: Option<NodeId>,
    pub confirmation_code: String,
}

#[derive(Debug, Deserialize)]
pub struct EmailConfirmResponse {
    /// A borsh-encoded MintSignature
    pub payload: String,
    /// The mint signature of the payload
    pub signature: Signature,
    /// The mint node id
    pub mint_node_id: NodeId,
}

#[derive(Debug, Clone, Serialize)]
pub struct NotificationSendRequest {
    /// The payload for the notification, borsh-encoded NotificationSendPayload
    pub payload: String,
    /// The payload signed by the sender
    pub signature: Signature,
}

#[derive(Debug, Clone, BorshSerialize)]
pub struct NotificationSendPayload {
    pub kind: String,
    pub id: String,
    pub receiver_node_id: NodeId,
    pub receiver_company_node_id: Option<NodeId>,
    pub sender_node_id: NodeId,
}

#[derive(Debug, Deserialize)]
pub struct NotificationSendResponse {
    pub success: bool,
}

#[derive(Debug, Serialize)]
pub struct GetEmailPreferencesLinkRequest {
    pub node_id: NodeId,
    pub company_node_id: Option<NodeId>,
    pub signed_challenge: Signature,
}

#[derive(Debug, Deserialize)]
pub struct GetEmailPreferencesLinkResponse {
    pub preferences_link: url::Url,
}
