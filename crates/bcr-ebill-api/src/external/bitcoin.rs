use crate::get_config;
use async_trait::async_trait;
use bcr_ebill_core::{PublicKey, ServiceTraitBounds, util};
use bitcoin::{Network, secp256k1::Scalar};
use log::debug;
use serde::Deserialize;
use thiserror::Error;

/// Generic result type
pub type Result<T> = std::result::Result<T, super::Error>;

/// Generic error type
#[derive(Debug, Error)]
pub enum Error {
    /// all errors originating from interacting with the web api
    #[error("External Bitcoin Web API error: {0}")]
    Api(#[from] reqwest::Error),

    /// all errors originating from dealing with secp256k1 keys
    #[error("External Bitcoin Key error: {0}")]
    Key(#[from] bitcoin::secp256k1::Error),

    /// all errors originating from dealing with public secp256k1 keys
    #[error("External Bitcoin Public Key error: {0}")]
    PublicKey(String),

    /// all errors originating from dealing with private secp256k1 keys
    #[error("External Bitcoin Private Key error: {0}")]
    PrivateKey(String),
}

#[cfg(test)]
use mockall::automock;

#[cfg_attr(test, automock)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait BitcoinClientApi: ServiceTraitBounds {
    async fn get_address_info(&self, address: &str) -> Result<AddressInfo>;

    #[allow(dead_code)]
    async fn get_transactions(&self, address: &str) -> Result<Transactions>;

    #[allow(dead_code)]
    async fn get_last_block_height(&self) -> Result<u64>;

    #[allow(dead_code)]
    fn get_first_transaction(&self, transactions: &Transactions) -> Option<Txid>;

    async fn check_if_paid(&self, address: &str, sum: u64) -> Result<(bool, u64)>;

    fn get_address_to_pay(
        &self,
        bill_public_key: &PublicKey,
        holder_public_key: &PublicKey,
    ) -> Result<String>;

    fn generate_link_to_pay(&self, address: &str, sum: u64, message: &str) -> String;

    fn get_combined_private_descriptor(
        &self,
        pkey: &bitcoin::PrivateKey,
        pkey_to_combine: &bitcoin::PrivateKey,
    ) -> Result<String>;

    fn get_mempool_link_for_address(&self, address: &str) -> String;
}

#[derive(Clone)]
pub struct BitcoinClient {
    cl: reqwest::Client,
}

impl ServiceTraitBounds for BitcoinClient {}

#[cfg(test)]
impl ServiceTraitBounds for MockBitcoinClientApi {}

impl BitcoinClient {
    pub fn new() -> Self {
        Self {
            cl: reqwest::Client::new(),
        }
    }

    pub fn request_url(&self, path: &str) -> String {
        match get_config().bitcoin_network() {
            Network::Bitcoin => {
                format!("{}/api{path}", get_config().esplora_base_url)
            }
            Network::Regtest => {
                format!("{}/regtest/api{path}", get_config().esplora_base_url)
            }
            _ => {
                // for testnet and testnet4
                format!("{}/testnet/api{path}", get_config().esplora_base_url)
            }
        }
    }

    pub fn link_url(&self, path: &str) -> String {
        match get_config().bitcoin_network() {
            Network::Bitcoin => {
                format!("{}{path}", get_config().esplora_base_url)
            }
            Network::Regtest => {
                format!("{}/regtest{path}", get_config().esplora_base_url)
            }
            _ => {
                // for testnet and testnet4
                format!("{}/testnet{path}", get_config().esplora_base_url)
            }
        }
    }
}

impl Default for BitcoinClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl BitcoinClientApi for BitcoinClient {
    async fn get_address_info(&self, address: &str) -> Result<AddressInfo> {
        let address: AddressInfo = self
            .cl
            .get(self.request_url(&format!("/address/{address}")))
            .send()
            .await
            .map_err(Error::from)?
            .json()
            .await
            .map_err(Error::from)?;

        Ok(address)
    }

    async fn get_transactions(&self, address: &str) -> Result<Transactions> {
        let transactions: Transactions = self
            .cl
            .get(self.request_url(&format!("/address/{address}/txs")))
            .send()
            .await
            .map_err(Error::from)?
            .json()
            .await
            .map_err(Error::from)?;

        Ok(transactions)
    }

    async fn get_last_block_height(&self) -> Result<u64> {
        let height: u64 = self
            .cl
            .get(self.request_url("/blocks/tip/height"))
            .send()
            .await?
            .json()
            .await?;

        Ok(height)
    }

    fn get_first_transaction(&self, transactions: &Transactions) -> Option<Txid> {
        transactions.last().cloned()
    }

    async fn check_if_paid(&self, address: &str, sum: u64) -> Result<(bool, u64)> {
        debug!("checking if btc address {address} is paid {sum}");
        let info_about_address = self.get_address_info(address).await?;

        // the received and spent sum need to add up to the sum
        let received_sum = info_about_address.chain_stats.funded_txo_sum; // balance on address
        let spent_sum = info_about_address.chain_stats.spent_txo_sum; // money already spent

        // Tx is still in mem_pool (0 if it's already on the chain)
        let received_sum_mempool = info_about_address.mempool_stats.funded_txo_sum;
        let spent_sum_mempool = info_about_address.mempool_stats.spent_txo_sum;

        let sum_chain_mempool: u64 =
            received_sum + spent_sum + received_sum_mempool + spent_sum_mempool;
        if sum_chain_mempool >= sum {
            // if the received sum is higher than the sum we're looking
            // to get, it's OK
            Ok((true, received_sum + spent_sum)) // only return sum received on chain, so we don't
        // return a sum if it's in mempool
        } else {
            Ok((false, 0))
        }
    }

    fn get_address_to_pay(
        &self,
        bill_public_key: &PublicKey,
        holder_public_key: &PublicKey,
    ) -> Result<String> {
        let public_key_bill = bitcoin::CompressedPublicKey(*bill_public_key);
        let public_key_bill_holder = bitcoin::CompressedPublicKey(*holder_public_key);

        let public_key_bill = public_key_bill
            .0
            .combine(&public_key_bill_holder.0)
            .map_err(Error::from)?;
        let pub_key_bill = bitcoin::CompressedPublicKey(public_key_bill);

        Ok(bitcoin::Address::p2wpkh(&pub_key_bill, get_config().bitcoin_network()).to_string())
    }

    fn generate_link_to_pay(&self, address: &str, sum: u64, message: &str) -> String {
        let btc_sum = util::currency::sat_to_btc(sum);
        let link = format!("bitcoin:{address}?amount={btc_sum}&message={message}");
        link
    }

    fn get_combined_private_descriptor(
        &self,
        pkey: &bitcoin::PrivateKey,
        pkey_to_combine: &bitcoin::PrivateKey,
    ) -> Result<String> {
        let private_key_bill = pkey
            .inner
            .add_tweak(&Scalar::from(pkey_to_combine.inner))
            .map_err(|e| Error::PrivateKey(e.to_string()))?;
        let priv_key = bitcoin::PrivateKey::new(private_key_bill, get_config().bitcoin_network());
        let single = miniscript::descriptor::SinglePriv {
            key: priv_key,
            origin: None,
        };
        let desc_seckey = miniscript::descriptor::DescriptorSecretKey::Single(single);
        let desc_pubkey = desc_seckey.to_public(secp256k1::global::SECP256K1).unwrap();
        let kmap = miniscript::descriptor::KeyMap::from_iter(std::iter::once((
            desc_pubkey.clone(),
            desc_seckey,
        )));
        let desc = miniscript::Descriptor::new_wpkh(desc_pubkey).unwrap();
        Ok(desc.to_string_with_secret(&kmap))
    }

    fn get_mempool_link_for_address(&self, address: &str) -> String {
        self.link_url(&format!("/address/{address}"))
    }
}

/// Fields documented at https://github.com/Blockstream/esplora/blob/master/API.md#addresses
#[derive(Deserialize, Debug)]
pub struct AddressInfo {
    pub chain_stats: Stats,
    pub mempool_stats: Stats,
}

#[derive(Deserialize, Debug)]
pub struct Stats {
    pub funded_txo_sum: u64,
    pub spent_txo_sum: u64,
}

pub type Transactions = Vec<Txid>;

/// Available fields documented at https://github.com/Blockstream/esplora/blob/master/API.md#transactions
#[derive(Deserialize, Debug, Clone)]
#[allow(dead_code)]
pub struct Txid {
    pub status: Status,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug, Clone)]
pub struct Status {
    pub block_height: u64,
}
