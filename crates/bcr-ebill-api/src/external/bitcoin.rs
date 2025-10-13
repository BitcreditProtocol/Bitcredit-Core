use crate::get_config;
use async_trait::async_trait;
use bcr_ebill_core::{
    PublicKey, ServiceTraitBounds,
    bill::{InMempoolData, PaidData, PaymentState},
    util,
};
use bitcoin::{Network, secp256k1::Scalar};
use log::debug;
use serde::Deserialize;
use thiserror::Error;
use tokio::alias::try_join;
use tokio_with_wasm as tokio;

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

    /// all errors originating from dealing with invalid data from the API
    #[error("Got invalid data from the API")]
    InvalidData(String),
}

#[cfg(test)]
use mockall::automock;

#[cfg_attr(test, automock)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait BitcoinClientApi: ServiceTraitBounds {
    async fn get_address_info(&self, address: &str) -> Result<AddressInfo>;

    async fn get_transactions(&self, address: &str) -> Result<Transactions>;

    async fn get_last_block_height(&self) -> Result<u64>;

    /// Checks payment by iterating over the transactions on the address in chronological order, until
    /// the target amount is filled, returning the respective payment status
    async fn check_payment_for_address(
        &self,
        address: &str,
        target_amount: u64,
    ) -> Result<PaymentState>;

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
                format!("{}api{path}", get_config().esplora_base_url)
            }
            Network::Regtest => {
                format!("{}regtest/api{path}", get_config().esplora_base_url)
            }
            _ => {
                // for testnet and testnet4
                format!("{}testnet/api{path}", get_config().esplora_base_url)
            }
        }
    }

    pub fn link_url(&self, path: &str) -> String {
        match get_config().bitcoin_network() {
            Network::Bitcoin => {
                format!("{}{path}", get_config().esplora_base_url)
            }
            Network::Regtest => {
                format!("{}regtest{path}", get_config().esplora_base_url)
            }
            _ => {
                // for testnet and testnet4
                format!("{}testnet{path}", get_config().esplora_base_url)
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

    async fn check_payment_for_address(
        &self,
        address: &str,
        target_amount: u64,
    ) -> Result<PaymentState> {
        debug!("checking if btc address {address} is paid {target_amount}");
        // in parallel, get current chain height, transactions and address info for the given address
        let (chain_block_height, txs) =
            try_join!(self.get_last_block_height(), self.get_transactions(address),)?;

        payment_state_from_transactions(chain_block_height, txs, address, target_amount)
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

fn payment_state_from_transactions(
    chain_block_height: u64,
    txs: Transactions,
    address: &str,
    target_amount: u64,
) -> Result<PaymentState> {
    // no transactions - no payment
    if txs.is_empty() {
        return Ok(PaymentState::NotFound);
    }

    let mut total = 0;
    let mut tx_filled = None;

    // sort from back to front (chronologically)
    for tx in txs.iter().rev() {
        for vout in tx.vout.iter() {
            // sum up outputs towards the address to check
            if let Some(ref addr) = vout.scriptpubkey_address
                && addr == address
            {
                total += vout.value;
            }
        }
        // if the current transaction covers the amount, we save it and break
        if total >= target_amount {
            tx_filled = Some(tx.to_owned());
            break;
        }
    }

    match tx_filled {
        Some(tx) => {
            // in mem pool
            if !tx.status.confirmed {
                debug!("payment for {address} is in mem pool {}", tx.txid);
                Ok(PaymentState::InMempool(InMempoolData { tx_id: tx.txid }))
            } else {
                match (
                    tx.status.block_height,
                    tx.status.block_time,
                    tx.status.block_hash,
                ) {
                    (Some(block_height), Some(block_time), Some(block_hash)) => {
                        let confirmations = chain_block_height - block_height + 1;
                        let paid_data = PaidData {
                            block_time,
                            block_hash,
                            confirmations,
                            tx_id: tx.txid,
                        };
                        if confirmations
                            >= get_config().payment_config.num_confirmations_for_payment as u64
                        {
                            // paid and confirmed
                            debug!(
                                "payment for {address} is paid and confirmed with {confirmations} confirmations"
                            );
                            Ok(PaymentState::PaidConfirmed(paid_data))
                        } else {
                            // paid but not enough confirmations yet
                            debug!(
                                "payment for {address} is paid and unconfirmed with {confirmations} confirmations"
                            );
                            Ok(PaymentState::PaidUnconfirmed(paid_data))
                        }
                    }
                    _ => {
                        log::error!(
                            "Invalid data when checking payment for {address} - confirmed tx, but no metadata"
                        );
                        Err(Error::InvalidData(format!("Invalid data when checking payment for {address} - confirmed tx, but no metadata")).into())
                    }
                }
            }
        }
        None => {
            // not enough funds to cover amount
            debug!(
                "Not enough funds to cover {target_amount} yet when checking payment for {address}: {total}"
            );
            Ok(PaymentState::NotFound)
        }
    }
}

/// Fields documented at https://github.com/Blockstream/esplora/blob/master/API.md#addresses
#[derive(Deserialize, Debug, Clone)]
pub struct AddressInfo {
    pub chain_stats: Stats,
    pub mempool_stats: Stats,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Stats {
    pub funded_txo_sum: u64,
    pub spent_txo_sum: u64,
}

pub type Transactions = Vec<Tx>;

/// Available fields documented at https://github.com/Blockstream/esplora/blob/master/API.md#transactions
#[derive(Deserialize, Debug, Clone)]
pub struct Tx {
    pub txid: String,
    pub status: Status,
    pub vout: Vec<Vout>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Vout {
    pub value: u64,
    pub scriptpubkey_address: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Status {
    // Height of the block the tx is in
    pub block_height: Option<u64>,
    // Unix Timestamp
    pub block_time: Option<u64>,
    // Hash of the block the tx is in
    pub block_hash: Option<String>,
    // Whether it's in the mempool (false), or in a block (true)
    pub confirmed: bool,
}

#[cfg(test)]
pub mod tests {
    use crate::tests::tests::init_test_cfg;

    use super::*;

    #[test]
    fn test_payment_state_from_transactions() {
        init_test_cfg();
        let test_height = 4578915;
        let test_addr = "n4n9CNeCkgtEs8wukKEvWC78eEqK4A3E6d";
        let test_amount = 500;
        let mut test_tx = Tx {
            txid: "".into(),
            status: Status {
                block_height: Some(test_height - 7),
                block_time: Some(1731593927),
                block_hash: Some(
                    "000000000061ad7b0d52af77e5a9dbcdc421bf00e93992259f16b2cf2693c4b1".into(),
                ),
                confirmed: true,
            },
            vout: vec![Vout {
                value: 500,
                scriptpubkey_address: Some(test_addr.to_owned()),
            }],
        };

        let res_empty =
            payment_state_from_transactions(test_height, vec![], test_addr, test_amount);
        assert!(matches!(res_empty, Ok(PaymentState::NotFound)));

        let res_paid_confirmed = payment_state_from_transactions(
            test_height,
            vec![test_tx.clone()],
            test_addr,
            test_amount,
        );
        assert!(matches!(
            res_paid_confirmed,
            Ok(PaymentState::PaidConfirmed(..))
        ));

        test_tx.status.block_height = Some(test_height - 1); // only 2 confirmations
        let res_paid_unconfirmed = payment_state_from_transactions(
            test_height,
            vec![test_tx.clone()],
            test_addr,
            test_amount,
        );
        assert!(matches!(
            res_paid_unconfirmed,
            Ok(PaymentState::PaidUnconfirmed(..))
        ));

        test_tx.status.block_height = None;
        test_tx.status.block_time = None;
        test_tx.status.block_hash = None;
        let res_paid_confirmed_no_data = payment_state_from_transactions(
            test_height,
            vec![test_tx.clone()],
            test_addr,
            test_amount,
        );
        assert!(matches!(
            res_paid_confirmed_no_data,
            Err(super::super::Error::ExternalBitcoinApi(Error::InvalidData(
                ..
            )))
        ));

        test_tx.status.confirmed = false;
        let res_in_mem_pool = payment_state_from_transactions(
            test_height,
            vec![test_tx.clone()],
            test_addr,
            test_amount,
        );
        assert!(matches!(res_in_mem_pool, Ok(PaymentState::InMempool(..))));

        test_tx.vout[0].value = 200;
        let res_not_filled = payment_state_from_transactions(
            test_height,
            vec![test_tx.clone()],
            test_addr,
            test_amount,
        );
        assert!(matches!(res_not_filled, Ok(PaymentState::NotFound)));
    }
}
