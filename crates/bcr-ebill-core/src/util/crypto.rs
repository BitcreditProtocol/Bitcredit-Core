use std::str::FromStr;

use crate::{bill::BillKeys, company::CompanyKeys};

use super::{base58_decode, base58_encode};
use bip39::Mnemonic;
use bitcoin::{
    Network,
    secp256k1::{
        self, Keypair, Message, PublicKey, SECP256K1, Scalar, SecretKey, rand, schnorr::Signature,
    },
};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Private key error: {0}")]
    PrivateKey(#[from] secp256k1::Error),

    #[error("Ecies encryption error: {0}")]
    Ecies(String),

    #[error("Signature had invalid length")]
    InvalidSignatureLength,

    #[error("Aggregated signature needs at least 2 keys")]
    TooFewKeys,

    /// Errors stemming from decoding base58
    #[error("Decode base58 error: {0}")]
    Decode(#[from] super::Error),

    /// Errors stemming from parsing the recovery id
    #[error("Parse recovery id error: {0}")]
    ParseRecoveryId(#[from] std::num::ParseIntError),

    #[error("Mnemonic seed phrase error {0}")]
    Mnemonic(#[from] bip39::Error),
}

// -------------------- Keypair --------------------------

/// A wrapper around the secp256k1 keypair that can be used for
/// Bitcoin and Nostr keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BcrKeys {
    inner: Keypair,
}

impl BcrKeys {
    /// Generates a fresh random keypair that can be used for
    /// Bitcoin and Nostr keys.
    pub fn new() -> Self {
        Self {
            inner: generate_keypair(),
        }
    }

    /// Generates a fresh random keypair including a seed phrase that
    /// can be used to recover the private_key
    pub fn new_with_seed_phrase() -> Result<(Self, String)> {
        let (seed_phrase, keypair) = generate_keypair_from_seed_phrase()?;
        let keys = Self { inner: keypair };
        Ok((keys, seed_phrase.to_string()))
    }

    /// Recovers keys from a given seedphrase
    pub fn from_seedphrase(seed: &str) -> Result<Self> {
        let recovered_keys = keypair_from_seed_phrase(seed)?;
        Ok(Self {
            inner: recovered_keys,
        })
    }

    /// Loads a keypair from a given private key string
    pub fn from_private_key(private_key: &SecretKey) -> Result<Self> {
        let keypair = load_keypair(private_key)?;
        Ok(Self { inner: keypair })
    }

    /// Returns the private key as a hex encoded string
    pub fn get_private_key_string(&self) -> String {
        self.inner.secret_key().display_secret().to_string()
    }

    /// Returns the private key
    pub fn get_private_key(&self) -> SecretKey {
        self.inner.secret_key()
    }

    pub fn pub_key(&self) -> PublicKey {
        self.inner.public_key()
    }

    /// Returns the public key as a hex encoded string
    pub fn get_public_key(&self) -> String {
        self.inner.public_key().to_string()
    }

    pub fn get_bitcoin_keys(
        &self,
        used_network: Network,
    ) -> (bitcoin::PrivateKey, bitcoin::PublicKey) {
        let private_key = self.get_bitcoin_private_key(used_network);
        (private_key, private_key.public_key(SECP256K1))
    }

    /// Returns the key pair as a bitcoin private key for the given network
    pub fn get_bitcoin_private_key(&self, used_network: Network) -> bitcoin::PrivateKey {
        bitcoin::PrivateKey::new(self.inner.secret_key(), used_network)
    }

    /// Returns the key pair as a nostr key pair
    pub fn get_nostr_keys(&self) -> nostr::Keys {
        nostr::Keys::new(self.inner.secret_key().into())
    }

    /// Returns the secp256k1 key pair
    pub fn get_key_pair(&self) -> Keypair {
        self.inner
    }
}

impl Default for BcrKeys {
    fn default() -> Self {
        Self::new()
    }
}

impl TryFrom<CompanyKeys> for BcrKeys {
    type Error = Error;

    fn try_from(keys: CompanyKeys) -> Result<Self> {
        BcrKeys::from_private_key(&keys.private_key)
    }
}

impl TryFrom<&CompanyKeys> for BcrKeys {
    type Error = Error;

    fn try_from(keys: &CompanyKeys) -> Result<Self> {
        BcrKeys::from_private_key(&keys.private_key)
    }
}

impl TryFrom<BillKeys> for BcrKeys {
    type Error = Error;

    fn try_from(keys: BillKeys) -> Result<Self> {
        BcrKeys::from_private_key(&keys.private_key)
    }
}

impl TryFrom<&BillKeys> for BcrKeys {
    type Error = Error;

    fn try_from(keys: &BillKeys) -> Result<Self> {
        BcrKeys::from_private_key(&keys.private_key)
    }
}

/// Number of words to use when generating BIP39 seed phrases
const BIP39_WORD_COUNT: usize = 12;

/// Generates a new keypair using the secp256k1 library
fn generate_keypair() -> Keypair {
    Keypair::new(SECP256K1, &mut rand::thread_rng())
}

/// Loads a secp256k1 keypair from a private key
fn load_keypair(private_key: &SecretKey) -> Result<Keypair> {
    let pair = Keypair::from_secret_key(SECP256K1, private_key);
    Ok(pair)
}

// -------------------- Aggregated Signatures --------------------------

/// Returns the combined public key for the given public keys
pub fn combine_pub_keys(pub_keys: &[PublicKey]) -> Result<PublicKey> {
    if pub_keys.len() < 2 {
        return Err(Error::TooFewKeys);
    }

    let combined_key = PublicKey::combine_keys(&pub_keys.iter().collect::<Vec<&PublicKey>>())?;
    Ok(combined_key)
}

/// Returns the aggregated public key for the given private keys
pub fn get_aggregated_public_key(private_keys: &[SecretKey]) -> Result<PublicKey> {
    if private_keys.len() < 2 {
        return Err(Error::TooFewKeys);
    }

    let key_pairs: Vec<Keypair> = private_keys
        .iter()
        .map(load_keypair)
        .collect::<Result<Vec<Keypair>>>()?;
    let public_keys: Vec<PublicKey> = key_pairs.into_iter().map(|kp| kp.public_key()).collect();

    let first_key = public_keys.first().ok_or(Error::TooFewKeys)?;
    let mut aggregated_key: PublicKey = first_key.to_owned();
    for key in public_keys.iter().skip(1) {
        aggregated_key = aggregated_key.combine(key)?;
    }
    Ok(aggregated_key)
}

/// The keys need to be in the correct order (identity -> company -> bill) to get the same
/// signature for the same keys
/// Public keys can be aggregated regardless of order
/// Returns the aggregated signature
pub fn aggregated_signature(hash: &str, keys: &[SecretKey]) -> Result<String> {
    if keys.len() < 2 {
        return Err(Error::TooFewKeys);
    }
    let key_pairs: Vec<Keypair> = keys
        .iter()
        .map(load_keypair)
        .collect::<Result<Vec<Keypair>>>()?;
    let secret_keys: Vec<SecretKey> = key_pairs.into_iter().map(|kp| kp.secret_key()).collect();

    let first_key = secret_keys.first().ok_or(Error::TooFewKeys)?;
    let mut aggregated_key: SecretKey = first_key.to_owned();
    for key in secret_keys.iter().skip(1) {
        aggregated_key = aggregated_key.add_tweak(&Scalar::from(*key))?;
    }

    let aggregated_key_pair = Keypair::from_secret_key(SECP256K1, &aggregated_key);
    let msg = Message::from_digest_slice(&base58_decode(hash)?)?;
    let signature = SECP256K1.sign_schnorr(&msg, &aggregated_key_pair);

    Ok(base58_encode(&signature.serialize()))
}

// -------------------- Signatures --------------------------

pub fn signature(hash: &str, private_key: &SecretKey) -> Result<String> {
    let key_pair = load_keypair(private_key)?;
    let msg = Message::from_digest_slice(&base58_decode(hash)?)?;
    let signature = SECP256K1.sign_schnorr(&msg, &key_pair);
    Ok(base58_encode(&signature.serialize()))
}

pub fn verify(hash: &str, signature: &str, public_key: &PublicKey) -> Result<bool> {
    let (pub_key, _) = public_key.x_only_public_key();
    let msg = Message::from_digest_slice(&base58_decode(hash)?)?;
    let decoded_signature = Signature::from_slice(&base58_decode(signature)?)?;
    Ok(SECP256K1
        .verify_schnorr(&decoded_signature, &msg, &pub_key)
        .is_ok())
}

// -------------------- Encryption --------------------------

/// Encrypt the given bytes with the given Secp256k1 key via ECIES
pub fn encrypt_ecies(bytes: &[u8], public_key: &PublicKey) -> Result<Vec<u8>> {
    let pub_key_bytes = public_key.serialize();
    let encrypted =
        ecies::encrypt(pub_key_bytes.as_slice(), bytes).map_err(|e| Error::Ecies(e.to_string()))?;
    Ok(encrypted)
}

/// Decrypt the given bytes with the given Secp256k1 key via ECIES
pub fn decrypt_ecies(bytes: &[u8], private_key: &SecretKey) -> Result<Vec<u8>> {
    let decrypted = ecies::decrypt(private_key.secret_bytes().as_slice(), bytes)
        .map_err(|e| Error::Ecies(e.to_string()))?;
    Ok(decrypted)
}

// ------------------------ BIP39 ---------------------------

/// Generate a new secp256k1 keypair using a 12 word seed phrase.
/// Returns both the keypair and the Mnemonic with the seed phrase.
fn generate_keypair_from_seed_phrase() -> Result<(Mnemonic, Keypair)> {
    let mnemonic = Mnemonic::generate(BIP39_WORD_COUNT)?;
    let keypair = keypair_from_mnemonic(&mnemonic)?;
    Ok((mnemonic, keypair))
}

/// Recover a key pair from a BIP39 seed phrase. Word count
/// and language are detected automatically.
fn keypair_from_seed_phrase(words: &str) -> Result<Keypair> {
    let mnemonic = Mnemonic::from_str(words)?;
    keypair_from_mnemonic(&mnemonic)
}

/// Recover a key pair from a BIP39 mnemonic.
fn keypair_from_mnemonic(mnemonic: &Mnemonic) -> Result<Keypair> {
    let seed = mnemonic.to_seed("");
    let (key, _) = seed.split_at(32);
    let secret = SecretKey::from_slice(key)?;
    Ok(Keypair::from_secret_key(SECP256K1, &secret))
}

#[cfg(test)]
mod tests {
    use nostr::nips::nip19::ToBech32;

    use super::*;
    use crate::util;

    fn priv_key() -> SecretKey {
        SecretKey::from_str("926a7ce0fdacad199307bcbbcda4869bca84d54b939011bafe6a83cb194130d3")
            .unwrap()
    }

    #[test]
    fn test_generate_keypair_and_seed_phrase_round_trip() {
        let (mnemonic, keypair) = generate_keypair_from_seed_phrase()
            .expect("Could not generate keypair and seed phrase");
        let recovered_keys = keypair_from_seed_phrase(&mnemonic.to_string())
            .expect("Could not recover private key from seed phrase");
        assert_eq!(keypair.secret_key(), recovered_keys.secret_key());
    }

    #[test]
    fn test_recover_keypair_from_seed_phrase_24_words() {
        // a valid pair of 24 words to priv key
        let words = "forward paper connect economy twelve debate cart isolate accident creek bind predict captain rifle glory cradle hip whisper wealth save buddy place develop dolphin";
        let priv_key = "f31e0373f6fa9f4835d49a278cd48f47ea115af7480edf435275a3c2dbb1f982";
        let keypair =
            keypair_from_seed_phrase(words).expect("Could not create keypair from seed phrase");
        let returned_priv_key = keypair.secret_key().display_secret().to_string();
        assert_eq!(priv_key, returned_priv_key);
    }

    #[test]
    fn test_recover_keypair_from_seed_phrase_12_words() {
        // a valid pair of 12 words to priv key
        let words = "oblige repair kind park dust act name myth cheap treat hammer arrive";
        let priv_key = "92f920d8e183cab62723c3a7eee9cb0b3edb3c4aad459f4062cfb7960b570662";
        let keypair =
            keypair_from_seed_phrase(words).expect("Could not create keypair from seed phrase");
        let returned_priv_key = keypair.secret_key().display_secret().to_string();
        assert_eq!(priv_key, returned_priv_key);
    }

    #[test]
    fn test_sign_verify() {
        let keypair = BcrKeys::new();
        let hash = util::sha256_hash("Hello, World".as_bytes());
        let signature = signature(&hash, &keypair.get_private_key()).unwrap();
        assert!(verify(&hash, &signature, &keypair.pub_key()).is_ok());
        assert!(verify(&hash, &signature, &keypair.pub_key()).unwrap());
    }

    #[test]
    fn test_sign_verify_invalid() {
        let keypair = BcrKeys::new();
        let hash = util::sha256_hash("Hello, World".as_bytes());
        let signature = signature(&hash, &keypair.get_private_key()).unwrap();
        let hash2 = util::sha256_hash("Hello, Changed Changed Changed World".as_bytes());
        assert!(verify(&hash, &signature, &keypair.pub_key()).is_ok());
        assert!(verify(&hash, &signature, &keypair.pub_key()).is_ok());
        // it fails for a different hash
        assert!(verify(&hash2, &signature, &keypair.pub_key()).is_ok());
        assert!(
            !verify(&hash2, &signature, &keypair.pub_key())
                .as_ref()
                .unwrap()
        );
    }

    #[test]
    fn test_sign_verify_aggregated() {
        let keypair1 = BcrKeys::new();
        let keypair2 = BcrKeys::new();
        let keys: Vec<SecretKey> = vec![keypair1.get_private_key(), keypair2.get_private_key()];
        let hash = util::sha256_hash("Hello, World".as_bytes());

        let public_key = get_aggregated_public_key(&keys).unwrap();
        let signature = aggregated_signature(&hash, &keys).unwrap();

        assert!(verify(&hash, &signature, &public_key).is_ok());
        assert!(verify(&hash, &signature, &public_key).unwrap());
    }

    #[test]
    fn test_sign_verify_aggregated_order_dependence() {
        let hash = util::sha256_hash("Hello, World".as_bytes());

        let keypair1 = BcrKeys::new();
        let keypair2 = BcrKeys::new();

        let keys: Vec<SecretKey> = vec![keypair1.get_private_key(), keypair2.get_private_key()];
        let public_key = get_aggregated_public_key(&keys).unwrap();
        let signature = aggregated_signature(&hash, &keys).unwrap();

        let keys2: Vec<SecretKey> = vec![keypair2.get_private_key(), keypair1.get_private_key()];
        let public_key2 = get_aggregated_public_key(&keys2).unwrap();
        let signature2 = aggregated_signature(&hash, &keys2).unwrap();

        assert_ne!(signature, signature2); // the signatures aren't the same
        assert_eq!(public_key, public_key2); // but the public keys are

        assert!(verify(&hash, &signature, &public_key).is_ok());
        assert!(verify(&hash, &signature, &public_key).unwrap());

        assert!(verify(&hash, &signature2, &public_key2).is_ok());
        assert!(verify(&hash, &signature2, &public_key2).unwrap());

        assert!(verify(&hash, &signature, &public_key2).is_ok());
        assert!(verify(&hash, &signature, &public_key2).unwrap());

        assert!(verify(&hash, &signature2, &public_key).is_ok());
        assert!(verify(&hash, &signature2, &public_key).unwrap());
    }

    #[test]
    fn test_sign_verify_aggregated_invalid() {
        let keypair1 = BcrKeys::new();
        let keypair2 = BcrKeys::new();
        let keys: Vec<SecretKey> = vec![keypair1.get_private_key(), keypair2.get_private_key()];
        let hash = util::sha256_hash("Hello, World".as_bytes());

        let public_key = get_aggregated_public_key(&keys).unwrap();
        let signature = aggregated_signature(&hash, &keys).unwrap();

        let changed_hash = util::sha256_hash("Hello Hello, World".as_bytes());
        assert!(verify(&changed_hash, &signature, &public_key).is_ok());
        assert!(!verify(&changed_hash, &signature, &public_key).unwrap());
    }

    #[test]
    fn test_sign_verify_aggregated_invalid_only_one_pubkey() {
        let keypair1 = BcrKeys::new();
        let keypair2 = BcrKeys::new();
        let keys: Vec<SecretKey> = vec![keypair1.get_private_key(), keypair2.get_private_key()];
        let hash = util::sha256_hash("Hello, World".as_bytes());
        let signature = aggregated_signature(&hash, &keys).unwrap();
        assert!(verify(&hash, &signature, &keypair2.pub_key()).is_ok());
        assert!(!verify(&hash, &signature, &keypair2.pub_key()).unwrap());
    }

    #[test]
    fn test_sign_verify_aggregated_multiple() {
        let keypair1 = BcrKeys::new();
        let keypair2 = BcrKeys::new();
        let keypair3 = BcrKeys::new();
        let keys: Vec<SecretKey> = vec![
            keypair1.get_private_key(),
            keypair2.get_private_key(),
            keypair3.get_private_key(),
        ];
        let hash = util::sha256_hash("Hello, World".as_bytes());
        let public_key = get_aggregated_public_key(&keys).unwrap();
        let signature = aggregated_signature(&hash, &keys).unwrap();
        assert!(verify(&hash, &signature, &public_key).is_ok());
        assert!(verify(&hash, &signature, &public_key).unwrap());
    }

    #[test]
    fn test_sign_verify_aggregated_multiple_manually_combined_pubkeys_for_verify() {
        let keypair1 = BcrKeys::new();
        let keypair2 = BcrKeys::new();
        let keypair3 = BcrKeys::new();
        let keys: Vec<SecretKey> = vec![
            keypair1.get_private_key(),
            keypair2.get_private_key(),
            keypair3.get_private_key(),
        ];
        let hash = util::sha256_hash("Hello, World".as_bytes());
        let public_key = get_aggregated_public_key(&keys).unwrap();
        let signature = aggregated_signature(&hash, &keys).unwrap();

        let combined_pub_key = keypair1
            .inner
            .public_key()
            .combine(&keypair2.inner.public_key())
            .unwrap()
            .combine(&keypair3.inner.public_key())
            .unwrap();

        assert_eq!(public_key, combined_pub_key);
        assert!(verify(&hash, &signature, &combined_pub_key).is_ok());
        assert!(verify(&hash, &signature, &combined_pub_key).unwrap());
    }

    #[test]
    fn test_sign_verify_aggregated_manually_combined_pubkeys_for_verify() {
        let keypair1 = BcrKeys::new();
        let keypair2 = BcrKeys::new();
        let keys: Vec<SecretKey> = vec![keypair1.get_private_key(), keypair2.get_private_key()];
        let hash = util::sha256_hash("Hello, World".as_bytes());
        let public_key = get_aggregated_public_key(&keys).unwrap();
        let signature = aggregated_signature(&hash, &keys).unwrap();

        let combined_pub_key = keypair1
            .inner
            .public_key()
            .combine(&keypair2.inner.public_key())
            .unwrap();

        assert_eq!(public_key, combined_pub_key);
        assert!(verify(&hash, &signature, &combined_pub_key).is_ok());
        assert!(verify(&hash, &signature, &combined_pub_key).unwrap());
    }

    #[test]
    fn test_sign_verify_aggregated_manually_combined_pubkeys_for_verify_different_order_also_works()
    {
        let keypair1 = BcrKeys::new();
        let keypair2 = BcrKeys::new();
        let keys: Vec<SecretKey> = vec![keypair1.get_private_key(), keypair2.get_private_key()];
        let hash = util::sha256_hash("Hello, World".as_bytes());
        let public_key = get_aggregated_public_key(&keys).unwrap();
        let signature = aggregated_signature(&hash, &keys).unwrap();

        let combined_pub_key = keypair2
            .inner
            .public_key()
            .combine(&keypair1.inner.public_key())
            .unwrap();
        assert_eq!(public_key, combined_pub_key);
        assert!(verify(&hash, &signature, &combined_pub_key).is_ok());
        assert!(verify(&hash, &signature, &combined_pub_key).unwrap());
    }

    #[test]
    fn test_sign_verify_aggregated_manually_combined_pubkeys_for_verify_invalid_pubkey() {
        let keypair1 = BcrKeys::new();
        let keypair2 = BcrKeys::new();
        let keypair3 = BcrKeys::new();
        let keys: Vec<SecretKey> = vec![keypair1.get_private_key(), keypair2.get_private_key()];
        let hash = util::sha256_hash("Hello, World".as_bytes());
        let public_key = get_aggregated_public_key(&keys).unwrap();
        let signature = aggregated_signature(&hash, &keys).unwrap();

        let combined_pub_key = combine_pub_keys(&[keypair1.pub_key(), keypair3.pub_key()]).unwrap();
        let combined_correct_pub_key =
            combine_pub_keys(&[keypair1.pub_key(), keypair2.pub_key()]).unwrap();
        assert_ne!(public_key, combined_pub_key);
        assert_eq!(public_key, combined_correct_pub_key);
        assert!(verify(&hash, &signature, &combined_pub_key).is_ok());
        assert!(verify(&hash, &signature, &combined_correct_pub_key).is_ok());
        assert!(!verify(&hash, &signature, &combined_pub_key).unwrap());
    }

    #[test]
    fn test_combine_pub_keys_baseline() {
        let keypair1 = BcrKeys::new();
        let keypair2 = BcrKeys::new();
        let keypair3 = BcrKeys::new();
        let combined_pub_key =
            combine_pub_keys(&[keypair1.pub_key(), keypair2.pub_key(), keypair3.pub_key()])
                .unwrap();
        let combined_pub_key_diff_order =
            combine_pub_keys(&[keypair2.pub_key(), keypair1.pub_key(), keypair3.pub_key()])
                .unwrap();
        // when combining public keys, the order isn't important
        assert_eq!(combined_pub_key, combined_pub_key_diff_order);
    }

    #[test]
    fn test_combine_pub_keys_too_few() {
        let keypair1 = BcrKeys::new();
        let combined_pub_key = combine_pub_keys(&[keypair1.pub_key()]);
        assert!(combined_pub_key.is_err());
    }

    #[test]
    fn test_new_keypair() {
        let keypair = BcrKeys::new();
        assert!(!keypair.get_private_key_string().is_empty());
        assert!(!keypair.get_public_key().is_empty());
        assert!(
            !keypair
                .get_bitcoin_private_key(Network::Bitcoin)
                .to_string()
                .is_empty()
        );
        assert!(keypair.get_nostr_keys().public_key().to_bech32().is_ok());
    }

    #[test]
    fn test_load_keypair() {
        let keypair = BcrKeys::from_private_key(&priv_key()).unwrap();
        let keypair2 = BcrKeys::from_private_key(&priv_key()).unwrap();
        assert_eq!(
            keypair.get_private_key_string(),
            keypair2.get_private_key_string()
        );
        assert_eq!(keypair.get_public_key(), keypair2.get_public_key());
        assert_eq!(
            keypair.get_bitcoin_private_key(Network::Bitcoin),
            keypair2.get_bitcoin_private_key(Network::Bitcoin)
        );
        assert_eq!(keypair.get_nostr_keys(), keypair2.get_nostr_keys());
    }

    #[test]
    fn encrypt_decrypt_ecies_basic() {
        let msg = "Hello, this is a very important message!"
            .to_string()
            .into_bytes();
        let keypair = BcrKeys::new();

        let encrypted = encrypt_ecies(&msg, &keypair.pub_key());
        assert!(encrypted.is_ok());
        let decrypted = decrypt_ecies(encrypted.as_ref().unwrap(), &keypair.get_private_key());
        assert!(decrypted.is_ok());

        assert_eq!(&msg, decrypted.as_ref().unwrap());
    }

    #[test]
    fn encrypt_decrypt_ecies_hardcoded_creds() {
        let msg = "Important!".to_string().into_bytes();

        let encrypted = encrypt_ecies(
            &msg,
            &PublicKey::from_str(
                "03205b8dec12bc9e879f5b517aa32192a2550e88adcee3e54ec2c7294802568fef",
            )
            .unwrap(),
        );
        assert!(encrypted.is_ok());
        let decrypted = decrypt_ecies(
            encrypted.as_ref().unwrap(),
            &SecretKey::from_str(
                "8863c82829480536893fc49c4b30e244f97261e989433373d73c648c1a656a79",
            )
            .unwrap(),
        );
        assert!(decrypted.is_ok());

        assert_eq!(&msg, decrypted.as_ref().unwrap());
    }

    #[test]
    fn get_key_pair() {
        let keys = BcrKeys::new();
        let key_pair = keys.get_key_pair();
        let pub_key = key_pair.public_key().to_string();
        assert_eq!(keys.get_public_key(), pub_key);
    }
}
