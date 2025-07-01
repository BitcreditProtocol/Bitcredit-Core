use borsh::io::{ErrorKind, Read, Write};
use secp256k1::PublicKey;
use std::str::FromStr;

pub fn serialize_pubkey<W: Write>(
    key: &PublicKey,
    writer: &mut W,
) -> std::result::Result<(), borsh::io::Error> {
    let pubkey_str = key.to_string();
    borsh::BorshSerialize::serialize(&pubkey_str, writer)?;
    Ok(())
}

pub fn deserialize_pubkey<R: Read>(
    reader: &mut R,
) -> std::result::Result<PublicKey, borsh::io::Error> {
    let pubkey_str: String = borsh::BorshDeserialize::deserialize_reader(reader)?;
    let pubkey = PublicKey::from_str(&pubkey_str)
        .map_err(|e| borsh::io::Error::new(ErrorKind::InvalidInput, e))?;
    Ok(pubkey)
}

pub fn serialize_vec_url<W: std::io::Write>(
    vec: &[url::Url],
    writer: &mut W,
) -> std::io::Result<()> {
    let url_strs: Vec<String> = vec.iter().map(|u| u.to_string()).collect();
    borsh::BorshSerialize::serialize(&url_strs, writer)?;
    Ok(())
}

pub fn deserialize_vec_url<R: std::io::Read>(reader: &mut R) -> std::io::Result<Vec<url::Url>> {
    let url_strs: Vec<String> = borsh::BorshDeserialize::deserialize_reader(reader)?;
    url_strs
        .into_iter()
        .map(|s| {
            url::Url::from_str(&s)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        })
        .collect()
}
