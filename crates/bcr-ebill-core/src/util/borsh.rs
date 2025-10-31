use borsh::io::{ErrorKind, Read, Write};
use secp256k1::{PublicKey, SecretKey};
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

pub fn serialize_privkey<W: Write>(
    key: &SecretKey,
    writer: &mut W,
) -> std::result::Result<(), borsh::io::Error> {
    let privkey_str = key.display_secret().to_string();
    borsh::BorshSerialize::serialize(&privkey_str, writer)?;
    Ok(())
}

pub fn deserialize_privkey<R: Read>(
    reader: &mut R,
) -> std::result::Result<SecretKey, borsh::io::Error> {
    let privkey_str: String = borsh::BorshDeserialize::deserialize_reader(reader)?;
    let privkey = SecretKey::from_str(&privkey_str)
        .map_err(|e| borsh::io::Error::new(ErrorKind::InvalidInput, e))?;
    Ok(privkey)
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

pub fn serialize_url<W: std::io::Write>(url: &url::Url, writer: &mut W) -> std::io::Result<()> {
    let url_str: String = url.to_string();
    borsh::BorshSerialize::serialize(&url_str, writer)?;
    Ok(())
}

pub fn deserialize_url<R: std::io::Read>(reader: &mut R) -> std::io::Result<url::Url> {
    let url_str: String = borsh::BorshDeserialize::deserialize_reader(reader)?;
    let url = url::Url::from_str(&url_str)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(url)
}
