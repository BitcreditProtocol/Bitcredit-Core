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
