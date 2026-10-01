use crate::{
    Error, Result,
    sql::{contact_type_from_db, contact_type_to_db, decode_file, decode_postal_address},
};
use bcr_common::core::NodeId;
use bcr_ebill_core::{
    application::contact::Contact,
    protocol::{Address, City, Country, Date, Email, Identification, Name, Sha256Hash, Zip},
};
use bitcoin::hashes::sha256::Hash as Sha256HexHash;
use sqlx::{FromRow, types::Text};

// SQL
pub(crate) const SELECT_ALL: &str = r#"
    SELECT
        node_id,
        contact_type,
        name,
        email,

        postal_address_country,
        postal_address_city,
        postal_address_zip,
        postal_address_address,

        date_of_birth_or_registration,
        country_of_birth_or_registration,
        city_of_birth_or_registration,
        identification_number,

        avatar_file_name,
        avatar_file_hash,
        avatar_file_nostr_hash,

        proof_document_file_name,
        proof_document_file_hash,
        proof_document_file_nostr_hash,

        nostr_relays,
        mint_url
    FROM contacts
"#;

pub(crate) const SELECT_ONE: &str = r#"
    SELECT
        node_id,
        contact_type,
        name,
        email,

        postal_address_country,
        postal_address_city,
        postal_address_zip,
        postal_address_address,

        date_of_birth_or_registration,
        country_of_birth_or_registration,
        city_of_birth_or_registration,
        identification_number,

        avatar_file_name,
        avatar_file_hash,
        avatar_file_nostr_hash,

        proof_document_file_name,
        proof_document_file_hash,
        proof_document_file_nostr_hash,

        nostr_relays,
        mint_url
    FROM contacts
    WHERE node_id = $1
"#;

pub(crate) const SEARCH: &str = r#"
    SELECT
        node_id,
        contact_type,
        name,
        email,

        postal_address_country,
        postal_address_city,
        postal_address_zip,
        postal_address_address,

        date_of_birth_or_registration,
        country_of_birth_or_registration,
        city_of_birth_or_registration,
        identification_number,

        avatar_file_name,
        avatar_file_hash,
        avatar_file_nostr_hash,

        proof_document_file_name,
        proof_document_file_hash,
        proof_document_file_nostr_hash,

        nostr_relays,
        mint_url
    FROM contacts
    WHERE LOWER(name) LIKE LOWER($1)
"#;

pub(crate) const INSERT: &str = r#"
    INSERT INTO contacts (
        node_id,
        contact_type,
        name,
        email,

        postal_address_country,
        postal_address_city,
        postal_address_zip,
        postal_address_address,

        date_of_birth_or_registration,
        country_of_birth_or_registration,
        city_of_birth_or_registration,
        identification_number,

        avatar_file_name,
        avatar_file_hash,
        avatar_file_nostr_hash,

        proof_document_file_name,
        proof_document_file_hash,
        proof_document_file_nostr_hash,

        nostr_relays,
        mint_url
    )
    VALUES (
        $1, $2, $3, $4,
        $5, $6, $7, $8,
        $9, $10, $11, $12,
        $13, $14, $15,
        $16, $17, $18,
        $19, $20
    )
"#;

pub(crate) const UPDATE: &str = r#"
    UPDATE contacts
    SET
        contact_type = $1,
        name = $2,
        email = $3,

        postal_address_country = $4,
        postal_address_city = $5,
        postal_address_zip = $6,
        postal_address_address = $7,

        date_of_birth_or_registration = $8,
        country_of_birth_or_registration = $9,
        city_of_birth_or_registration = $10,
        identification_number = $11,

        avatar_file_name = $12,
        avatar_file_hash = $13,
        avatar_file_nostr_hash = $14,

        proof_document_file_name = $15,
        proof_document_file_hash = $16,
        proof_document_file_nostr_hash = $17,

        nostr_relays = $18,
        mint_url = $19
    WHERE node_id = $20
"#;

pub(crate) const DELETE: &str = r#"
    DELETE FROM contacts
    WHERE node_id = $1
"#;

macro_rules! bind_insert {
    ($query:expr, $row:expr) => {
        $query
            .bind(&$row.node_id)
            .bind(&$row.contact_type)
            .bind(&$row.name)
            .bind(&$row.email)
            .bind(&$row.postal_address_country)
            .bind(&$row.postal_address_city)
            .bind(&$row.postal_address_zip)
            .bind(&$row.postal_address_address)
            .bind(&$row.date_of_birth_or_registration)
            .bind(&$row.country_of_birth_or_registration)
            .bind(&$row.city_of_birth_or_registration)
            .bind(&$row.identification_number)
            .bind(&$row.avatar_file_name)
            .bind(&$row.avatar_file_hash)
            .bind(&$row.avatar_file_nostr_hash)
            .bind(&$row.proof_document_file_name)
            .bind(&$row.proof_document_file_hash)
            .bind(&$row.proof_document_file_nostr_hash)
            .bind(&$row.nostr_relays)
            .bind(&$row.mint_url)
    };
}

pub(crate) use bind_insert;

macro_rules! bind_update {
    ($query:expr, $row:expr) => {
        $query
            .bind(&$row.contact_type)
            .bind(&$row.name)
            .bind(&$row.email)
            .bind(&$row.postal_address_country)
            .bind(&$row.postal_address_city)
            .bind(&$row.postal_address_zip)
            .bind(&$row.postal_address_address)
            .bind(&$row.date_of_birth_or_registration)
            .bind(&$row.country_of_birth_or_registration)
            .bind(&$row.city_of_birth_or_registration)
            .bind(&$row.identification_number)
            .bind(&$row.avatar_file_name)
            .bind(&$row.avatar_file_hash)
            .bind(&$row.avatar_file_nostr_hash)
            .bind(&$row.proof_document_file_name)
            .bind(&$row.proof_document_file_hash)
            .bind(&$row.proof_document_file_nostr_hash)
            .bind(&$row.nostr_relays)
            .bind(&$row.mint_url)
            .bind(&$row.node_id)
    };
}

pub(crate) use bind_update;

// Models
#[derive(Debug, Clone, FromRow)]
pub(crate) struct ContactRow {
    pub node_id: Text<NodeId>,
    pub contact_type: i64,

    pub name: Text<Name>,
    pub email: Option<Text<Email>>,

    pub postal_address_country: Option<Text<Country>>,
    pub postal_address_city: Option<Text<City>>,
    pub postal_address_zip: Option<Text<Zip>>,
    pub postal_address_address: Option<Text<Address>>,

    pub date_of_birth_or_registration: Option<Text<Date>>,
    pub country_of_birth_or_registration: Option<Text<Country>>,
    pub city_of_birth_or_registration: Option<Text<City>>,
    pub identification_number: Option<Text<Identification>>,

    pub avatar_file_name: Option<Text<Name>>,
    pub avatar_file_hash: Option<Text<Sha256Hash>>,
    pub avatar_file_nostr_hash: Option<Text<Sha256HexHash>>,

    pub proof_document_file_name: Option<Text<Name>>,
    pub proof_document_file_hash: Option<Text<Sha256Hash>>,
    pub proof_document_file_nostr_hash: Option<Text<Sha256HexHash>>,

    // JSON String
    pub nostr_relays: String,
    pub mint_url: Option<Text<url::Url>>,
}

impl TryFrom<ContactRow> for Contact {
    type Error = crate::Error;

    fn try_from(row: ContactRow) -> Result<Self> {
        let postal_address = decode_postal_address(
            row.postal_address_country,
            row.postal_address_city,
            row.postal_address_zip,
            row.postal_address_address,
        )?;

        let avatar_file = decode_file(
            row.avatar_file_name,
            row.avatar_file_hash,
            row.avatar_file_nostr_hash,
        )?;

        let proof_document_file = decode_file(
            row.proof_document_file_name,
            row.proof_document_file_hash,
            row.proof_document_file_nostr_hash,
        )?;

        Ok(Contact {
            t: contact_type_from_db(row.contact_type)?,
            node_id: row.node_id.0,
            name: row.name.0,
            email: row.email.map(|v| v.0),
            postal_address,
            date_of_birth_or_registration: row.date_of_birth_or_registration.map(|v| v.0),
            country_of_birth_or_registration: row.country_of_birth_or_registration.map(|v| v.0),
            city_of_birth_or_registration: row.city_of_birth_or_registration.map(|v| v.0),
            identification_number: row.identification_number.map(|v| v.0),
            avatar_file,
            proof_document_file,
            nostr_relays: serde_json::from_str(&row.nostr_relays)?,
            is_logical: false,
            mint_url: row.mint_url.map(|v| v.0),
        })
    }
}

impl TryFrom<&Contact> for ContactRow {
    type Error = crate::Error;

    fn try_from(contact: &Contact) -> Result<Self> {
        let (
            postal_address_country,
            postal_address_city,
            postal_address_zip,
            postal_address_address,
        ) = match &contact.postal_address {
            Some(address) => (
                Some(Text(address.country.clone())),
                Some(Text(address.city.clone())),
                address.zip.clone().map(Text),
                Some(Text(address.address.clone())),
            ),
            None => (None, None, None, None),
        };

        let (avatar_file_name, avatar_file_hash, avatar_file_nostr_hash) =
            match &contact.avatar_file {
                Some(file) => (
                    Some(Text(file.name.clone())),
                    Some(Text(file.hash.clone())),
                    Some(Text(file.nostr_hash)),
                ),
                None => (None, None, None),
            };

        let (proof_document_file_name, proof_document_file_hash, proof_document_file_nostr_hash) =
            match &contact.proof_document_file {
                Some(file) => (
                    Some(Text(file.name.clone())),
                    Some(Text(file.hash.clone())),
                    Some(Text(file.nostr_hash)),
                ),
                None => (None, None, None),
            };

        Ok(Self {
            node_id: Text(contact.node_id.clone()),
            contact_type: contact_type_to_db(&contact.t),
            name: Text(contact.name.clone()),
            email: contact.email.clone().map(Text),
            postal_address_country,
            postal_address_city,
            postal_address_zip,
            postal_address_address,
            date_of_birth_or_registration: contact.date_of_birth_or_registration.clone().map(Text),
            country_of_birth_or_registration: contact
                .country_of_birth_or_registration
                .clone()
                .map(Text),
            city_of_birth_or_registration: contact.city_of_birth_or_registration.clone().map(Text),
            identification_number: contact.identification_number.clone().map(Text),
            avatar_file_name,
            avatar_file_hash,
            avatar_file_nostr_hash,
            proof_document_file_name,
            proof_document_file_hash,
            proof_document_file_nostr_hash,
            nostr_relays: serde_json::to_string(&contact.nostr_relays)?,
            mint_url: contact.mint_url.clone().map(Text),
        })
    }
}

pub(crate) fn ensure_node_id_matches(node_id: &NodeId, contact: &Contact) -> Result<()> {
    if node_id != &contact.node_id {
        return Err(Error::InvalidData(
            "contact node_id does not match stored node id".into(),
        ));
    }

    Ok(())
}
