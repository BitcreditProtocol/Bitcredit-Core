use bcr_common::core::NodeId;
use bcr_ebill_core::{
    application::identity::{ActiveIdentityState, Identity},
    protocol::{
        Address, City, Country, Date, Email, EmailIdentityProofData, Identification, Name,
        OptionalPostalAddress, Sha256Hash, SignedIdentityProof, Zip,
    },
};
use bitcoin::hashes::sha256::Hash as Sha256HexHash;
use sqlx::{FromRow, types::Text};
use url::Url;

use crate::{
    Error, Result,
    sql::{
        decode_file, identity_type_from_db, identity_type_to_db, timestamp_from_db, timestamp_to_db,
    },
};

pub(crate) const SELECT_IDENTITY: &str = r#"
    SELECT
        identity_type,
        node_id,
        name,
        email,

        postal_address_country,
        postal_address_city,
        postal_address_zip,
        postal_address_address,

        date_of_birth,
        country_of_birth,
        city_of_birth,
        identification_number,

        identity_document_file_name,
        identity_document_file_hash,
        identity_document_file_nostr_hash,

        profile_picture_file_name,
        profile_picture_file_hash,
        profile_picture_file_nostr_hash,

        nostr_relays
    FROM identity
    WHERE id = 1
"#;

pub(crate) const UPSERT_IDENTITY: &str = r#"
    INSERT INTO identity (
        id,

        identity_type,
        node_id,
        name,
        email,

        postal_address_country,
        postal_address_city,
        postal_address_zip,
        postal_address_address,

        date_of_birth,
        country_of_birth,
        city_of_birth,
        identification_number,

        identity_document_file_name,
        identity_document_file_hash,
        identity_document_file_nostr_hash,

        profile_picture_file_name,
        profile_picture_file_hash,
        profile_picture_file_nostr_hash,

        nostr_relays
    )
    VALUES (
        1,
        $1, $2, $3, $4,
        $5, $6, $7, $8,
        $9, $10, $11, $12,
        $13, $14, $15,
        $16, $17, $18,
        $19
    )
    ON CONFLICT(id) DO UPDATE SET
        identity_type = excluded.identity_type,
        node_id = excluded.node_id,
        name = excluded.name,
        email = excluded.email,

        postal_address_country = excluded.postal_address_country,
        postal_address_city = excluded.postal_address_city,
        postal_address_zip = excluded.postal_address_zip,
        postal_address_address = excluded.postal_address_address,

        date_of_birth = excluded.date_of_birth,
        country_of_birth = excluded.country_of_birth,
        city_of_birth = excluded.city_of_birth,
        identification_number = excluded.identification_number,

        identity_document_file_name =
            excluded.identity_document_file_name,
        identity_document_file_hash =
            excluded.identity_document_file_hash,
        identity_document_file_nostr_hash =
            excluded.identity_document_file_nostr_hash,

        profile_picture_file_name =
            excluded.profile_picture_file_name,
        profile_picture_file_hash =
            excluded.profile_picture_file_hash,
        profile_picture_file_nostr_hash =
            excluded.profile_picture_file_nostr_hash,

        nostr_relays = excluded.nostr_relays
"#;

pub(crate) const SELECT_KEYS: &str = r#"
    SELECT
        key,
        seed_phrase
    FROM identity_keys
    WHERE id = 1
"#;

pub(crate) const UPSERT_KEYS: &str = r#"
    INSERT INTO identity_keys (
        id,
        key,
        seed_phrase
    )
    VALUES (
        1,
        $1,
        $2
    )
    ON CONFLICT(id) DO UPDATE SET
        key = excluded.key,
        seed_phrase = excluded.seed_phrase
"#;

pub(crate) const SELECT_NETWORK: &str = r#"
    SELECT network
    FROM identity_network
    WHERE id = 1
"#;

pub(crate) const INSERT_NETWORK: &str = r#"
    INSERT INTO identity_network (
        id,
        network
    )
    VALUES (
        1,
        $1
    )
"#;

pub(crate) const SELECT_ACTIVE_IDENTITY: &str = r#"
    SELECT
        personal,
        company
    FROM active_identity
    WHERE id = 1
"#;

pub(crate) const UPSERT_ACTIVE_IDENTITY: &str = r#"
    INSERT INTO active_identity (
        id,
        personal,
        company
    )
    VALUES (
        1,
        $1,
        $2
    )
    ON CONFLICT(id) DO UPDATE SET
        personal = excluded.personal,
        company = excluded.company
"#;

pub(crate) const SELECT_EMAIL_CONFIRMATIONS: &str = r#"
    SELECT
        signature,
        witness,
        node_id,
        company_node_id,
        email,
        created_at
    FROM email_confirmation
    ORDER BY created_at ASC, witness ASC
"#;

pub(crate) const UPSERT_EMAIL_CONFIRMATION: &str = r#"
    INSERT INTO email_confirmation (
        signature,
        witness,
        node_id,
        company_node_id,
        email,
        created_at
    )
    VALUES (
        $1,
        $2,
        $3,
        $4,
        $5,
        $6
    )
    ON CONFLICT(witness) DO UPDATE SET
        signature = excluded.signature,
        node_id = excluded.node_id,
        company_node_id = excluded.company_node_id,
        email = excluded.email,
        created_at = excluded.created_at
"#;

macro_rules! bind_identity {
    ($query:expr, $row:expr) => {
        $query
            .bind(&$row.identity_type)
            .bind(&$row.node_id)
            .bind(&$row.name)
            .bind(&$row.email)
            .bind(&$row.postal_address_country)
            .bind(&$row.postal_address_city)
            .bind(&$row.postal_address_zip)
            .bind(&$row.postal_address_address)
            .bind(&$row.date_of_birth)
            .bind(&$row.country_of_birth)
            .bind(&$row.city_of_birth)
            .bind(&$row.identification_number)
            .bind(&$row.identity_document_file_name)
            .bind(&$row.identity_document_file_hash)
            .bind(&$row.identity_document_file_nostr_hash)
            .bind(&$row.profile_picture_file_name)
            .bind(&$row.profile_picture_file_hash)
            .bind(&$row.profile_picture_file_nostr_hash)
            .bind(&$row.nostr_relays)
    };
}

pub(crate) use bind_identity;

#[derive(Debug, Clone, FromRow)]
pub(crate) struct IdentityRow {
    pub identity_type: i64,

    pub node_id: Text<NodeId>,
    pub name: Text<Name>,
    pub email: Option<Text<Email>>,

    pub postal_address_country: Option<Text<Country>>,
    pub postal_address_city: Option<Text<City>>,
    pub postal_address_zip: Option<Text<Zip>>,
    pub postal_address_address: Option<Text<Address>>,

    pub date_of_birth: Option<Text<Date>>,
    pub country_of_birth: Option<Text<Country>>,
    pub city_of_birth: Option<Text<City>>,
    pub identification_number: Option<Text<Identification>>,

    pub identity_document_file_name: Option<Text<Name>>,
    pub identity_document_file_hash: Option<Text<Sha256Hash>>,
    pub identity_document_file_nostr_hash: Option<Text<Sha256HexHash>>,

    pub profile_picture_file_name: Option<Text<Name>>,
    pub profile_picture_file_hash: Option<Text<Sha256Hash>>,
    pub profile_picture_file_nostr_hash: Option<Text<Sha256HexHash>>,

    pub nostr_relays: String,
}

#[derive(Debug, Clone, FromRow)]
pub(crate) struct IdentityKeysRow {
    pub key: String,
    pub seed_phrase: String,
}

#[derive(Debug, Clone, FromRow)]
pub(crate) struct ActiveIdentityRow {
    pub personal: Text<NodeId>,
    pub company: Option<Text<NodeId>>,
}

#[derive(Debug, Clone, FromRow)]
pub(crate) struct EmailConfirmationRow {
    pub signature: String,
    pub witness: String,
    pub node_id: Text<NodeId>,
    pub company_node_id: Option<Text<NodeId>>,
    pub email: Text<Email>,
    pub created_at: i64,
}

pub(crate) fn identity_to_row(identity: &Identity) -> Result<IdentityRow> {
    let nostr_relays = serde_json::to_string(&identity.nostr_relays).map_err(|e| {
        Error::InvalidData(format!("could not serialize identity nostr relays: {e}"))
    })?;
    let identity_document = identity.identity_document_file.as_ref();
    let profile_picture = identity.profile_picture_file.as_ref();
    Ok(IdentityRow {
        identity_type: identity_type_to_db(&identity.t),
        node_id: Text(identity.node_id.to_owned()),
        name: Text(identity.name.to_owned()),
        email: identity.email.clone().map(Text),
        postal_address_country: identity.postal_address.country.clone().map(Text),
        postal_address_city: identity.postal_address.city.clone().map(Text),
        postal_address_zip: identity.postal_address.zip.clone().map(Text),
        postal_address_address: identity.postal_address.address.clone().map(Text),
        date_of_birth: identity.date_of_birth.clone().map(Text),
        country_of_birth: identity.country_of_birth.clone().map(Text),
        city_of_birth: identity.city_of_birth.clone().map(Text),
        identification_number: identity.identification_number.clone().map(Text),
        identity_document_file_name: identity_document.map(|file| Text(file.name.to_owned())),
        identity_document_file_hash: identity_document.map(|file| Text(file.hash.to_owned())),
        identity_document_file_nostr_hash: identity_document.map(|file| Text(file.nostr_hash)),
        profile_picture_file_name: profile_picture.map(|file| Text(file.name.to_owned())),
        profile_picture_file_hash: profile_picture.map(|file| Text(file.hash.to_owned())),
        profile_picture_file_nostr_hash: profile_picture.map(|file| Text(file.nostr_hash)),
        nostr_relays,
    })
}

impl TryFrom<IdentityRow> for Identity {
    type Error = Error;

    fn try_from(row: IdentityRow) -> Result<Self> {
        let nostr_relays: Vec<Url> = serde_json::from_str(&row.nostr_relays)
            .map_err(|e| Error::InvalidData(format!("invalid identity nostr relays: {e}")))?;

        let identity_document_file = decode_file(
            row.identity_document_file_name,
            row.identity_document_file_hash,
            row.identity_document_file_nostr_hash,
        )?;

        let profile_picture_file = decode_file(
            row.profile_picture_file_name,
            row.profile_picture_file_hash,
            row.profile_picture_file_nostr_hash,
        )?;

        Ok(Identity {
            t: identity_type_from_db(row.identity_type)?,
            node_id: row.node_id.into_inner(),
            name: row.name.into_inner(),
            email: row.email.map(Text::into_inner),
            postal_address: OptionalPostalAddress {
                country: row.postal_address_country.map(Text::into_inner),
                city: row.postal_address_city.map(Text::into_inner),
                zip: row.postal_address_zip.map(Text::into_inner),
                address: row.postal_address_address.map(Text::into_inner),
            },
            date_of_birth: row.date_of_birth.map(Text::into_inner),
            country_of_birth: row.country_of_birth.map(Text::into_inner),
            city_of_birth: row.city_of_birth.map(Text::into_inner),
            identification_number: row.identification_number.map(Text::into_inner),
            nostr_relays,
            profile_picture_file,
            identity_document_file,
        })
    }
}

impl From<ActiveIdentityRow> for ActiveIdentityState {
    fn from(row: ActiveIdentityRow) -> Self {
        Self {
            personal: row.personal.into_inner(),
            company: row.company.map(Text::into_inner),
        }
    }
}

pub(crate) fn email_confirmation_to_row(
    (proof, data): &(SignedIdentityProof, EmailIdentityProofData),
) -> Result<EmailConfirmationRow> {
    Ok(EmailConfirmationRow {
        signature: proof.signature.to_string(),
        witness: proof.witness.to_string(),
        node_id: Text(data.node_id.clone()),
        company_node_id: data.company_node_id.clone().map(Text),
        email: Text(data.email.clone()),
        created_at: timestamp_to_db(data.created_at)?,
    })
}

pub(crate) fn email_confirmation_from_row(
    row: EmailConfirmationRow,
) -> Result<(SignedIdentityProof, EmailIdentityProofData)> {
    Ok((
        SignedIdentityProof {
            signature: row.signature.parse().map_err(|_| Error::EncodingError)?,
            witness: row.witness.parse().map_err(|_| Error::EncodingError)?,
        },
        EmailIdentityProofData {
            node_id: row.node_id.into_inner(),
            company_node_id: row.company_node_id.map(Text::into_inner),
            email: row.email.into_inner(),
            created_at: timestamp_from_db(row.created_at)?,
        },
    ))
}
