use crate::{
    Error, Result,
    sql::{decode_file, timestamp_from_db, timestamp_to_db, unit_enum_from_db, unit_enum_to_db},
};
use bcr_common::core::NodeId;
use bcr_ebill_core::{
    application::company::{Company, CompanySignatory, CompanySignatoryStatus},
    protocol::{
        Address, City, Country, Date, Email, EmailIdentityProofData, Identification, Name,
        PostalAddress, Sha256Hash, SignedIdentityProof, Timestamp, Zip,
    },
};
use bitcoin::hashes::sha256::Hash as Sha256HexHash;
use sqlx::types::Text;

// SQL
pub(crate) const SELECT_COMPANY: &str = r#"
    SELECT
        id,
        name,
        country_of_registration,
        city_of_registration,

        postal_address_country,
        postal_address_city,
        postal_address_zip,
        postal_address_address,

        email,

        registration_number,
        registration_date,

        proof_of_registration_file_name,
        proof_of_registration_file_hash,
        proof_of_registration_file_nostr_hash,

        logo_file_name,
        logo_file_hash,
        logo_file_nostr_hash,

        creation_time,
        status
    FROM company
    WHERE id = $1
"#;

pub(crate) const INSERT_COMPANY: &str = r#"
    INSERT INTO company (
        id,
        name,
        country_of_registration,
        city_of_registration,

        postal_address_country,
        postal_address_city,
        postal_address_zip,
        postal_address_address,

        email,

        registration_number,
        registration_date,

        proof_of_registration_file_name,
        proof_of_registration_file_hash,
        proof_of_registration_file_nostr_hash,

        logo_file_name,
        logo_file_hash,
        logo_file_nostr_hash,

        creation_time,
        status
    )
    VALUES (
        $1, $2, $3, $4,
        $5, $6, $7, $8,
        $9,
        $10, $11,
        $12, $13, $14,
        $15, $16, $17,
        $18, $19
    )
"#;

pub(crate) const UPDATE_COMPANY: &str = r#"
    UPDATE company
    SET
        name = $2,
        country_of_registration = $3,
        city_of_registration = $4,

        postal_address_country = $5,
        postal_address_city = $6,
        postal_address_zip = $7,
        postal_address_address = $8,

        email = $9,

        registration_number = $10,
        registration_date = $11,

        proof_of_registration_file_name = $12,
        proof_of_registration_file_hash = $13,
        proof_of_registration_file_nostr_hash = $14,

        logo_file_name = $15,
        logo_file_hash = $16,
        logo_file_nostr_hash = $17,

        creation_time = $18,
        status = $19

    WHERE id = $1
"#;

pub(crate) const DELETE_COMPANY: &str = r#"
    DELETE FROM company
    WHERE id = $1
"#;

pub(crate) const SELECT_SIGNATORIES: &str = r#"
    SELECT
        company_id,
        position,
        signatory_type,
        node_id,
        status,
        ts,
        inviter,
        remover,
        data_node_id,
        data_company_node_id,
        data_email,
        data_created_at,
        proof_signature,
        proof_witness
    FROM company_signatory
    WHERE company_id = $1
    ORDER BY position ASC
"#;

pub(crate) const DELETE_SIGNATORIES: &str = r#"
    DELETE FROM company_signatory
    WHERE company_id = $1
"#;

pub(crate) const INSERT_SIGNATORY: &str = r#"
    INSERT INTO company_signatory (
        company_id,
        position,
        signatory_type,
        node_id,
        status,
        ts,
        inviter,
        remover,
        data_node_id,
        data_company_node_id,
        data_email,
        data_created_at,
        proof_signature,
        proof_witness
    )
    VALUES (
        $1, $2, $3, $4, $5,
        $6, $7, $8, $9, $10,
        $11, $12, $13, $14
    )
"#;

pub(crate) const INSERT_KEY: &str = r#"
    INSERT INTO company_keys (
        id,
        private_key
    )
    VALUES (
        $1,
        $2
    )
"#;

pub(crate) const SELECT_KEY: &str = r#"
    SELECT private_key
    FROM company_keys
    WHERE id = $1
"#;

pub(crate) const DELETE_KEY: &str = r#"
    DELETE FROM company_keys
    WHERE id = $1
"#;

pub(crate) const SELECT_COMPANIES_WITH_KEYS_BY_STATUS: &str = r#"
    SELECT
        c.id,
        k.private_key
    FROM company AS c
    INNER JOIN company_keys AS k
        ON k.id = c.id
    WHERE c.status = $1
"#;

pub(crate) const EXISTS: &str = r#"
    SELECT EXISTS (
        SELECT 1
        FROM company AS c
        INNER JOIN company_keys AS k
            ON k.id = c.id
        WHERE c.id = $1
          AND c.status <> $2
    )
"#;

pub(crate) const SEARCH: &str = r#"
    SELECT id
    FROM company
    WHERE status = $1
      AND LOWER(name)
          LIKE LOWER($2) ESCAPE '\'
"#;

pub(crate) const SELECT_EMAIL_CONFIRMATIONS: &str = r#"
    SELECT
        signature,
        witness,
        node_id,
        company_node_id,
        email,
        created_at
    FROM company_email_confirmation
    WHERE company_id = $1
    ORDER BY created_at ASC, witness ASC
"#;

pub(crate) const UPSERT_EMAIL_CONFIRMATION: &str = r#"
    INSERT INTO company_email_confirmation (
        company_id,
        signature,
        witness,
        node_id,
        company_node_id,
        email,
        created_at
    )
    VALUES (
        $1, $2, $3, $4,
        $5, $6, $7
    )
    ON CONFLICT(company_id, witness)
    DO UPDATE SET
        signature = excluded.signature,
        node_id = excluded.node_id,
        company_node_id =
            excluded.company_node_id,
        email = excluded.email,
        created_at = excluded.created_at
"#;

pub(crate) const SELECT_LOCAL_OVERRIDES: &str = r#"
    SELECT
        company_id,
        node_id,
        status
    FROM company_local_signatory_override
    WHERE company_id = $1
"#;

pub(crate) const UPSERT_LOCAL_OVERRIDE: &str = r#"
    INSERT INTO company_local_signatory_override (
        company_id,
        node_id,
        status
    )
    VALUES (
        $1, $2, $3
    )
    ON CONFLICT(company_id, node_id)
    DO UPDATE SET
        status = excluded.status
"#;

pub(crate) const DELETE_LOCAL_OVERRIDE: &str = r#"
    DELETE FROM company_local_signatory_override
    WHERE company_id = $1
      AND node_id = $2
"#;

pub(crate) fn escape_like(term: &str) -> String {
    term.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

macro_rules! bind_company {
    ($query:expr, $row:expr) => {
        $query
            .bind(&$row.id)
            .bind(&$row.name)
            .bind(&$row.country_of_registration)
            .bind(&$row.city_of_registration)
            .bind(&$row.postal_address_country)
            .bind(&$row.postal_address_city)
            .bind(&$row.postal_address_zip)
            .bind(&$row.postal_address_address)
            .bind(&$row.email)
            .bind(&$row.registration_number)
            .bind(&$row.registration_date)
            .bind(&$row.proof_of_registration_file_name)
            .bind(&$row.proof_of_registration_file_hash)
            .bind(&$row.proof_of_registration_file_nostr_hash)
            .bind(&$row.logo_file_name)
            .bind(&$row.logo_file_hash)
            .bind(&$row.logo_file_nostr_hash)
            .bind($row.creation_time)
            .bind(&$row.status)
    };
}

macro_rules! bind_signatory {
    ($query:expr, $row:expr) => {
        $query
            .bind(&$row.company_id)
            .bind($row.position)
            .bind(&$row.signatory_type)
            .bind(&$row.node_id)
            .bind(&$row.status)
            .bind($row.ts)
            .bind(&$row.inviter)
            .bind(&$row.remover)
            .bind(&$row.data_node_id)
            .bind(&$row.data_company_node_id)
            .bind(&$row.data_email)
            .bind($row.data_created_at)
            .bind(&$row.proof_signature)
            .bind(&$row.proof_witness)
    };
}

pub(crate) use bind_signatory;

pub(crate) use bind_company;

#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct CompanyRow {
    pub id: Text<NodeId>,
    pub name: Text<Name>,
    pub country_of_registration: Option<Text<Country>>,
    pub city_of_registration: Option<Text<City>>,

    pub postal_address_country: Text<Country>,
    pub postal_address_city: Text<City>,
    pub postal_address_zip: Option<Text<Zip>>,
    pub postal_address_address: Text<Address>,

    pub email: Text<Email>,

    pub registration_number: Option<Text<Identification>>,
    pub registration_date: Option<Text<Date>>,

    pub proof_of_registration_file_name: Option<Text<Name>>,
    pub proof_of_registration_file_hash: Option<Text<Sha256Hash>>,
    pub proof_of_registration_file_nostr_hash: Option<Text<Sha256HexHash>>,

    pub logo_file_name: Option<Text<Name>>,
    pub logo_file_hash: Option<Text<Sha256Hash>>,
    pub logo_file_nostr_hash: Option<Text<Sha256HexHash>>,

    pub creation_time: i64,
    pub status: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct CompanySignatoryRow {
    pub company_id: Text<NodeId>,
    pub position: i64,
    pub signatory_type: String,
    pub node_id: Text<NodeId>,
    pub status: String,
    pub ts: Option<i64>,
    pub inviter: Option<Text<NodeId>>,
    pub remover: Option<Text<NodeId>>,
    pub data_node_id: Option<Text<NodeId>>,
    pub data_company_node_id: Option<Text<NodeId>>,
    pub data_email: Option<Text<Email>>,
    pub data_created_at: Option<i64>,
    pub proof_signature: Option<String>,
    pub proof_witness: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct LocalSignatoryOverrideRow {
    pub company_id: Text<NodeId>,
    pub node_id: Text<NodeId>,
    pub status: String,
}

#[derive(Debug, Default)]
pub(crate) struct CompanySignatoryStatusColumns {
    pub status: String,
    pub ts: Option<i64>,
    pub inviter: Option<Text<NodeId>>,
    pub remover: Option<Text<NodeId>>,
    pub data_node_id: Option<Text<NodeId>>,
    pub data_company_node_id: Option<Text<NodeId>>,
    pub data_email: Option<Text<Email>>,
    pub data_created_at: Option<i64>,
    pub proof_signature: Option<String>,
    pub proof_witness: Option<String>,
}

// flatten out signatory status to several fields
pub(crate) fn company_signatory_status_to_db(
    status: &CompanySignatoryStatus,
) -> Result<CompanySignatoryStatusColumns> {
    let value = serde_json::to_value(status).map_err(|e| {
        Error::InvalidData(format!("could not serialize company signatory status: {e}"))
    })?;

    match value {
        // just the status with no fields as string
        serde_json::Value::String(status) => Ok(CompanySignatoryStatusColumns {
            status,
            ..Default::default()
        }),
        // struct enum variants
        serde_json::Value::Object(outer) if outer.len() == 1 => {
            let (status, payload) = outer.into_iter().next().expect("checked len");
            let payload = payload.as_object().ok_or_else(|| {
                Error::InvalidData("invalid company signatory status payload".to_owned())
            })?;
            for key in payload.keys() {
                if !matches!(
                    key.as_str(),
                    "ts" | "inviter" | "data" | "proof" | "remover"
                ) {
                    return Err(Error::InvalidData(format!(
                        "unsupported company signatory status field: {key}"
                    )));
                }
            }
            let ts = payload
                .get("ts")
                .map(|value| {
                    serde_json::from_value::<Timestamp>(value.clone())
                        .map_err(|e| {
                            Error::InvalidData(format!("invalid signatory status timestamp: {e}"))
                        })
                        .and_then(timestamp_to_db)
                })
                .transpose()?;
            let inviter = payload
                .get("inviter")
                .map(|value| {
                    serde_json::from_value::<NodeId>(value.clone())
                        .map(Text)
                        .map_err(|e| Error::InvalidData(format!("invalid signatory inviter: {e}")))
                })
                .transpose()?;
            let remover = payload
                .get("remover")
                .map(|value| {
                    serde_json::from_value::<NodeId>(value.clone())
                        .map(Text)
                        .map_err(|e| Error::InvalidData(format!("invalid signatory remover: {e}")))
                })
                .transpose()?;
            let data = payload
                .get("data")
                .map(|value| {
                    serde_json::from_value::<EmailIdentityProofData>(value.clone()).map_err(|e| {
                        Error::InvalidData(format!("invalid signatory identity proof data: {e}"))
                    })
                })
                .transpose()?;
            let proof = payload
                .get("proof")
                .map(|value| {
                    serde_json::from_value::<SignedIdentityProof>(value.clone()).map_err(|e| {
                        Error::InvalidData(format!("invalid signatory identity proof: {e}"))
                    })
                })
                .transpose()?;
            Ok(CompanySignatoryStatusColumns {
                status,
                ts,
                inviter,
                remover,
                data_node_id: data.as_ref().map(|d| Text(d.node_id.clone())),
                data_company_node_id: data
                    .as_ref()
                    .and_then(|d| d.company_node_id.clone())
                    .map(Text),
                data_email: data.as_ref().map(|d| Text(d.email.clone())),
                data_created_at: data
                    .as_ref()
                    .map(|d| timestamp_to_db(d.created_at))
                    .transpose()?,
                proof_signature: proof.as_ref().map(|p| p.signature.to_string()),
                proof_witness: proof.as_ref().map(|p| p.witness.to_string()),
            })
        }
        other => Err(Error::InvalidData(format!(
            "invalid company signatory status representation: {other}"
        ))),
    }
}

// recombine from flattened out signatory status
pub(crate) fn company_signatory_status_from_db(
    row: &CompanySignatoryRow,
) -> Result<CompanySignatoryStatus> {
    let mut payload = serde_json::Map::new();
    if let Some(ts) = row.ts {
        payload.insert(
            "ts".to_owned(),
            serde_json::to_value(timestamp_from_db(ts)?)
                .map_err(|e| Error::InvalidData(e.to_string()))?,
        );
    }
    if let Some(inviter) = row.inviter.clone() {
        payload.insert(
            "inviter".to_owned(),
            serde_json::to_value(inviter.into_inner())
                .map_err(|e| Error::InvalidData(e.to_string()))?,
        );
    }
    if let Some(remover) = row.remover.clone() {
        payload.insert(
            "remover".to_owned(),
            serde_json::to_value(remover.into_inner())
                .map_err(|e| Error::InvalidData(e.to_string()))?,
        );
    }
    let has_data = row.data_node_id.is_some()
        || row.data_company_node_id.is_some()
        || row.data_email.is_some()
        || row.data_created_at.is_some();
    if has_data {
        let node_id = row
            .data_node_id
            .clone()
            .ok_or_else(|| Error::InvalidData("missing signatory data node_id".to_owned()))?
            .into_inner();
        let email = row
            .data_email
            .clone()
            .ok_or_else(|| Error::InvalidData("missing signatory data email".to_owned()))?
            .into_inner();
        let created_at =
            timestamp_from_db(row.data_created_at.ok_or_else(|| {
                Error::InvalidData("missing signatory data created_at".to_owned())
            })?)?;
        let data = EmailIdentityProofData {
            node_id,
            company_node_id: row.data_company_node_id.clone().map(Text::into_inner),
            email,
            created_at,
        };
        payload.insert(
            "data".to_owned(),
            serde_json::to_value(data).map_err(|e| Error::InvalidData(e.to_string()))?,
        );
    }

    match (&row.proof_signature, &row.proof_witness) {
        (None, None) => {}
        (Some(signature), Some(witness)) => {
            let proof = SignedIdentityProof {
                signature: signature.parse().map_err(|_| Error::EncodingError)?,
                witness: witness.parse().map_err(|_| Error::EncodingError)?,
            };
            payload.insert(
                "proof".to_owned(),
                serde_json::to_value(proof).map_err(|e| Error::InvalidData(e.to_string()))?,
            );
        }
        _ => {
            return Err(Error::InvalidData("incomplete signatory proof".to_owned()));
        }
    }

    let serialized = if payload.is_empty() {
        serde_json::Value::String(row.status.clone())
    } else {
        serde_json::Value::Object(
            [(row.status.clone(), serde_json::Value::Object(payload))]
                .into_iter()
                .collect(),
        )
    };
    serde_json::from_value(serialized)
        .map_err(|e| Error::InvalidData(format!("invalid persisted company signatory status: {e}")))
}

pub(crate) fn company_to_row(company: &Company) -> Result<CompanyRow> {
    let proof = company.proof_of_registration_file.as_ref();
    let logo = company.logo_file.as_ref();
    Ok(CompanyRow {
        id: Text(company.id.clone()),
        name: Text(company.name.clone()),
        country_of_registration: company.country_of_registration.clone().map(Text),
        city_of_registration: company.city_of_registration.clone().map(Text),
        postal_address_country: Text(company.postal_address.country.clone()),
        postal_address_city: Text(company.postal_address.city.clone()),
        postal_address_zip: company.postal_address.zip.clone().map(Text),
        postal_address_address: Text(company.postal_address.address.clone()),
        email: Text(company.email.clone()),
        registration_number: company.registration_number.clone().map(Text),
        registration_date: company.registration_date.clone().map(Text),
        proof_of_registration_file_name: proof.map(|f| Text(f.name.clone())),
        proof_of_registration_file_hash: proof.map(|f| Text(f.hash.clone())),
        proof_of_registration_file_nostr_hash: proof.map(|f| Text(f.nostr_hash)),
        logo_file_name: logo.map(|f| Text(f.name.clone())),
        logo_file_hash: logo.map(|f| Text(f.hash.clone())),
        logo_file_nostr_hash: logo.map(|f| Text(f.nostr_hash)),
        creation_time: timestamp_to_db(company.creation_time)?,
        status: unit_enum_to_db(&company.status)?,
    })
}

pub(crate) fn company_from_row(
    row: CompanyRow,
    signatories: Vec<CompanySignatory>,
) -> Result<Company> {
    let proof_of_registration_file = decode_file(
        row.proof_of_registration_file_name,
        row.proof_of_registration_file_hash,
        row.proof_of_registration_file_nostr_hash,
    )?;

    let logo_file = decode_file(
        row.logo_file_name,
        row.logo_file_hash,
        row.logo_file_nostr_hash,
    )?;

    Ok(Company {
        id: row.id.into_inner(),
        name: row.name.into_inner(),
        country_of_registration: row.country_of_registration.map(Text::into_inner),
        city_of_registration: row.city_of_registration.map(Text::into_inner),
        postal_address: PostalAddress {
            country: row.postal_address_country.into_inner(),
            city: row.postal_address_city.into_inner(),
            zip: row.postal_address_zip.map(|z| z.into_inner()),
            address: row.postal_address_address.into_inner(),
        },
        email: row.email.into_inner(),
        registration_number: row.registration_number.map(Text::into_inner),
        registration_date: row.registration_date.map(Text::into_inner),
        proof_of_registration_file,
        logo_file,
        signatories,
        creation_time: timestamp_from_db(row.creation_time)?,
        status: unit_enum_from_db(row.status)?,
    })
}

pub(crate) fn company_signatory_to_row(
    company_id: &NodeId,
    position: usize,
    signatory: &CompanySignatory,
) -> Result<CompanySignatoryRow> {
    let status = company_signatory_status_to_db(&signatory.status)?;
    Ok(CompanySignatoryRow {
        company_id: Text(company_id.clone()),
        position: i64::try_from(position)
            .map_err(|_| Error::InvalidData("signatory position exceeds i64".to_owned()))?,
        signatory_type: unit_enum_to_db(&signatory.t)?,
        node_id: Text(signatory.node_id.clone()),
        status: status.status,
        ts: status.ts,
        inviter: status.inviter,
        remover: status.remover,
        data_node_id: status.data_node_id,
        data_company_node_id: status.data_company_node_id,
        data_email: status.data_email,
        data_created_at: status.data_created_at,
        proof_signature: status.proof_signature,
        proof_witness: status.proof_witness,
    })
}

impl TryFrom<CompanySignatoryRow> for CompanySignatory {
    type Error = Error;

    fn try_from(row: CompanySignatoryRow) -> Result<Self> {
        let status = company_signatory_status_from_db(&row)?;
        Ok(Self {
            t: unit_enum_from_db(row.signatory_type)?,
            node_id: row.node_id.into_inner(),
            status,
        })
    }
}
