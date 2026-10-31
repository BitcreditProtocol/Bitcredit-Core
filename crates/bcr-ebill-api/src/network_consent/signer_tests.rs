use super::*;
use bcr_ebill_core::{
    application::company::CompanySignatoryStatus,
    protocol::{
        Address, City, Country, Email, EmailIdentityProofData, Name, PostalAddress, Timestamp,
        blockchain::company::block::CompanyCreateBlockData,
    },
};
use bitcoin::{Network, secp256k1::SecretKey};

fn keys(n: u8) -> BcrKeys {
    BcrKeys::from_private_key(&SecretKey::from_slice(&[n; 32]).unwrap())
}
fn node(n: u8) -> NodeId {
    NodeId::new(keys(n).pub_key(), Network::Regtest)
}
fn ts() -> Timestamp {
    Timestamp::new(1790000000).unwrap()
}
fn company(status: CompanySignatoryStatus) -> Company {
    let mut company = Company::from_block_data(
        CompanyCreateBlockData {
            id: node(2),
            name: Name::new("Synthetic company").unwrap(),
            country_of_registration: None,
            city_of_registration: None,
            postal_address: PostalAddress {
                country: Country::parse("AT").unwrap(),
                city: City::new("Vienna").unwrap(),
                zip: None,
                address: Address::new("Synthetic street 1").unwrap(),
            },
            email: Email::new("synthetic@example.test").unwrap(),
            registration_number: None,
            registration_date: None,
            proof_of_registration_file: None,
            logo_file: None,
            creation_time: ts(),
            creator: node(1),
        },
        &node(1),
    );
    company.signatories[0].status = status;
    company
}
fn proven() -> CompanySignatoryStatus {
    let data = EmailIdentityProofData {
        node_id: node(1),
        company_node_id: Some(node(2)),
        email: Email::new("synthetic@example.test").unwrap(),
        created_at: ts(),
    };
    let proof = data.sign(&node(3), &keys(3).get_private_key()).unwrap();
    CompanySignatoryStatus::InviteAcceptedIdentityProven {
        ts: ts(),
        data,
        proof,
    }
}
fn source(selected_personal: NodeId, company: Option<Company>) -> MockSigningIdentitySource {
    let mut source = MockSigningIdentitySource::new();
    let selected_company = company.as_ref().map(|c| c.id.clone());
    source.expect_selected().once().return_once(move || {
        Ok(ActiveIdentityState {
            personal: selected_personal,
            company: selected_company,
        })
    });
    source
        .expect_personal()
        .once()
        .return_once(|| Ok((node(1), keys(1))));
    if let Some(company) = company {
        source
            .expect_company()
            .once()
            .withf(|id| id == &node(2))
            .return_once(move |_| Ok((company, keys(2))));
    }
    source
}

// Same resolver as the directory and consent signing entry points.
#[tokio::test]
async fn exported_signing_resolution_requires_identity_proven_authorized_company_signer() {
    let statuses = [
        (
            CompanySignatoryStatus::Invited {
                ts: ts(),
                inviter: node(3),
            },
            false,
        ),
        (CompanySignatoryStatus::InviteAccepted { ts: ts() }, false),
        (CompanySignatoryStatus::InviteRejected { ts: ts() }, false),
        (proven(), true),
        (
            CompanySignatoryStatus::Removed {
                ts: ts(),
                remover: node(3),
            },
            false,
        ),
    ];
    for (status, authorized) in statuses {
        let source = source(node(1), Some(company(status.clone())));
        let result = get_current_signer_with_type(&source).await;
        assert_eq!(result.is_ok(), authorized, "{status:?}");
        if let Ok((id, key, kind)) = result {
            assert_eq!(id, node(2));
            assert_eq!(key.pub_key(), node(2).pub_key());
            assert_eq!(kind, DirectorySubjectType::Company);
        }
    }
    let mut unrelated = company(proven());
    unrelated.signatories.clear();
    assert!(
        get_current_signer_with_type(&source(node(1), Some(unrelated)))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn selected_personal_identity_must_be_actual_local_identity_in_both_contexts() {
    for selected_company in [None, Some(node(2))] {
        let mut source = MockSigningIdentitySource::new();
        source.expect_selected().once().return_once(move || {
            Ok(ActiveIdentityState {
                personal: node(3),
                company: selected_company,
            })
        });
        source
            .expect_personal()
            .once()
            .return_once(|| Ok((node(1), keys(1))));
        source.expect_company().never();
        assert!(get_current_signer_with_type(&source).await.is_err());
    }
    let (id, _, kind) = get_current_signer_with_type(&source(node(1), None))
        .await
        .unwrap();
    assert_eq!(id, node(1));
    assert_eq!(kind, DirectorySubjectType::SoleTrader);
}

#[tokio::test]
async fn company_selected_voice_uses_device_operator_personal_key_without_company_authority() {
    let mut source = MockSigningIdentitySource::new();
    source.expect_selected().once().return_once(|| {
        Ok(ActiveIdentityState {
            personal: node(1),
            company: Some(node(2)),
        })
    });
    source
        .expect_personal()
        .once()
        .return_once(|| Ok((node(1), keys(1))));
    source.expect_company().never();
    let (_, signer, keys) = get_personal_signer(&source).await.unwrap();
    assert_eq!(signer, node(1));
    assert_eq!(keys.pub_key(), node(1).pub_key());
}
