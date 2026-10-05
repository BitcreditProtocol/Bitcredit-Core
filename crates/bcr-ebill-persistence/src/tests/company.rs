use crate::{
    tests::tests::{
        empty_address, node_id_test, node_id_test_other, private_key_test,
        signed_identity_proof_test, test_ts,
    },
    traits::company::CompanyStoreApi,
};
use bcr_ebill_core::{
    application::company::{
        Company, CompanySignatory, CompanySignatoryStatus, CompanyStatus,
        LocalSignatoryOverrideStatus,
    },
    protocol::{
        City, Country, Date, Email, Identification, Name,
        blockchain::company::block::SignatoryType, crypto::BcrKeys,
    },
};

pub fn get_baseline_company() -> Company {
    let (proof, data) = signed_identity_proof_test();
    Company {
        id: node_id_test(),
        name: Name::new("some_name").unwrap(),
        country_of_registration: Some(Country::AT),
        city_of_registration: Some(City::new("Vienna").unwrap()),
        postal_address: empty_address(),
        email: Email::new("company@example.com").unwrap(),
        registration_number: Some(Identification::new("some_number").unwrap()),
        registration_date: Some(Date::new("2012-01-01").unwrap()),
        proof_of_registration_file: None,
        logo_file: None,
        signatories: vec![CompanySignatory {
            t: SignatoryType::Solo,
            node_id: node_id_test(),
            status: CompanySignatoryStatus::InviteAcceptedIdentityProven {
                ts: test_ts(),
                data,
                proof,
            },
        }],
        creation_time: test_ts(),
        status: CompanyStatus::Active,
    }
}

pub async fn test_company_store<S>(store: &S)
where
    S: CompanyStoreApi + ?Sized,
{
    let id = node_id_test();

    let other_id = node_id_test_other();

    // EXISTS / INSERT / GET
    assert!(!store.exists(&id).await);
    let mut company = get_baseline_company();
    company.name = Name::new("first company").unwrap();
    store
        .insert(&company)
        .await
        .expect("company can be inserted");

    // Company alone is not enough
    assert!(!store.exists(&id).await);
    let fetched = store.get(&id).await.expect("company can be fetched");
    assert_eq!(fetched.name, company.name);
    assert_company_signatories_eq(&fetched.signatories, &company.signatories);

    // INSERT is create semantics
    assert!(store.insert(&company).await.is_err());

    // KEYS
    let keys = BcrKeys::from_private_key(&private_key_test());
    store
        .save_key_pair(&id, &keys)
        .await
        .expect("company keys can be saved");
    assert!(store.exists(&id).await);
    let stored_keys = store.get_key_pair(&id).await.unwrap();
    assert_eq!(stored_keys.pub_key(), keys.pub_key());

    // saving keys again conflicts
    assert!(store.save_key_pair(&id, &keys).await.is_err());

    // UPDATE
    company.name = Name::new("updated company").unwrap();
    store
        .update(&id, &company)
        .await
        .expect("company can be updated");
    let updated = store.get(&id).await.unwrap();
    assert_eq!(updated.name, company.name);
    assert_company_signatories_eq(&updated.signatories, &company.signatories);

    // SECOND COMPANY / STATUS FILTERING
    store.save_key_pair(&other_id, &keys).await.unwrap();
    assert!(!store.exists(&other_id).await);
    let mut other = get_baseline_company();
    other.id = other_id.clone();
    other.name = Name::new("second company").unwrap();
    other.status = CompanyStatus::None;
    store.insert(&other).await.unwrap();

    // None-status companies aren't usable
    assert!(!store.exists(&other_id).await);

    // get_all only returns Active
    let all = store.get_all().await.unwrap();
    assert_eq!(all.len(), 1);
    assert!(all.contains_key(&id));

    // Search also only returns Active
    let search = store.search("company").await.unwrap();
    assert_eq!(search.len(), 1);
    assert_eq!(search[0].id, id);

    // Partial substring
    let search = store.search("updated").await.unwrap();
    assert_eq!(search.len(), 1);

    // INVITES
    other.status = CompanyStatus::Invited;
    store.update(&other_id, &other).await.unwrap();
    let invites = store.get_active_company_invites().await.unwrap();
    assert_eq!(invites.len(), 1);
    assert!(invites.contains_key(&other_id));

    // EMAIL CONFIRMATION
    let (proof, mut data) = signed_identity_proof_test();
    data.company_node_id = Some(id.clone());
    store
        .set_email_confirmation(&id, &proof, &data)
        .await
        .expect("company email confirmation can be saved");
    let confirmations = store.get_email_confirmations(&id).await.unwrap();
    assert_eq!(confirmations.len(), 1);
    assert_eq!(confirmations[0].0.signature, proof.signature);
    assert_eq!(confirmations[0].0.witness, proof.witness);

    // Same company + witness = upsert.
    store
        .set_email_confirmation(&id, &proof, &data)
        .await
        .unwrap();
    assert_eq!(store.get_email_confirmations(&id).await.unwrap().len(), 1);

    // LOCAL SIGNATORY OVERRIDE
    store
        .set_local_signatory_override(&id, &node_id_test(), LocalSignatoryOverrideStatus::Hidden)
        .await
        .unwrap();
    let overrides = store.get_local_signatory_overrides(&id).await.unwrap();
    assert_eq!(overrides.len(), 1);
    assert_eq!(overrides[0].company_id, id);
    assert_eq!(overrides[0].node_id, node_id_test());
    store
        .delete_local_signatory_override(&id, &node_id_test())
        .await
        .unwrap();
    assert!(
        store
            .get_local_signatory_overrides(&id)
            .await
            .unwrap()
            .is_empty()
    );

    // SIGNATORY STATUS ROUND TRIPS
    assert_signatory_status_round_trip(
        store,
        &mut company,
        CompanySignatoryStatus::Invited {
            ts: test_ts(),
            inviter: node_id_test_other(),
        },
    )
    .await;
    assert_signatory_status_round_trip(
        store,
        &mut company,
        CompanySignatoryStatus::InviteAccepted { ts: test_ts() },
    )
    .await;
    assert_signatory_status_round_trip(
        store,
        &mut company,
        CompanySignatoryStatus::InviteRejected { ts: test_ts() },
    )
    .await;
    let (proof, mut identity_proof_data) = signed_identity_proof_test();
    identity_proof_data.company_node_id = Some(company.id.clone());
    assert_signatory_status_round_trip(
        store,
        &mut company,
        CompanySignatoryStatus::InviteAcceptedIdentityProven {
            ts: test_ts(),
            data: identity_proof_data,
            proof,
        },
    )
    .await;
    assert_signatory_status_round_trip(
        store,
        &mut company,
        CompanySignatoryStatus::Removed {
            ts: test_ts(),
            remover: node_id_test_other(),
        },
    )
    .await;
    let first_signatory = CompanySignatory {
        t: SignatoryType::Solo,
        node_id: node_id_test(),
        status: CompanySignatoryStatus::InviteAccepted { ts: test_ts() },
    };
    let second_node = node_id_test_other();
    let second_signatory = CompanySignatory {
        t: SignatoryType::Solo,
        node_id: second_node,
        status: CompanySignatoryStatus::Removed {
            ts: test_ts(),
            remover: node_id_test(),
        },
    };
    company.signatories = vec![first_signatory, second_signatory];
    store.update(&company.id, &company).await.unwrap();
    let fetched = store.get(&company.id).await.unwrap();
    assert_company_signatories_eq(&fetched.signatories, &company.signatories);

    // REMOVE
    store.remove(&id).await.expect("company can be removed");
    assert!(!store.exists(&id).await);
    assert!(store.get(&id).await.is_err());
    assert!(store.get_key_pair(&id).await.is_err());
}

async fn assert_signatory_status_round_trip<S>(
    store: &S,
    company: &mut Company,
    status: CompanySignatoryStatus,
) where
    S: CompanyStoreApi + ?Sized,
{
    company.signatories = vec![CompanySignatory {
        t: SignatoryType::Solo,
        node_id: node_id_test(),
        status,
    }];
    store
        .update(&company.id, company)
        .await
        .expect("company signatory status can be persisted");
    let fetched = store
        .get(&company.id)
        .await
        .expect("company with signatory can be fetched");
    assert_company_signatories_eq(&fetched.signatories, &company.signatories);
}

fn assert_company_signatories_eq(actual: &[CompanySignatory], expected: &[CompanySignatory]) {
    assert_eq!(actual.len(), expected.len());
    for (actual, expected) in actual.iter().zip(expected.iter()) {
        assert_eq!(actual.t, expected.t);
        assert_eq!(actual.node_id, expected.node_id);
        assert_eq!(actual.status, expected.status);
    }
}
