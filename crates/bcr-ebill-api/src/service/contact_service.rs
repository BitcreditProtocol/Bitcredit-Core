use std::sync::Arc;

use async_trait::async_trait;
use bcr_ebill_core::{
    ValidationError,
    contact::{
        BillParticipant,
        validation::{validate_create_contact, validate_update_contact},
    },
};
#[cfg(test)]
use mockall::automock;

use crate::{
    data::{
        File, OptionalPostalAddress, PostalAddress,
        contact::{Contact, ContactType},
    },
    get_config,
    persistence::{
        contact::ContactStoreApi, file_upload::FileUploadStoreApi, identity::IdentityStoreApi,
    },
    util,
};

use super::Result;
use log::{debug, info};

#[cfg_attr(test, automock)]
#[async_trait]
pub trait ContactServiceApi: Send + Sync {
    /// Searches contacts for the search term
    async fn search(&self, search_term: &str) -> Result<Vec<Contact>>;
    /// Returns all contacts in short form
    async fn get_contacts(&self) -> Result<Vec<Contact>>;

    /// Returns the contact details for the given node_id
    async fn get_contact(&self, node_id: &str) -> Result<Contact>;

    /// Returns the contact by node id
    async fn get_identity_by_node_id(&self, node_id: &str) -> Result<Option<BillParticipant>>;

    /// Deletes the contact with the given node_id.
    async fn delete(&self, node_id: &str) -> Result<()>;

    /// Updates the contact with the given data.
    async fn update_contact(
        &self,
        node_id: &str,
        name: Option<String>,
        email: Option<String>,
        postal_address: OptionalPostalAddress,
        date_of_birth_or_registration: Option<String>,
        country_of_birth_or_registration: Option<String>,
        city_of_birth_or_registration: Option<String>,
        identification_number: Option<String>,
        avatar_file_upload_id: Option<String>,
        proof_document_file_upload_id: Option<String>,
    ) -> Result<()>;

    /// Adds a new contact
    async fn add_contact(
        &self,
        node_id: &str,
        t: ContactType,
        name: String,
        email: Option<String>,
        postal_address: Option<PostalAddress>,
        date_of_birth_or_registration: Option<String>,
        country_of_birth_or_registration: Option<String>,
        city_of_birth_or_registration: Option<String>,
        identification_number: Option<String>,
        avatar_file_upload_id: Option<String>,
        proof_document_file_upload_id: Option<String>,
    ) -> Result<Contact>;

    /// Deanonymize a contact
    async fn deanonymize_contact(
        &self,
        node_id: &str,
        t: ContactType,
        name: String,
        email: Option<String>,
        postal_address: Option<PostalAddress>,
        date_of_birth_or_registration: Option<String>,
        country_of_birth_or_registration: Option<String>,
        city_of_birth_or_registration: Option<String>,
        identification_number: Option<String>,
        avatar_file_upload_id: Option<String>,
        proof_document_file_upload_id: Option<String>,
    ) -> Result<Contact>;

    /// Returns whether a given npub (as hex) is in our contact list.
    #[allow(dead_code)]
    async fn is_known_npub(&self, npub: &str) -> Result<bool>;

    /// opens and decrypts the attached file from the given contact
    async fn open_and_decrypt_file(
        &self,
        id: &str,
        file_name: &str,
        private_key: &str,
    ) -> Result<Vec<u8>>;
}

/// The contact service is responsible for managing the local contacts
#[derive(Clone)]
pub struct ContactService {
    store: Arc<dyn ContactStoreApi>,
    file_upload_store: Arc<dyn FileUploadStoreApi>,
    identity_store: Arc<dyn IdentityStoreApi>,
}

impl ContactService {
    pub fn new(
        store: Arc<dyn ContactStoreApi>,
        file_upload_store: Arc<dyn FileUploadStoreApi>,
        identity_store: Arc<dyn IdentityStoreApi>,
    ) -> Self {
        Self {
            store,
            file_upload_store,
            identity_store,
        }
    }

    async fn process_upload_file(
        &self,
        upload_id: &Option<String>,
        id: &str,
        public_key: &str,
    ) -> Result<Option<File>> {
        if let Some(upload_id) = upload_id {
            debug!("processing upload file for contact {id}: {upload_id:?}");
            let (file_name, file_bytes) = &self
                .file_upload_store
                .read_temp_upload_file(upload_id)
                .await
                .map_err(|_| crate::service::Error::NoFileForFileUploadId)?;
            let file = self
                .encrypt_and_save_uploaded_file(file_name, file_bytes, id, public_key)
                .await?;
            return Ok(Some(file));
        }
        Ok(None)
    }

    async fn encrypt_and_save_uploaded_file(
        &self,
        file_name: &str,
        file_bytes: &[u8],
        node_id: &str,
        public_key: &str,
    ) -> Result<File> {
        let file_hash = util::sha256_hash(file_bytes);
        let encrypted = util::crypto::encrypt_ecies(file_bytes, public_key)?;
        self.file_upload_store
            .save_attached_file(&encrypted, node_id, file_name)
            .await?;
        info!("Saved contact file {file_name} with hash {file_hash} for contact {node_id}");
        Ok(File {
            name: file_name.to_owned(),
            hash: file_hash,
        })
    }
}

#[async_trait]
impl ContactServiceApi for ContactService {
    async fn search(&self, search_term: &str) -> Result<Vec<Contact>> {
        let contacts = self.store.search(search_term).await?;
        Ok(contacts)
    }

    async fn get_contacts(&self) -> Result<Vec<Contact>> {
        let contact_map = self.store.get_map().await?;
        let contact_list: Vec<Contact> = contact_map.into_values().collect();
        Ok(contact_list)
    }

    async fn get_contact(&self, node_id: &str) -> Result<Contact> {
        debug!("getting contact for {node_id}");
        let res = self.store.get(node_id).await?;
        match res {
            None => Err(super::Error::NotFound),
            Some(contact) => Ok(contact),
        }
    }

    async fn get_identity_by_node_id(&self, node_id: &str) -> Result<Option<BillParticipant>> {
        let res = self.store.get(node_id).await?;
        res.map(|c| c.try_into().map_err(super::Error::Validation))
            .transpose()
    }

    async fn delete(&self, node_id: &str) -> Result<()> {
        self.store.delete(node_id).await?;
        Ok(())
    }

    async fn update_contact(
        &self,
        node_id: &str,
        name: Option<String>,
        email: Option<String>,
        postal_address: OptionalPostalAddress,
        date_of_birth_or_registration: Option<String>,
        country_of_birth_or_registration: Option<String>,
        city_of_birth_or_registration: Option<String>,
        identification_number: Option<String>,
        avatar_file_upload_id: Option<String>,
        proof_document_file_upload_id: Option<String>,
    ) -> Result<()> {
        debug!("updating contact with node_id: {node_id}");
        let mut contact = match self.store.get(node_id).await? {
            Some(contact) => contact,
            None => {
                return Err(super::Error::NotFound);
            }
        };
        validate_update_contact(
            contact.t.clone(),
            &name,
            &email,
            &postal_address,
            &avatar_file_upload_id,
            &proof_document_file_upload_id,
        )?;

        let mut changed = false;

        if let Some(ref name_to_set) = name {
            contact.name = name_to_set.clone();
            changed = true;
        }

        // for anonymous contact, we only consider email and name
        if contact.t == ContactType::Anon {
            util::update_optional_field(&mut contact.email, &email, &mut changed);
        } else {
            let identity_public_key = self.identity_store.get_key_pair().await?.get_public_key();

            if let Some(ref email_to_set) = email {
                contact.email = Some(email_to_set.clone());
                changed = true;
            }

            if let Some(ref mut contact_postal_address) = contact.postal_address {
                if let Some(ref postal_address_city_to_set) = postal_address.city {
                    contact_postal_address.city = postal_address_city_to_set.clone();
                    changed = true;
                }

                if let Some(ref postal_address_country_to_set) = postal_address.country {
                    contact_postal_address.country = postal_address_country_to_set.clone();
                    changed = true;
                }

                util::update_optional_field(
                    &mut contact_postal_address.zip,
                    &postal_address.zip,
                    &mut changed,
                );

                if let Some(ref postal_address_address_to_set) = postal_address.address {
                    contact_postal_address.address = postal_address_address_to_set.clone();
                    changed = true;
                }
            } else {
                return Err(super::Error::Validation(ValidationError::InvalidContact(
                    contact.node_id.to_owned(),
                )));
            }

            util::update_optional_field(
                &mut contact.date_of_birth_or_registration,
                &date_of_birth_or_registration,
                &mut changed,
            );

            util::update_optional_field(
                &mut contact.country_of_birth_or_registration,
                &country_of_birth_or_registration,
                &mut changed,
            );

            util::update_optional_field(
                &mut contact.city_of_birth_or_registration,
                &city_of_birth_or_registration,
                &mut changed,
            );

            util::update_optional_field(
                &mut contact.identification_number,
                &identification_number,
                &mut changed,
            );

            if !changed
                && avatar_file_upload_id.is_none()
                && proof_document_file_upload_id.is_none()
            {
                return Ok(());
            }

            let avatar_file = self
                .process_upload_file(&avatar_file_upload_id, node_id, &identity_public_key)
                .await?;
            // only override the picture, if there is a new one
            if avatar_file.is_some() {
                contact.avatar_file = avatar_file;
            }
            let proof_document_file = self
                .process_upload_file(
                    &proof_document_file_upload_id,
                    node_id,
                    &identity_public_key,
                )
                .await?;
            // only override the document, if there is a new one
            if proof_document_file.is_some() {
                contact.proof_document_file = proof_document_file;
            }
        }

        self.store.update(node_id, contact).await?;
        debug!("updated contact with node_id: {node_id}");

        Ok(())
    }

    async fn add_contact(
        &self,
        node_id: &str,
        t: ContactType,
        name: String,
        email: Option<String>,
        postal_address: Option<PostalAddress>,
        date_of_birth_or_registration: Option<String>,
        country_of_birth_or_registration: Option<String>,
        city_of_birth_or_registration: Option<String>,
        identification_number: Option<String>,
        avatar_file_upload_id: Option<String>,
        proof_document_file_upload_id: Option<String>,
    ) -> Result<Contact> {
        debug!("creating {:?} contact with node_id {node_id}", &t);
        validate_create_contact(
            t.clone(),
            node_id,
            &name,
            &email,
            &postal_address,
            &avatar_file_upload_id,
            &proof_document_file_upload_id,
        )?;

        let identity_public_key = self.identity_store.get_key_pair().await?.get_public_key();

        let contact = match t {
            ContactType::Company | ContactType::Person => {
                let avatar_file = self
                    .process_upload_file(&avatar_file_upload_id, node_id, &identity_public_key)
                    .await?;

                let proof_document_file = self
                    .process_upload_file(
                        &proof_document_file_upload_id,
                        node_id,
                        &identity_public_key,
                    )
                    .await?;

                Contact {
                    node_id: node_id.to_owned(),
                    t: t.clone(),
                    name,
                    email,
                    postal_address,
                    date_of_birth_or_registration,
                    country_of_birth_or_registration,
                    city_of_birth_or_registration,
                    identification_number,
                    avatar_file,
                    proof_document_file,
                    nostr_relays: get_config().nostr_relays.clone(), // Use the configured relays for now
                }
            }
            ContactType::Anon => {
                Contact {
                    node_id: node_id.to_owned(),
                    t: t.clone(),
                    name,
                    email,
                    postal_address: None,
                    date_of_birth_or_registration: None,
                    country_of_birth_or_registration: None,
                    city_of_birth_or_registration: None,
                    identification_number: None,
                    avatar_file: None,
                    proof_document_file: None,
                    nostr_relays: get_config().nostr_relays.clone(), // Use the configured relays for now
                }
            }
        };

        self.store.insert(node_id, contact.clone()).await?;
        debug!("contact {:?} with node_id {node_id} created", &t);
        Ok(contact)
    }

    async fn deanonymize_contact(
        &self,
        node_id: &str,
        t: ContactType,
        name: String,
        email: Option<String>,
        postal_address: Option<PostalAddress>,
        date_of_birth_or_registration: Option<String>,
        country_of_birth_or_registration: Option<String>,
        city_of_birth_or_registration: Option<String>,
        identification_number: Option<String>,
        avatar_file_upload_id: Option<String>,
        proof_document_file_upload_id: Option<String>,
    ) -> Result<Contact> {
        debug!("de-anonymizing {:?} contact with node_id {node_id}", &t);
        validate_create_contact(
            t.clone(),
            node_id,
            &name,
            &email,
            &postal_address,
            &avatar_file_upload_id,
            &proof_document_file_upload_id,
        )?;

        // can't de-anonymize to an anonymous contact
        if t == ContactType::Anon {
            return Err(super::Error::Validation(
                ValidationError::InvalidContactType,
            ));
        }

        let existing_anon_contact = match self.store.get(node_id).await? {
            Some(existing_anon_contact) => existing_anon_contact,
            None => {
                return Err(super::Error::NotFound);
            }
        };

        // if the existing contact is not anonymous, the action is not valid
        if existing_anon_contact.t != ContactType::Anon {
            return Err(super::Error::Validation(ValidationError::InvalidContact(
                node_id.to_owned(),
            )));
        }

        let identity_public_key = self.identity_store.get_key_pair().await?.get_public_key();
        let avatar_file = self
            .process_upload_file(&avatar_file_upload_id, node_id, &identity_public_key)
            .await?;

        let proof_document_file = self
            .process_upload_file(
                &proof_document_file_upload_id,
                node_id,
                &identity_public_key,
            )
            .await?;

        let contact = Contact {
            node_id: node_id.to_owned(),
            t: t.clone(),
            name,
            email,
            postal_address,
            date_of_birth_or_registration,
            country_of_birth_or_registration,
            city_of_birth_or_registration,
            identification_number,
            avatar_file,
            proof_document_file,
            nostr_relays: get_config().nostr_relays.clone(), // Use the configured relays for now
        };

        self.store.update(node_id, contact.clone()).await?;
        debug!("deanonymized contact with node_id: {node_id}");

        Ok(contact)
    }

    async fn is_known_npub(&self, npub: &str) -> Result<bool> {
        let node_id_list: Vec<String> = self.store.get_map().await?.into_keys().collect();
        Ok(node_id_list
            .iter()
            .any(|node_id| util::crypto::is_node_id_nostr_hex_npub(node_id, npub)))
    }

    async fn open_and_decrypt_file(
        &self,
        id: &str,
        file_name: &str,
        private_key: &str,
    ) -> Result<Vec<u8>> {
        debug!("getting file {file_name} for contact with id: {id}",);
        let read_file = self
            .file_upload_store
            .open_attached_file(id, file_name)
            .await?;
        let decrypted = util::crypto::decrypt_ecies(&read_file, private_key)?;
        Ok(decrypted)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{
        service::Error,
        tests::tests::{
            MockContactStoreApiMock, MockFileUploadStoreApiMock, MockIdentityStoreApiMock,
            TEST_NODE_ID_SECP, TEST_NODE_ID_SECP_AS_NPUB_HEX, empty_address,
            empty_optional_address, init_test_cfg,
        },
    };
    use std::collections::HashMap;
    use util::BcrKeys;

    pub fn get_baseline_contact() -> Contact {
        Contact {
            t: ContactType::Person,
            node_id: TEST_NODE_ID_SECP.to_owned(),
            name: "some_name".to_string(),
            email: Some("some_mail@example.com".to_string()),
            postal_address: Some(empty_address()),
            date_of_birth_or_registration: None,
            country_of_birth_or_registration: None,
            city_of_birth_or_registration: None,
            identification_number: None,
            avatar_file: None,
            proof_document_file: None,
            nostr_relays: vec![],
        }
    }

    fn get_service(
        mock_storage: MockContactStoreApiMock,
        mock_file_upload_storage: MockFileUploadStoreApiMock,
        mock_identity_storage: MockIdentityStoreApiMock,
    ) -> ContactService {
        ContactService::new(
            Arc::new(mock_storage),
            Arc::new(mock_file_upload_storage),
            Arc::new(mock_identity_storage),
        )
    }

    fn get_storages() -> (
        MockContactStoreApiMock,
        MockFileUploadStoreApiMock,
        MockIdentityStoreApiMock,
    ) {
        (
            MockContactStoreApiMock::new(),
            MockFileUploadStoreApiMock::new(),
            MockIdentityStoreApiMock::new(),
        )
    }

    #[tokio::test]
    async fn get_contacts_baseline() {
        let (mut store, file_upload_store, identity_store) = get_storages();
        store.expect_get_map().returning(|| {
            let mut contact = get_baseline_contact();
            contact.name = "Minka".to_string();
            let mut map = HashMap::new();
            map.insert(TEST_NODE_ID_SECP.to_string(), contact);
            Ok(map)
        });
        let result = get_service(store, file_upload_store, identity_store)
            .get_contacts()
            .await;
        assert!(result.is_ok());
        assert_eq!(result.as_ref().unwrap().first().unwrap().name, *"Minka");
        assert_eq!(
            result.as_ref().unwrap().first().unwrap().node_id,
            *TEST_NODE_ID_SECP
        );
    }

    #[tokio::test]
    async fn get_identity_by_node_id_baseline() {
        let (mut store, file_upload_store, identity_store) = get_storages();
        store.expect_get().returning(|_| {
            let mut contact = get_baseline_contact();
            contact.name = "Minka".to_string();
            Ok(Some(contact))
        });
        let result = get_service(store, file_upload_store, identity_store)
            .get_identity_by_node_id(TEST_NODE_ID_SECP)
            .await;
        assert!(result.is_ok());
        assert_eq!(
            result.as_ref().unwrap().as_ref().unwrap().name(),
            Some("Minka".into())
        );
    }

    #[tokio::test]
    async fn delete_contact() {
        let (mut store, file_upload_store, identity_store) = get_storages();
        store.expect_delete().returning(|_| Ok(()));
        let result = get_service(store, file_upload_store, identity_store)
            .delete("some_name")
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn update_contact_calls_store() {
        let (mut store, file_upload_store, mut identity_store) = get_storages();
        identity_store
            .expect_get_key_pair()
            .returning(|| Ok(BcrKeys::new()));
        store.expect_get().returning(|_| {
            let contact = get_baseline_contact();
            Ok(Some(contact))
        });
        store.expect_update().returning(|_, _| Ok(()));
        let result = get_service(store, file_upload_store, identity_store)
            .update_contact(
                TEST_NODE_ID_SECP,
                Some("new_name".to_string()),
                None,
                empty_optional_address(),
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn add_contact_calls_store() {
        init_test_cfg();
        let (mut store, file_upload_store, mut identity_store) = get_storages();
        identity_store
            .expect_get_key_pair()
            .returning(|| Ok(BcrKeys::new()));
        store.expect_insert().returning(|_, _| Ok(()));
        let result = get_service(store, file_upload_store, identity_store)
            .add_contact(
                TEST_NODE_ID_SECP,
                ContactType::Person,
                "some_name".to_string(),
                Some("some_email@example.com".to_string()),
                Some(empty_address()),
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn add_anon_contact_calls_store() {
        init_test_cfg();
        let (mut store, file_upload_store, mut identity_store) = get_storages();
        identity_store
            .expect_get_key_pair()
            .returning(|| Ok(BcrKeys::new()));
        store.expect_insert().returning(|_, _| Ok(()));
        let result = get_service(store, file_upload_store, identity_store)
            .add_contact(
                TEST_NODE_ID_SECP,
                ContactType::Anon,
                "some_name".to_string(),
                Some("some_email@example.com".to_string()),
                Some(empty_address()),
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn deanonymize_contact_calls_store() {
        init_test_cfg();
        let (mut store, file_upload_store, mut identity_store) = get_storages();
        identity_store
            .expect_get_key_pair()
            .returning(|| Ok(BcrKeys::new()));
        store.expect_update().returning(|_, _| Ok(()));
        store.expect_get().returning(|_| {
            let mut contact = get_baseline_contact();
            contact.t = ContactType::Anon;
            Ok(Some(contact))
        });
        let result = get_service(store, file_upload_store, identity_store)
            .deanonymize_contact(
                TEST_NODE_ID_SECP,
                ContactType::Person,
                "some_name".to_string(),
                Some("some_email@example.com".to_string()),
                Some(empty_address()),
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn deanonymize_contact_of_non_anon_fails() {
        init_test_cfg();
        let (mut store, file_upload_store, mut identity_store) = get_storages();
        identity_store
            .expect_get_key_pair()
            .returning(|| Ok(BcrKeys::new()));
        store.expect_update().returning(|_, _| Ok(()));
        store.expect_get().returning(|_| {
            let contact = get_baseline_contact();
            Ok(Some(contact))
        });
        let result = get_service(store, file_upload_store, identity_store)
            .deanonymize_contact(
                TEST_NODE_ID_SECP,
                ContactType::Person,
                "some_name".to_string(),
                Some("some_email@example.com".to_string()),
                Some(empty_address()),
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .await;
        assert!(result.is_err());
        if let Err(Error::Validation(ValidationError::InvalidContact(node_id))) = result {
            assert_eq!(node_id, TEST_NODE_ID_SECP.to_owned());
        } else {
            panic!("wrong error");
        }
    }

    #[tokio::test]
    async fn deanonymize_contact_with_new_anon_fails() {
        init_test_cfg();
        let (mut store, file_upload_store, mut identity_store) = get_storages();
        identity_store
            .expect_get_key_pair()
            .returning(|| Ok(BcrKeys::new()));
        store.expect_update().returning(|_, _| Ok(()));
        store.expect_get().returning(|_| {
            let mut contact = get_baseline_contact();
            contact.t = ContactType::Anon;
            Ok(Some(contact))
        });
        let result = get_service(store, file_upload_store, identity_store)
            .deanonymize_contact(
                TEST_NODE_ID_SECP,
                ContactType::Anon,
                "some_name".to_string(),
                Some("some_email@example.com".to_string()),
                Some(empty_address()),
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .await;
        assert!(result.is_err());
        if let Err(Error::Validation(ValidationError::InvalidContactType)) = result {
            // fine
        } else {
            panic!("wrong error");
        }
    }

    #[tokio::test]
    async fn is_known_npub_calls_store() {
        let (mut store, file_upload_store, identity_store) = get_storages();
        store.expect_get_map().returning(|| {
            let contact = get_baseline_contact();
            let mut map = HashMap::new();
            map.insert(TEST_NODE_ID_SECP.to_string(), contact);
            Ok(map)
        });
        let result = get_service(store, file_upload_store, identity_store)
            .is_known_npub(TEST_NODE_ID_SECP_AS_NPUB_HEX)
            .await;
        assert!(result.is_ok());
        assert!(result.as_ref().unwrap());
    }
}
