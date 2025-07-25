use std::sync::Arc;

use async_trait::async_trait;
use bcr_ebill_core::{
    NodeId, PublicKey, SecretKey, ServiceTraitBounds, ValidationError,
    contact::{
        BillParticipant,
        validation::{validate_create_contact, validate_update_contact},
    },
    nostr_contact::{NostrContact, NostrPublicKey, TrustLevel},
};
use bcr_ebill_persistence::nostr::NostrContactStoreApi;
#[cfg(test)]
use mockall::automock;

use crate::{
    Config,
    data::{
        File, OptionalPostalAddress, PostalAddress,
        contact::{Contact, ContactType},
        validate_node_id_network,
    },
    external::file_storage::FileStorageClientApi,
    get_config,
    persistence::{
        contact::ContactStoreApi, file_upload::FileUploadStoreApi, identity::IdentityStoreApi,
    },
    util::{self, file::UploadFileType},
};

use super::Result;
use log::{debug, error, info};

#[cfg(test)]
impl ServiceTraitBounds for MockContactServiceApi {}

#[cfg_attr(test, automock)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait ContactServiceApi: ServiceTraitBounds {
    /// Searches contacts for the search term
    async fn search(&self, search_term: &str) -> Result<Vec<Contact>>;
    /// Returns all contacts in short form
    async fn get_contacts(&self) -> Result<Vec<Contact>>;

    /// Returns the contact details for the given node_id
    async fn get_contact(&self, node_id: &NodeId) -> Result<Contact>;

    /// Returns the contact by node id
    async fn get_identity_by_node_id(&self, node_id: &NodeId) -> Result<Option<BillParticipant>>;

    /// Deletes the contact with the given node_id.
    async fn delete(&self, node_id: &NodeId) -> Result<()>;

    /// Updates the contact with the given data.
    async fn update_contact(
        &self,
        node_id: &NodeId,
        name: Option<String>,
        email: Option<String>,
        postal_address: OptionalPostalAddress,
        date_of_birth_or_registration: Option<String>,
        country_of_birth_or_registration: Option<String>,
        city_of_birth_or_registration: Option<String>,
        identification_number: Option<String>,
        avatar_file_upload_id: Option<String>,
        ignore_avatar_file_upload_id: bool,
        proof_document_file_upload_id: Option<String>,
        ignore_proof_document_file_upload_id: bool,
    ) -> Result<()>;

    /// Adds a new contact
    async fn add_contact(
        &self,
        node_id: &NodeId,
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
        node_id: &NodeId,
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
    async fn is_known_npub(&self, npub: &NostrPublicKey) -> Result<bool>;

    /// Returns the Npubs we want to subscribe to on Nostr.
    async fn get_nostr_npubs(&self) -> Result<Vec<NostrPublicKey>>;

    /// Returns a Nostr contact by node id if we have a trusted one.
    async fn get_nostr_contact_by_node_id(&self, node_id: &NodeId) -> Result<Option<NostrContact>>;

    /// opens and decrypts the attached file from the given contact
    async fn open_and_decrypt_file(
        &self,
        contact: Contact,
        id: &NodeId,
        file_name: &str,
        private_key: &SecretKey,
    ) -> Result<Vec<u8>>;
}

/// The contact service is responsible for managing the local contacts
#[derive(Clone)]
pub struct ContactService {
    store: Arc<dyn ContactStoreApi>,
    file_upload_store: Arc<dyn FileUploadStoreApi>,
    file_upload_client: Arc<dyn FileStorageClientApi>,
    identity_store: Arc<dyn IdentityStoreApi>,
    nostr_contact_store: Arc<dyn NostrContactStoreApi>,
    config: Config,
}

impl ContactService {
    pub fn new(
        store: Arc<dyn ContactStoreApi>,
        file_upload_store: Arc<dyn FileUploadStoreApi>,
        file_upload_client: Arc<dyn FileStorageClientApi>,
        identity_store: Arc<dyn IdentityStoreApi>,
        nostr_contact_store: Arc<dyn NostrContactStoreApi>,
        config: &Config,
    ) -> Self {
        Self {
            store,
            file_upload_store,
            file_upload_client,
            identity_store,
            nostr_contact_store,
            config: config.clone(),
        }
    }

    async fn process_upload_file(
        &self,
        upload_id: &Option<String>,
        id: &NodeId,
        public_key: &PublicKey,
        relay_url: &str,
        upload_file_type: UploadFileType,
    ) -> Result<Option<File>> {
        if let Some(upload_id) = upload_id {
            debug!("processing upload file for contact {id}: {upload_id:?}");
            let (file_name, file_bytes) = &self
                .file_upload_store
                .read_temp_upload_file(upload_id)
                .await
                .map_err(|_| crate::service::Error::NoFileForFileUploadId)?;
            // validate file size for upload file type
            if !upload_file_type.check_file_size(file_bytes.len()) {
                return Err(crate::service::Error::Validation(
                    ValidationError::FileIsTooBig(upload_file_type.max_file_size()),
                ));
            }
            let file = self
                .encrypt_and_save_uploaded_file(file_name, file_bytes, id, public_key, relay_url)
                .await?;
            return Ok(Some(file));
        }
        Ok(None)
    }

    async fn encrypt_and_save_uploaded_file(
        &self,
        file_name: &str,
        file_bytes: &[u8],
        node_id: &NodeId,
        public_key: &PublicKey,
        relay_url: &str,
    ) -> Result<File> {
        let file_hash = util::sha256_hash(file_bytes);
        let encrypted = util::crypto::encrypt_ecies(file_bytes, public_key)?;
        let nostr_hash = self.file_upload_client.upload(relay_url, encrypted).await?;
        info!("Saved contact file {file_name} with hash {file_hash} for contact {node_id}");
        Ok(File {
            name: file_name.to_owned(),
            hash: file_hash,
            nostr_hash: nostr_hash.to_string(),
        })
    }

    async fn cascade_nostr_contact(&self, contact: &Contact) -> Result<()> {
        let nostr_contact = match self
            .nostr_contact_store
            .by_node_id(&contact.node_id)
            .await?
        {
            Some(nostr_contact) => nostr_contact.merge_contact(contact),
            None => NostrContact::from_contact(contact)?,
        };
        self.nostr_contact_store.upsert(&nostr_contact).await?;
        Ok(())
    }
}

impl ServiceTraitBounds for ContactService {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
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

    async fn get_contact(&self, node_id: &NodeId) -> Result<Contact> {
        validate_node_id_network(node_id)?;
        debug!("getting contact for {node_id}");
        let res = self.store.get(node_id).await?;
        match res {
            None => Err(super::Error::NotFound),
            Some(contact) => Ok(contact),
        }
    }

    async fn get_identity_by_node_id(&self, node_id: &NodeId) -> Result<Option<BillParticipant>> {
        validate_node_id_network(node_id)?;
        let res = self.store.get(node_id).await?;
        res.map(|c| c.try_into().map_err(super::Error::Validation))
            .transpose()
    }

    async fn delete(&self, node_id: &NodeId) -> Result<()> {
        validate_node_id_network(node_id)?;
        self.store.delete(node_id).await?;
        self.nostr_contact_store.delete(node_id).await?;
        Ok(())
    }

    async fn update_contact(
        &self,
        node_id: &NodeId,
        name: Option<String>,
        email: Option<String>,
        postal_address: OptionalPostalAddress,
        date_of_birth_or_registration: Option<String>,
        country_of_birth_or_registration: Option<String>,
        city_of_birth_or_registration: Option<String>,
        identification_number: Option<String>,
        avatar_file_upload_id: Option<String>,
        ignore_avatar_file_upload_id: bool,
        proof_document_file_upload_id: Option<String>,
        ignore_proof_document_file_upload_id: bool,
    ) -> Result<()> {
        debug!("updating contact with node_id: {node_id}");
        validate_node_id_network(node_id)?;
        let mut contact = match self.store.get(node_id).await? {
            Some(contact) => contact,
            None => {
                return Err(super::Error::NotFound);
            }
        };

        let nostr_relays = contact.nostr_relays.clone();

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
            let identity_public_key = self.identity_store.get_key_pair().await?.pub_key();

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
                    contact.node_id.to_string(),
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

            // remove the avatar
            if !ignore_avatar_file_upload_id && avatar_file_upload_id.is_none() {
                contact.avatar_file = None;
                changed = true;
            }

            // remove the proof document
            if !ignore_proof_document_file_upload_id && proof_document_file_upload_id.is_none() {
                contact.proof_document_file = None;
                changed = true;
            }

            if !changed {
                return Ok(());
            }

            if let Some(nostr_relay) = nostr_relays.first() {
                if !ignore_avatar_file_upload_id {
                    let avatar_file = self
                        .process_upload_file(
                            &avatar_file_upload_id,
                            node_id,
                            &identity_public_key,
                            nostr_relay,
                            UploadFileType::Picture,
                        )
                        .await?;
                    // only override the picture, if there is a new one
                    if avatar_file.is_some() {
                        contact.avatar_file = avatar_file;
                    }
                }

                if !ignore_proof_document_file_upload_id {
                    let proof_document_file = self
                        .process_upload_file(
                            &proof_document_file_upload_id,
                            node_id,
                            &identity_public_key,
                            nostr_relay,
                            UploadFileType::Document,
                        )
                        .await?;
                    // only override the document, if there is a new one
                    if proof_document_file.is_some() {
                        contact.proof_document_file = proof_document_file;
                    }
                }
            };
        }

        self.store.update(node_id, contact.clone()).await?;
        self.cascade_nostr_contact(&contact).await?;

        debug!("updated contact with node_id: {node_id}");

        Ok(())
    }

    async fn add_contact(
        &self,
        node_id: &NodeId,
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
        debug!("creating {t:?} contact with node_id {node_id}");
        validate_node_id_network(node_id)?;
        validate_create_contact(
            t.clone(),
            node_id,
            &name,
            &email,
            &postal_address,
            &avatar_file_upload_id,
            &proof_document_file_upload_id,
            get_config().bitcoin_network(),
        )?;

        let nostr_relays = get_config().nostr_config.relays.clone();
        let identity_public_key = self.identity_store.get_key_pair().await?.pub_key();

        let contact = match t {
            ContactType::Company | ContactType::Person => {
                let (avatar_file, proof_document_file) = match nostr_relays.first() {
                    Some(nostr_relay) => {
                        let avatar_file = self
                            .process_upload_file(
                                &avatar_file_upload_id,
                                node_id,
                                &identity_public_key,
                                nostr_relay,
                                UploadFileType::Picture,
                            )
                            .await?;

                        let proof_document_file = self
                            .process_upload_file(
                                &proof_document_file_upload_id,
                                node_id,
                                &identity_public_key,
                                nostr_relay,
                                UploadFileType::Document,
                            )
                            .await?;
                        (avatar_file, proof_document_file)
                    }
                    None => (None, None),
                };

                Contact {
                    node_id: node_id.clone(),
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
                    nostr_relays,
                }
            }
            ContactType::Anon => {
                Contact {
                    node_id: node_id.clone(),
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
                    nostr_relays: get_config().nostr_config.relays.clone(), // Use the configured relays for now
                }
            }
        };

        self.store.insert(node_id, contact.clone()).await?;
        self.cascade_nostr_contact(&contact).await?;
        debug!("contact {t:?} with node_id {node_id} created");
        Ok(contact)
    }

    async fn deanonymize_contact(
        &self,
        node_id: &NodeId,
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
        debug!("de-anonymizing {t:?} contact with node_id {node_id}");
        validate_node_id_network(node_id)?;
        validate_create_contact(
            t.clone(),
            node_id,
            &name,
            &email,
            &postal_address,
            &avatar_file_upload_id,
            &proof_document_file_upload_id,
            get_config().bitcoin_network(),
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

        let nostr_relays = existing_anon_contact.nostr_relays.clone();

        // if the existing contact is not anonymous, the action is not valid
        if existing_anon_contact.t != ContactType::Anon {
            return Err(super::Error::Validation(ValidationError::InvalidContact(
                node_id.to_string(),
            )));
        }

        let identity_public_key = self.identity_store.get_key_pair().await?.pub_key();

        let (avatar_file, proof_document_file) = match nostr_relays.first() {
            Some(nostr_relay) => {
                let avatar_file = self
                    .process_upload_file(
                        &avatar_file_upload_id,
                        node_id,
                        &identity_public_key,
                        nostr_relay,
                        UploadFileType::Picture,
                    )
                    .await?;

                let proof_document_file = self
                    .process_upload_file(
                        &proof_document_file_upload_id,
                        node_id,
                        &identity_public_key,
                        nostr_relay,
                        UploadFileType::Document,
                    )
                    .await?;
                (avatar_file, proof_document_file)
            }
            None => (None, None),
        };

        let contact = Contact {
            node_id: node_id.clone(),
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
            nostr_relays: self.config.nostr_config.relays.clone(),
        };

        debug!("contact {t:?} with node_id {node_id} created");
        self.store.update(node_id, contact.clone()).await?;
        self.cascade_nostr_contact(&contact).await?;
        debug!("deanonymized contact with node_id: {node_id}");
        Ok(contact)
    }

    async fn is_known_npub(&self, npub: &NostrPublicKey) -> Result<bool> {
        Ok(!self.config.nostr_config.only_known_contacts
            || self
                .nostr_contact_store
                .by_npub(npub)
                .await?
                .map(|c| c.trust_level != TrustLevel::None)
                .unwrap_or(false))
    }

    /// Returns the Npubs we want to subscribe to on Nostr.
    async fn get_nostr_npubs(&self) -> Result<Vec<NostrPublicKey>> {
        Ok(self
            .nostr_contact_store
            .get_npubs(vec![TrustLevel::Trusted, TrustLevel::Participant])
            .await?)
    }

    /// Returns a Nostr contact by node id if we have a trusted or participant one.
    async fn get_nostr_contact_by_node_id(&self, node_id: &NodeId) -> Result<Option<NostrContact>> {
        validate_node_id_network(node_id)?;
        match self.nostr_contact_store.by_node_id(node_id).await {
            Ok(Some(c)) if c.trust_level != TrustLevel::None => Ok(Some(c)),
            _ => Ok(None),
        }
    }

    async fn open_and_decrypt_file(
        &self,
        contact: Contact,
        node_id: &NodeId,
        file_name: &str,
        private_key: &SecretKey,
    ) -> Result<Vec<u8>> {
        debug!("getting file {file_name} for contact with id: {node_id}",);
        validate_node_id_network(node_id)?;
        let nostr_relays = contact.nostr_relays.clone();
        if let Some(nostr_relay) = nostr_relays.first() {
            let mut file = None;
            if let Some(avatar_file) = contact.avatar_file {
                if avatar_file.name == file_name {
                    file = Some(avatar_file);
                }
            }

            if let Some(proof_document_file) = contact.proof_document_file {
                if proof_document_file.name == file_name {
                    file = Some(proof_document_file);
                }
            }

            if let Some(file) = file {
                let file_bytes = self
                    .file_upload_client
                    .download(nostr_relay, &file.nostr_hash)
                    .await?;
                let decrypted = util::crypto::decrypt_ecies(&file_bytes, private_key)?;
                let file_hash = util::sha256_hash(&decrypted);
                if file_hash != file.hash {
                    error!("Hash for contact file {file_name} did not match uploaded file");
                    return Err(super::Error::NotFound);
                }
                Ok(decrypted)
            } else {
                return Err(super::Error::NotFound);
            }
        } else {
            return Err(super::Error::NotFound);
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{
        external::file_storage::MockFileStorageClientApi,
        get_config,
        service::Error,
        tests::tests::{
            MockContactStoreApiMock, MockFileUploadStoreApiMock, MockIdentityStoreApiMock,
            MockNostrContactStore, NODE_ID_TEST_STR, TEST_NODE_ID_SECP_AS_NPUB_HEX, empty_address,
            empty_optional_address, init_test_cfg, node_id_test,
        },
    };
    use bcr_ebill_core::nostr_contact::{HandshakeStatus, NostrPublicKey};
    use std::collections::HashMap;
    use util::BcrKeys;

    pub fn get_baseline_contact() -> Contact {
        Contact {
            t: ContactType::Person,
            node_id: node_id_test(),
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
        mock_file_upload_client: MockFileStorageClientApi,
        mock_identity_storage: MockIdentityStoreApiMock,
        mock_nostr_contact_store: MockNostrContactStore,
    ) -> ContactService {
        ContactService::new(
            Arc::new(mock_storage),
            Arc::new(mock_file_upload_storage),
            Arc::new(mock_file_upload_client),
            Arc::new(mock_identity_storage),
            Arc::new(mock_nostr_contact_store),
            get_config(),
        )
    }

    fn get_storages() -> (
        MockContactStoreApiMock,
        MockFileUploadStoreApiMock,
        MockFileStorageClientApi,
        MockIdentityStoreApiMock,
        MockNostrContactStore,
    ) {
        (
            MockContactStoreApiMock::new(),
            MockFileUploadStoreApiMock::new(),
            MockFileStorageClientApi::new(),
            MockIdentityStoreApiMock::new(),
            MockNostrContactStore::new(),
        )
    }

    #[tokio::test]
    async fn get_contacts_baseline() {
        let (mut store, file_upload_store, file_upload_client, identity_store, nostr_contact) =
            get_storages();
        store.expect_get_map().returning(|| {
            let mut contact = get_baseline_contact();
            contact.name = "Minka".to_string();
            let mut map = HashMap::new();
            map.insert(node_id_test(), contact);
            Ok(map)
        });
        let result = get_service(
            store,
            file_upload_store,
            file_upload_client,
            identity_store,
            nostr_contact,
        )
        .get_contacts()
        .await;
        assert!(result.is_ok());
        assert_eq!(result.as_ref().unwrap().first().unwrap().name, *"Minka");
        assert_eq!(
            result.as_ref().unwrap().first().unwrap().node_id,
            node_id_test()
        );
    }

    #[tokio::test]
    async fn get_identity_by_node_id_baseline() {
        let (mut store, file_upload_store, file_upload_client, identity_store, nostr_contact) =
            get_storages();
        store.expect_get().returning(|_| {
            let mut contact = get_baseline_contact();
            contact.name = "Minka".to_string();
            Ok(Some(contact))
        });
        let result = get_service(
            store,
            file_upload_store,
            file_upload_client,
            identity_store,
            nostr_contact,
        )
        .get_identity_by_node_id(&node_id_test())
        .await;
        assert!(result.is_ok());
        assert_eq!(
            result.as_ref().unwrap().as_ref().unwrap().name(),
            Some("Minka".into())
        );
    }

    #[tokio::test]
    async fn wrong_network_failures() {
        let (store, file_upload_store, file_upload_client, identity_store, nostr_contact) =
            get_storages();
        let mainnet_node_id = NodeId::new(BcrKeys::new().pub_key(), bitcoin::Network::Bitcoin);
        let service = get_service(
            store,
            file_upload_store,
            file_upload_client,
            identity_store,
            nostr_contact,
        );

        assert!(
            service
                .get_identity_by_node_id(&mainnet_node_id)
                .await
                .is_err()
        );
        assert!(service.delete(&mainnet_node_id).await.is_err());
        assert!(service.get_contact(&mainnet_node_id).await.is_err());
        assert!(
            service
                .get_nostr_contact_by_node_id(&mainnet_node_id)
                .await
                .is_err()
        );
        assert!(
            service
                .update_contact(
                    &mainnet_node_id,
                    None,
                    None,
                    OptionalPostalAddress::empty(),
                    None,
                    None,
                    None,
                    None,
                    None,
                    true,
                    None,
                    true,
                )
                .await
                .is_err()
        );
        assert!(
            service
                .add_contact(
                    &mainnet_node_id,
                    ContactType::Person,
                    "name".to_string(),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
                .await
                .is_err()
        );
        assert!(
            service
                .deanonymize_contact(
                    &mainnet_node_id,
                    ContactType::Person,
                    "name".to_string(),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn delete_contact() {
        let (mut store, file_upload_store, file_upload_client, identity_store, mut nostr_contact) =
            get_storages();
        store.expect_delete().returning(|_| Ok(()));
        nostr_contact.expect_delete().returning(|_| Ok(()));
        let result = get_service(
            store,
            file_upload_store,
            file_upload_client,
            identity_store,
            nostr_contact,
        )
        .delete(&node_id_test())
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn update_contact_calls_store() {
        let (
            mut store,
            file_upload_store,
            file_upload_client,
            mut identity_store,
            mut nostr_contact,
        ) = get_storages();
        identity_store
            .expect_get_key_pair()
            .returning(|| Ok(BcrKeys::new()));
        store.expect_get().returning(|_| {
            let contact = get_baseline_contact();
            Ok(Some(contact))
        });
        store.expect_update().returning(|_, _| Ok(()));
        nostr_contact.expect_by_node_id().returning(|_| Ok(None));
        nostr_contact.expect_upsert().returning(|_| Ok(()));
        let result = get_service(
            store,
            file_upload_store,
            file_upload_client,
            identity_store,
            nostr_contact,
        )
        .update_contact(
            &node_id_test(),
            Some("new_name".to_string()),
            None,
            empty_optional_address(),
            None,
            None,
            None,
            None,
            None,
            true,
            None,
            true,
        )
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn add_contact_calls_store() {
        init_test_cfg();
        let (
            mut store,
            file_upload_store,
            file_upload_client,
            mut identity_store,
            mut nostr_contact,
        ) = get_storages();
        identity_store
            .expect_get_key_pair()
            .returning(|| Ok(BcrKeys::new()));
        nostr_contact.expect_by_node_id().returning(|_| Ok(None));
        store.expect_insert().returning(|_, _| Ok(()));
        nostr_contact.expect_upsert().returning(|_| Ok(()));
        let result = get_service(
            store,
            file_upload_store,
            file_upload_client,
            identity_store,
            nostr_contact,
        )
        .add_contact(
            &node_id_test(),
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
        let (
            mut store,
            file_upload_store,
            file_upload_client,
            mut identity_store,
            mut nostr_contact_store,
        ) = get_storages();
        identity_store
            .expect_get_key_pair()
            .returning(|| Ok(BcrKeys::new()));
        store.expect_insert().returning(|_, _| Ok(()));
        nostr_contact_store
            .expect_by_node_id()
            .returning(|_| Ok(None));
        nostr_contact_store.expect_upsert().returning(|_| Ok(()));
        let result = get_service(
            store,
            file_upload_store,
            file_upload_client,
            identity_store,
            nostr_contact_store,
        )
        .add_contact(
            &node_id_test(),
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
        let (
            mut store,
            file_upload_store,
            file_upload_client,
            mut identity_store,
            mut nostr_contact_store,
        ) = get_storages();
        identity_store
            .expect_get_key_pair()
            .returning(|| Ok(BcrKeys::new()));
        store.expect_update().returning(|_, _| Ok(()));
        store.expect_get().returning(|_| {
            let mut contact = get_baseline_contact();
            contact.t = ContactType::Anon;
            Ok(Some(contact))
        });
        nostr_contact_store
            .expect_by_node_id()
            .returning(|_| Ok(None));
        nostr_contact_store.expect_upsert().returning(|_| Ok(()));
        let result = get_service(
            store,
            file_upload_store,
            file_upload_client,
            identity_store,
            nostr_contact_store,
        )
        .deanonymize_contact(
            &node_id_test(),
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
        let (
            mut store,
            file_upload_store,
            file_upload_client,
            mut identity_store,
            nostr_contact_store,
        ) = get_storages();
        identity_store
            .expect_get_key_pair()
            .returning(|| Ok(BcrKeys::new()));
        store.expect_update().returning(|_, _| Ok(()));
        store.expect_get().returning(|_| {
            let contact = get_baseline_contact();
            Ok(Some(contact))
        });
        let result = get_service(
            store,
            file_upload_store,
            file_upload_client,
            identity_store,
            nostr_contact_store,
        )
        .deanonymize_contact(
            &node_id_test(),
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
            assert_eq!(node_id, NODE_ID_TEST_STR.to_owned());
        } else {
            panic!("wrong error");
        }
    }

    #[tokio::test]
    async fn deanonymize_contact_with_new_anon_fails() {
        init_test_cfg();
        let (
            mut store,
            file_upload_store,
            file_upload_client,
            mut identity_store,
            nostr_contact_store,
        ) = get_storages();
        identity_store
            .expect_get_key_pair()
            .returning(|| Ok(BcrKeys::new()));
        store.expect_update().returning(|_, _| Ok(()));
        store.expect_get().returning(|_| {
            let mut contact = get_baseline_contact();
            contact.t = ContactType::Anon;
            Ok(Some(contact))
        });
        let result = get_service(
            store,
            file_upload_store,
            file_upload_client,
            identity_store,
            nostr_contact_store,
        )
        .deanonymize_contact(
            &node_id_test(),
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
        let (store, file_upload_store, file_upload_client, identity_store, mut nostr_contact) =
            get_storages();
        let pub_key = NostrPublicKey::from_hex(TEST_NODE_ID_SECP_AS_NPUB_HEX).unwrap();
        nostr_contact.expect_by_npub().returning(|_| {
            Ok(Some(NostrContact {
                npub: NostrPublicKey::parse(TEST_NODE_ID_SECP_AS_NPUB_HEX).unwrap(),
                name: None,
                relays: vec![],
                trust_level: TrustLevel::Participant,
                handshake_status: HandshakeStatus::None,
            }))
        });
        let result = get_service(
            store,
            file_upload_store,
            file_upload_client,
            identity_store,
            nostr_contact,
        )
        .is_known_npub(&pub_key)
        .await;
        assert!(result.is_ok());
        assert!(result.as_ref().unwrap());
    }
}
