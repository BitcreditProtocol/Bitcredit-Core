use super::Result;
use super::notification_service::NotificationServiceApi;
use super::notification_service::event::IdentityChainEvent;
use crate::data::validate_node_id_network;
use crate::external::file_storage::FileStorageClientApi;
use crate::service::Error;
use crate::service::notification_service::{BcrMetadata, NostrContactData};
use crate::util::file::UploadFileType;
use crate::{get_config, util};
use crate::{persistence::identity::IdentityStoreApi, util::BcrKeys};

use crate::blockchain::Blockchain;
use crate::blockchain::identity::{IdentityBlock, IdentityBlockchain, IdentityUpdateBlockData};
use crate::data::{
    File, OptionalPostalAddress, PublicKey, SecretKey,
    identity::{Identity, IdentityWithAll},
};
use crate::persistence::file_upload::FileUploadStoreApi;
use crate::persistence::identity::IdentityChainStoreApi;
use async_trait::async_trait;
use bcr_ebill_core::blockchain::identity::IdentityBlockPlaintextWrapper;
use bcr_ebill_core::country::Country;
use bcr_ebill_core::identity::validation::{validate_create_identity, validate_update_identity};
use bcr_ebill_core::identity::{ActiveIdentityState, IdentityType};
use bcr_ebill_core::util::base58_encode;
use bcr_ebill_core::util::crypto::DeriveKeypair;
use bcr_ebill_core::{NodeId, ServiceTraitBounds, ValidationError};
use log::{debug, error, info};
use std::sync::Arc;

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait IdentityServiceApi: ServiceTraitBounds {
    /// Updates the identity
    async fn update_identity(
        &self,
        name: Option<String>,
        email: Option<String>,
        postal_address: OptionalPostalAddress,
        date_of_birth: Option<String>,
        country_of_birth: Option<Country>,
        city_of_birth: Option<String>,
        identification_number: Option<String>,
        profile_picture_file_upload_id: Option<String>,
        ignore_profile_picture_file_upload_id: bool,
        identity_document_file_upload_id: Option<String>,
        ignore_identity_document_file_upload_id: bool,
        timestamp: u64,
    ) -> Result<()>;
    /// Gets the full local identity, including the key pair and node id
    async fn get_full_identity(&self) -> Result<IdentityWithAll>;
    /// Gets the local identity
    async fn get_identity(&self) -> Result<Identity>;
    /// Checks if the identity has been created
    async fn identity_exists(&self) -> bool;
    /// Creates the identity
    async fn create_identity(
        &self,
        t: IdentityType,
        name: String,
        email: Option<String>,
        postal_address: OptionalPostalAddress,
        date_of_birth: Option<String>,
        country_of_birth: Option<Country>,
        city_of_birth: Option<String>,
        identification_number: Option<String>,
        profile_picture_file_upload_id: Option<String>,
        identity_document_file_upload_id: Option<String>,
        timestamp: u64,
    ) -> Result<()>;
    /// Deanonymizes an anon identity
    async fn deanonymize_identity(
        &self,
        t: IdentityType,
        name: String,
        email: Option<String>,
        postal_address: OptionalPostalAddress,
        date_of_birth: Option<String>,
        country_of_birth: Option<Country>,
        city_of_birth: Option<String>,
        identification_number: Option<String>,
        profile_picture_file_upload_id: Option<String>,
        identity_document_file_upload_id: Option<String>,
        timestamp: u64,
    ) -> Result<()>;
    async fn get_seedphrase(&self) -> Result<String>;
    /// Recovers the private keys in the identity from a seed phrase
    async fn recover_from_seedphrase(&self, seed: &str) -> Result<()>;

    /// opens and decrypts the attached file from the identity
    async fn open_and_decrypt_file(
        &self,
        identity: Identity,
        id: &NodeId,
        file_name: &str,
        private_key: &SecretKey,
    ) -> Result<Vec<u8>>;

    /// gets the currently set identity
    async fn get_current_identity(&self) -> Result<ActiveIdentityState>;

    /// sets the active identity to the given personal node id
    async fn set_current_personal_identity(&self, node_id: &NodeId) -> Result<()>;

    /// sets the active identity to the given company node id
    async fn set_current_company_identity(&self, node_id: &NodeId) -> Result<()>;

    /// Returns the local key pair
    async fn get_keys(&self) -> Result<BcrKeys>;

    /// Shares derived keys for private identity contact information. Recipient is the given node id.
    async fn share_contact_details(&self, share_to: &NodeId) -> Result<()>;

    /// If dev mode is on, return the full identity chain with decrypted data
    async fn dev_mode_get_full_identity_chain(&self) -> Result<Vec<IdentityBlockPlaintextWrapper>>;
}

/// The identity service is responsible for managing the local identity
#[derive(Clone)]
pub struct IdentityService {
    store: Arc<dyn IdentityStoreApi>,
    file_upload_store: Arc<dyn FileUploadStoreApi>,
    file_upload_client: Arc<dyn FileStorageClientApi>,
    blockchain_store: Arc<dyn IdentityChainStoreApi>,
    notification_service: Arc<dyn NotificationServiceApi>,
}

impl IdentityService {
    pub fn new(
        store: Arc<dyn IdentityStoreApi>,
        file_upload_store: Arc<dyn FileUploadStoreApi>,
        file_upload_client: Arc<dyn FileStorageClientApi>,
        blockchain_store: Arc<dyn IdentityChainStoreApi>,
        notification_service: Arc<dyn NotificationServiceApi>,
    ) -> Self {
        Self {
            store,
            file_upload_store,
            file_upload_client,
            blockchain_store,
            notification_service,
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
            debug!("processing upload file for identity {id}: {upload_id:?}");
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
        info!("Saved identity file {file_name} with hash {file_hash} for identity {node_id}");
        Ok(File {
            name: file_name.to_owned(),
            hash: file_hash,
            nostr_hash: nostr_hash.to_string(),
        })
    }

    async fn populate_block(
        &self,
        identity: &Identity,
        block: &IdentityBlock,
        keys: &BcrKeys,
    ) -> Result<()> {
        self.notification_service
            .send_identity_chain_events(IdentityChainEvent::new(identity, block, keys))
            .await?;
        Ok(())
    }

    async fn on_identity_contact_change(&self, identity: &Identity, keys: &BcrKeys) -> Result<()> {
        debug!("Identity change, publishing our identity contact to nostr profile");
        let bcr_data = get_bcr_data(identity, keys)?;
        let contact_data =
            NostrContactData::new(&identity.name, identity.nostr_relays.clone(), bcr_data);
        self.notification_service
            .publish_contact(&identity.node_id, &contact_data)
            .await?;
        Ok(())
    }
}

/// Derives a child key, encrypts the contact data with it and returns the bcr metadata
fn get_bcr_data(identity: &Identity, keys: &BcrKeys) -> Result<BcrMetadata> {
    let derived_keys = keys.derive_keypair()?;
    let contact = identity.as_contact(None);
    debug!("Publishing identity contact data: {contact:?}");
    let payload = serde_json::to_string(&contact)?;
    let encrypted = base58_encode(&util::crypto::encrypt_ecies(
        payload.as_bytes(),
        &derived_keys.public_key(),
    )?);
    Ok(BcrMetadata {
        contact_data: encrypted,
    })
}

impl ServiceTraitBounds for IdentityService {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl IdentityServiceApi for IdentityService {
    async fn get_full_identity(&self) -> Result<IdentityWithAll> {
        let identity = self.store.get_full().await?;
        Ok(identity)
    }

    async fn update_identity(
        &self,
        name: Option<String>,
        email: Option<String>,
        postal_address: OptionalPostalAddress,
        date_of_birth: Option<String>,
        country_of_birth: Option<Country>,
        city_of_birth: Option<String>,
        identification_number: Option<String>,
        profile_picture_file_upload_id: Option<String>,
        ignore_profile_picture_file_upload_id: bool,
        identity_document_file_upload_id: Option<String>,
        ignore_identity_document_file_upload_id: bool,
        timestamp: u64,
    ) -> Result<()> {
        debug!("updating identity");
        let mut identity = self.store.get().await?;
        let mut changed = false;

        let mut profile_picture_file = None;
        let mut identity_document_file = None;

        let nostr_relays = identity.nostr_relays.clone();

        let keys = self.store.get_key_pair().await?;

        validate_update_identity(
            identity.t.clone(),
            &name,
            &email,
            &postal_address,
            &profile_picture_file_upload_id,
            &identity_document_file_upload_id,
        )?;

        if let Some(ref name_to_set) = name
            && identity.name != name_to_set.trim()
        {
            identity.name = name_to_set.trim().to_owned();
            changed = true;
        }

        // for anonymous identity, we only consider email and name
        if identity.t == IdentityType::Anon {
            util::update_optional_field(&mut identity.email, &email, &mut changed);
        } else {
            if let Some(ref email_to_set) = email
                && identity.email != Some(email_to_set.trim().to_string())
            {
                identity.email = Some(email_to_set.trim().to_owned());
                changed = true;
            }

            if let Some(ref country_to_set) = postal_address.country
                && identity.postal_address.country.as_ref() != Some(country_to_set)
            {
                identity.postal_address.country = Some(country_to_set.to_owned());
                changed = true;
            }

            if let Some(ref city_to_set) = postal_address.city
                && identity.postal_address.city != Some(city_to_set.trim().to_string())
            {
                identity.postal_address.city = Some(city_to_set.trim().to_owned());
                changed = true;
            }

            util::update_optional_field(
                &mut identity.postal_address.zip,
                &postal_address.zip,
                &mut changed,
            );

            if let Some(ref address_to_set) = postal_address.address
                && identity.postal_address.address != Some(address_to_set.trim().to_string())
            {
                identity.postal_address.address = Some(address_to_set.trim().to_owned());
                changed = true;
            }

            util::update_optional_field(&mut identity.date_of_birth, &date_of_birth, &mut changed);

            util::update_optional_field(
                &mut identity.country_of_birth,
                &country_of_birth,
                &mut changed,
            );

            util::update_optional_field(&mut identity.city_of_birth, &city_of_birth, &mut changed);

            util::update_optional_field(
                &mut identity.identification_number,
                &identification_number,
                &mut changed,
            );

            // remove the profile picture
            if !ignore_profile_picture_file_upload_id && profile_picture_file_upload_id.is_none() {
                identity.profile_picture_file = None;
                changed = true;
            }

            // remove the identity document
            if !ignore_identity_document_file_upload_id
                && identity_document_file_upload_id.is_none()
            {
                identity.identity_document_file = None;
                changed = true;
            }

            if !changed {
                return Ok(());
            }

            // TODO(multi-relay): don't default to first
            if let Some(nostr_relay) = nostr_relays.first() {
                if !ignore_profile_picture_file_upload_id {
                    profile_picture_file = self
                        .process_upload_file(
                            &profile_picture_file_upload_id,
                            &identity.node_id,
                            &keys.pub_key(),
                            nostr_relay,
                            UploadFileType::Picture,
                        )
                        .await?;
                    // only override the picture, if there is a new one
                    if profile_picture_file.is_some() {
                        identity.profile_picture_file = profile_picture_file.clone();
                    }
                }

                if !ignore_identity_document_file_upload_id {
                    identity_document_file = self
                        .process_upload_file(
                            &identity_document_file_upload_id,
                            &identity.node_id,
                            &keys.pub_key(),
                            nostr_relay,
                            UploadFileType::Document,
                        )
                        .await?;
                    // only override the document, if there is a new one
                    if identity_document_file.is_some() {
                        identity.identity_document_file = identity_document_file.clone();
                    }
                }
            };
        }

        let previous_block = self.blockchain_store.get_latest_block().await?;
        let new_block = IdentityBlock::create_block_for_update(
            &previous_block,
            &IdentityUpdateBlockData {
                name,
                email,
                postal_address,
                date_of_birth,
                country_of_birth,
                city_of_birth,
                identification_number,
                profile_picture_file,
                identity_document_file,
            },
            &keys,
            timestamp,
        )?;
        self.blockchain_store.add_block(&new_block).await?;
        self.store.save(&identity).await?;
        self.populate_block(&identity, &new_block, &keys).await?;
        self.on_identity_contact_change(&identity, &keys).await?;
        debug!("updated identity");
        Ok(())
    }

    async fn get_identity(&self) -> Result<Identity> {
        let identity = self.store.get().await?;
        Ok(identity)
    }

    async fn identity_exists(&self) -> bool {
        self.store.exists().await
    }

    async fn create_identity(
        &self,
        t: IdentityType,
        name: String,
        email: Option<String>,
        postal_address: OptionalPostalAddress,
        date_of_birth: Option<String>,
        country_of_birth: Option<Country>,
        city_of_birth: Option<String>,
        identification_number: Option<String>,
        profile_picture_file_upload_id: Option<String>,
        identity_document_file_upload_id: Option<String>,
        timestamp: u64,
    ) -> Result<()> {
        debug!("creating identity");
        let keys = self.store.get_or_create_key_pair().await?;
        let node_id = NodeId::new(keys.pub_key(), get_config().bitcoin_network());
        validate_create_identity(
            t.clone(),
            &name,
            &email,
            &postal_address,
            &profile_picture_file_upload_id,
            &identity_document_file_upload_id,
        )?;
        let nostr_relays = get_config().nostr_config.relays.clone();

        let identity = match t {
            IdentityType::Ident => {
                // TODO(multi-relay): don't default to first
                let (profile_picture_file, identity_document_file) = match nostr_relays.first() {
                    Some(nostr_relay) => {
                        let profile_picture_file = self
                            .process_upload_file(
                                &profile_picture_file_upload_id,
                                &node_id,
                                &keys.pub_key(),
                                nostr_relay,
                                UploadFileType::Picture,
                            )
                            .await?;

                        let identity_document_file = self
                            .process_upload_file(
                                &identity_document_file_upload_id,
                                &node_id,
                                &keys.pub_key(),
                                nostr_relay,
                                UploadFileType::Document,
                            )
                            .await?;
                        (profile_picture_file, identity_document_file)
                    }
                    None => (None, None),
                };

                Identity {
                    t: t.clone(),
                    node_id: node_id.clone(),
                    name,
                    email,
                    postal_address,
                    date_of_birth,
                    country_of_birth,
                    city_of_birth,
                    identification_number,
                    profile_picture_file,
                    identity_document_file,
                    nostr_relays: get_config().nostr_config.relays.to_owned(),
                }
            }
            IdentityType::Anon => Identity {
                t: t.clone(),
                node_id: node_id.clone(),
                name,
                email,
                postal_address: OptionalPostalAddress::empty(),
                date_of_birth: None,
                country_of_birth: None,
                city_of_birth: None,
                identification_number: None,
                profile_picture_file: None,
                identity_document_file: None,
                nostr_relays: get_config().nostr_config.relays.to_owned(),
            },
        };

        // create new identity chain and persist it
        let identity_chain = IdentityBlockchain::new(&identity.clone().into(), &keys, timestamp)?;
        let first_block = identity_chain.get_first_block();
        self.blockchain_store.add_block(first_block).await?;

        // persist the identity in the DB
        self.store.save(&identity).await?;
        self.populate_block(&identity, first_block, &keys).await?;
        self.on_identity_contact_change(&identity, &keys).await?;

        debug!("created identity");
        Ok(())
    }

    async fn deanonymize_identity(
        &self,
        t: IdentityType,
        name: String,
        email: Option<String>,
        postal_address: OptionalPostalAddress,
        date_of_birth: Option<String>,
        country_of_birth: Option<Country>,
        city_of_birth: Option<String>,
        identification_number: Option<String>,
        profile_picture_file_upload_id: Option<String>,
        identity_document_file_upload_id: Option<String>,
        timestamp: u64,
    ) -> Result<()> {
        debug!("deanonymizing identity");
        let existing_identity = self.store.get().await?;
        let keys = self.store.get_key_pair().await?;
        let nostr_relays = existing_identity.nostr_relays.clone();

        // can't de-anonymize to an anonymous identity
        if t == IdentityType::Anon {
            return Err(super::Error::Validation(
                ValidationError::IdentityCantBeAnon,
            ));
        }

        // if the existing identity is not anon, the action is not valid
        if existing_identity.t != IdentityType::Anon {
            return Err(super::Error::Validation(
                ValidationError::InvalidIdentityType,
            ));
        }

        validate_create_identity(
            t.clone(),
            &name,
            &email,
            &postal_address,
            &profile_picture_file_upload_id,
            &identity_document_file_upload_id,
        )?;

        // TODO(multi-relay): don't default to first
        let (profile_picture_file, identity_document_file) = match nostr_relays.first() {
            Some(nostr_relay) => {
                let profile_picture_file = self
                    .process_upload_file(
                        &profile_picture_file_upload_id,
                        &existing_identity.node_id,
                        &keys.pub_key(),
                        nostr_relay,
                        UploadFileType::Picture,
                    )
                    .await?;

                let identity_document_file = self
                    .process_upload_file(
                        &identity_document_file_upload_id,
                        &existing_identity.node_id,
                        &keys.pub_key(),
                        nostr_relay,
                        UploadFileType::Document,
                    )
                    .await?;
                (profile_picture_file, identity_document_file)
            }
            None => (None, None),
        };

        let identity = Identity {
            t: t.clone(),
            node_id: existing_identity.node_id.clone(),
            name: name.clone(),
            email: email.clone(),
            postal_address: postal_address.clone(),
            date_of_birth: date_of_birth.clone(),
            country_of_birth: country_of_birth.clone(),
            city_of_birth: city_of_birth.clone(),
            identification_number: identification_number.clone(),
            profile_picture_file: profile_picture_file.clone(),
            identity_document_file: identity_document_file.clone(),
            nostr_relays: get_config().nostr_config.relays.to_owned(),
        };

        let previous_block = self.blockchain_store.get_latest_block().await?;
        let new_block = IdentityBlock::create_block_for_update(
            &previous_block,
            &IdentityUpdateBlockData {
                name: Some(name),
                email,
                postal_address,
                date_of_birth,
                country_of_birth,
                city_of_birth,
                identification_number,
                profile_picture_file,
                identity_document_file,
            },
            &keys,
            timestamp,
        )?;
        self.blockchain_store.add_block(&new_block).await?;
        self.store.save(&identity).await?;
        self.populate_block(&identity, &new_block, &keys).await?;
        self.on_identity_contact_change(&identity, &keys).await?;
        debug!("deanonymized identity");
        Ok(())
    }

    /// Recovers keys from a seed phrase and stores them into the identity
    async fn recover_from_seedphrase(&self, seed: &str) -> Result<()> {
        let key_pair = BcrKeys::from_seedphrase(seed)?;
        self.store.save_key_pair(&key_pair, seed).await?;
        Ok(())
    }

    async fn get_seedphrase(&self) -> Result<String> {
        let res = self.store.get_seedphrase().await?;
        Ok(res)
    }

    async fn open_and_decrypt_file(
        &self,
        identity: Identity,
        id: &NodeId,
        file_name: &str,
        private_key: &SecretKey,
    ) -> Result<Vec<u8>> {
        validate_node_id_network(id)?;
        debug!("getting file {file_name} for identity with id: {id}");
        let nostr_relays = identity.nostr_relays.clone();
        // TODO(multi-relay): don't default to first
        if let Some(nostr_relay) = nostr_relays.first() {
            let mut file = None;

            if let Some(profile_picture_file) = identity.profile_picture_file
                && profile_picture_file.name == file_name
            {
                file = Some(profile_picture_file);
            }

            if let Some(identity_document_file) = identity.identity_document_file
                && identity_document_file.name == file_name
            {
                file = Some(identity_document_file);
            }

            if let Some(file) = file {
                let file_bytes = self
                    .file_upload_client
                    .download(nostr_relay, &file.nostr_hash)
                    .await?;
                let decrypted = util::crypto::decrypt_ecies(&file_bytes, private_key)?;
                let file_hash = util::sha256_hash(&decrypted);
                if file_hash != file.hash {
                    error!("Hash for identity file {file_name} did not match uploaded file");
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

    async fn get_current_identity(&self) -> Result<ActiveIdentityState> {
        let active_identity = self.store.get_current_identity().await?;
        Ok(active_identity)
    }

    async fn set_current_personal_identity(&self, node_id: &NodeId) -> Result<()> {
        validate_node_id_network(node_id)?;
        debug!("setting current identity to personal identity: {node_id}");
        self.store
            .set_current_identity(&ActiveIdentityState {
                personal: node_id.to_owned(),
                company: None,
            })
            .await?;
        Ok(())
    }

    async fn set_current_company_identity(&self, node_id: &NodeId) -> Result<()> {
        validate_node_id_network(node_id)?;
        debug!("setting current identity to company identity: {node_id}");
        let active_identity = self.store.get_current_identity().await?;
        self.store
            .set_current_identity(&ActiveIdentityState {
                personal: active_identity.personal,
                company: Some(node_id.to_owned()),
            })
            .await?;
        Ok(())
    }

    async fn get_keys(&self) -> Result<BcrKeys> {
        Ok(self.store.get_key_pair().await?)
    }

    async fn share_contact_details(&self, share_to: &NodeId) -> Result<()> {
        let identity = self.get_full_identity().await?;
        let derived_keys = identity.key_pair.derive_keypair()?;
        let keys = BcrKeys::from_private_key(&derived_keys.secret_key())?;
        self.notification_service
            .share_contact_details_keys(share_to, &identity.identity.node_id, &keys)
            .await?;
        Ok(())
    }

    async fn dev_mode_get_full_identity_chain(&self) -> Result<Vec<IdentityBlockPlaintextWrapper>> {
        // if dev mode is off - we return an error
        if !get_config().dev_mode_config.on {
            error!("Called dev mode operation with dev mode disabled - please enable!");
            return Err(Error::InvalidOperation);
        }

        // if there is identity yet, we return an error
        if !self.identity_exists().await {
            return Err(Error::NotFound);
        }

        let chain = self.blockchain_store.get_chain().await?;
        let keys = self.store.get_key_pair().await?;

        let plaintext_chain = chain.get_chain_with_plaintext_block_data(&keys)?;

        Ok(plaintext_chain)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::{
        external::file_storage::MockFileStorageClientApi,
        service::notification_service::MockNotificationServiceApi,
        tests::tests::{
            MockFileUploadStoreApiMock, MockIdentityChainStoreApiMock, MockIdentityStoreApiMock,
            empty_identity, empty_optional_address, filled_optional_address, init_test_cfg,
        },
    };
    use mockall::predicate::eq;

    fn get_service(mock_storage: MockIdentityStoreApiMock) -> IdentityService {
        IdentityService::new(
            Arc::new(mock_storage),
            Arc::new(MockFileUploadStoreApiMock::new()),
            Arc::new(MockFileStorageClientApi::new()),
            Arc::new(MockIdentityChainStoreApiMock::new()),
            Arc::new(MockNotificationServiceApi::new()),
        )
    }

    fn get_service_with_chain_storage(
        mock_storage: MockIdentityStoreApiMock,
        mock_chain_storage: MockIdentityChainStoreApiMock,
        notification: MockNotificationServiceApi,
    ) -> IdentityService {
        IdentityService::new(
            Arc::new(mock_storage),
            Arc::new(MockFileUploadStoreApiMock::new()),
            Arc::new(MockFileStorageClientApi::new()),
            Arc::new(mock_chain_storage),
            Arc::new(notification),
        )
    }

    #[tokio::test]
    async fn create_identity_baseline() {
        init_test_cfg();
        let mut storage = MockIdentityStoreApiMock::new();
        storage
            .expect_get_or_create_key_pair()
            .returning(|| Ok(BcrKeys::new()));
        storage.expect_save().returning(move |_| Ok(()));
        storage
            .expect_get_key_pair()
            .returning(|| Ok(BcrKeys::new()));
        let mut chain_storage = MockIdentityChainStoreApiMock::new();
        chain_storage.expect_add_block().returning(|_| Ok(()));
        let mut notification = MockNotificationServiceApi::new();
        notification
            .expect_send_identity_chain_events()
            .returning(|_| Ok(()))
            .once();
        // publishes contact info to nostr
        notification
            .expect_publish_contact()
            .returning(|_, _| Ok(()))
            .once();

        let service = get_service_with_chain_storage(storage, chain_storage, notification);
        let res = service
            .create_identity(
                IdentityType::Ident,
                "name".to_string(),
                Some("email".to_string()),
                filled_optional_address(),
                None,
                None,
                None,
                None,
                None,
                None,
                1731593928,
            )
            .await;

        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn create_anon_identity_baseline() {
        init_test_cfg();
        let mut storage = MockIdentityStoreApiMock::new();

        storage
            .expect_get_or_create_key_pair()
            .returning(|| Ok(BcrKeys::new()));
        storage.expect_save().returning(move |_| Ok(()));
        storage
            .expect_get_key_pair()
            .returning(|| Ok(BcrKeys::new()));
        let mut chain_storage = MockIdentityChainStoreApiMock::new();
        chain_storage.expect_add_block().returning(|_| Ok(()));
        let mut notification = MockNotificationServiceApi::new();
        notification
            .expect_send_identity_chain_events()
            .returning(|_| Ok(()))
            .once();
        // publishes contact info to nostr
        notification
            .expect_publish_contact()
            .returning(|_, _| Ok(()))
            .once();

        let service = get_service_with_chain_storage(storage, chain_storage, notification);
        let res = service
            .create_identity(
                IdentityType::Anon,
                "name".to_string(),
                Some("email".to_string()),
                empty_optional_address(),
                None,
                None,
                None,
                None,
                None,
                None,
                1731593928,
            )
            .await;

        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn deanonymize_identity_baseline() {
        init_test_cfg();
        let mut storage = MockIdentityStoreApiMock::new();
        storage
            .expect_get_or_create_key_pair()
            .returning(|| Ok(BcrKeys::new()));
        storage.expect_save().returning(move |_| Ok(()));
        storage
            .expect_get_key_pair()
            .returning(|| Ok(BcrKeys::new()));
        storage.expect_get().returning(move || {
            let mut identity = empty_identity();
            identity.node_id = NodeId::new(BcrKeys::new().pub_key(), bitcoin::Network::Testnet);
            identity.t = IdentityType::Anon;
            Ok(identity)
        });
        let mut chain_storage = MockIdentityChainStoreApiMock::new();
        chain_storage.expect_add_block().returning(|_| Ok(()));
        chain_storage.expect_get_latest_block().returning(|| {
            let identity = empty_identity();
            Ok(
                IdentityBlockchain::new(&identity.into(), &BcrKeys::new(), 1731593928)
                    .unwrap()
                    .get_latest_block()
                    .clone(),
            )
        });
        let mut notification = MockNotificationServiceApi::new();
        notification
            .expect_send_identity_chain_events()
            .returning(|_| Ok(()))
            .once();
        // publishes contact info to nostr
        notification
            .expect_publish_contact()
            .returning(|_, _| Ok(()))
            .once();

        let service = get_service_with_chain_storage(storage, chain_storage, notification);
        let res = service
            .deanonymize_identity(
                IdentityType::Ident,
                "name".to_string(),
                Some("email".to_string()),
                filled_optional_address(),
                None,
                None,
                None,
                None,
                None,
                None,
                1731593928,
            )
            .await;

        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn deanonymize_identity_fails_with_anon() {
        init_test_cfg();
        let mut storage = MockIdentityStoreApiMock::new();
        storage
            .expect_get_or_create_key_pair()
            .returning(|| Ok(BcrKeys::new()));
        storage.expect_save().returning(move |_| Ok(()));
        storage
            .expect_get_key_pair()
            .returning(|| Ok(BcrKeys::new()));
        storage.expect_get().returning(move || {
            let mut identity = empty_identity();
            identity.node_id = NodeId::new(BcrKeys::new().pub_key(), bitcoin::Network::Testnet);
            identity.t = IdentityType::Anon;
            Ok(identity)
        });
        let mut chain_storage = MockIdentityChainStoreApiMock::new();
        chain_storage.expect_add_block().returning(|_| Ok(()));
        let mut notification = MockNotificationServiceApi::new();
        notification.expect_send_identity_chain_events().never();

        let service = get_service_with_chain_storage(storage, chain_storage, notification);
        let res = service
            .deanonymize_identity(
                IdentityType::Anon,
                "name".to_string(),
                Some("email".to_string()),
                empty_optional_address(),
                None,
                None,
                None,
                None,
                None,
                None,
                1731593928,
            )
            .await;

        assert!(res.is_err());
        assert!(matches!(
            res.unwrap_err(),
            crate::service::Error::Validation(ValidationError::IdentityCantBeAnon)
        ));
    }

    #[tokio::test]
    async fn deanonymize_identity_fails_for_non_anon() {
        init_test_cfg();
        let mut storage = MockIdentityStoreApiMock::new();
        storage
            .expect_get_or_create_key_pair()
            .returning(|| Ok(BcrKeys::new()));
        storage.expect_save().returning(move |_| Ok(()));
        storage
            .expect_get_key_pair()
            .returning(|| Ok(BcrKeys::new()));
        storage.expect_get().returning(move || {
            let mut identity = empty_identity();
            identity.node_id = NodeId::new(BcrKeys::new().pub_key(), bitcoin::Network::Testnet);
            Ok(identity)
        });
        let mut chain_storage = MockIdentityChainStoreApiMock::new();
        chain_storage.expect_add_block().returning(|_| Ok(()));
        let mut notification = MockNotificationServiceApi::new();
        notification.expect_send_identity_chain_events().never();

        let service = get_service_with_chain_storage(storage, chain_storage, notification);
        let res = service
            .deanonymize_identity(
                IdentityType::Ident,
                "name".to_string(),
                Some("email".to_string()),
                empty_optional_address(),
                None,
                None,
                None,
                None,
                None,
                None,
                1731593928,
            )
            .await;

        assert!(res.is_err());
        assert!(matches!(
            res.unwrap_err(),
            crate::service::Error::Validation(ValidationError::InvalidIdentityType)
        ));
    }

    #[tokio::test]
    async fn update_identity_calls_storage() {
        let keys = BcrKeys::new();
        let mut storage = MockIdentityStoreApiMock::new();
        storage.expect_save().returning(|_| Ok(()));
        storage
            .expect_get_key_pair()
            .returning(move || Ok(keys.clone()));
        storage.expect_get().returning(move || {
            let identity = empty_identity();
            Ok(identity)
        });
        let mut chain_storage = MockIdentityChainStoreApiMock::new();
        chain_storage.expect_get_latest_block().returning(|| {
            let identity = empty_identity();
            Ok(
                IdentityBlockchain::new(&identity.into(), &BcrKeys::new(), 1731593928)
                    .unwrap()
                    .get_latest_block()
                    .clone(),
            )
        });
        chain_storage.expect_add_block().returning(|_| Ok(()));
        let mut notification = MockNotificationServiceApi::new();
        notification
            .expect_send_identity_chain_events()
            .returning(|_| Ok(()))
            .once();
        // publishes contact info to nostr
        notification
            .expect_publish_contact()
            .returning(|_, _| Ok(()))
            .once();

        let service = get_service_with_chain_storage(storage, chain_storage, notification);
        let res = service
            .update_identity(
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
                1731593928,
            )
            .await;

        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn update_identity_returns_if_no_changes_were_made() {
        let mut storage = MockIdentityStoreApiMock::new();
        storage.expect_save().returning(|_| Ok(()));
        storage
            .expect_get_key_pair()
            .returning(|| Ok(BcrKeys::new()));
        storage.expect_get().returning(move || {
            let mut identity = empty_identity();
            identity.name = "name".to_string();
            Ok(identity)
        });

        let service = get_service(storage);
        let res = service
            .update_identity(
                Some("name".to_string()),
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
                1731593928,
            )
            .await;

        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn update_identity_propagates_errors() {
        let mut storage = MockIdentityStoreApiMock::new();
        storage
            .expect_get_key_pair()
            .returning(|| Ok(BcrKeys::new()));
        storage.expect_get().returning(move || {
            let identity = empty_identity();
            Ok(identity)
        });
        storage.expect_save().returning(|_| {
            Err(bcr_ebill_persistence::Error::Io(std::io::Error::other(
                "test error",
            )))
        });
        let mut chain_storage = MockIdentityChainStoreApiMock::new();
        chain_storage.expect_get_latest_block().returning(|| {
            let identity = empty_identity();
            Ok(
                IdentityBlockchain::new(&identity.into(), &BcrKeys::new(), 1731593928)
                    .unwrap()
                    .get_latest_block()
                    .clone(),
            )
        });
        chain_storage
            .expect_add_block()
            .returning(|_| Ok(()))
            .once();
        let mut notification = MockNotificationServiceApi::new();
        notification.expect_send_identity_chain_events().never();

        let service = get_service_with_chain_storage(storage, chain_storage, notification);
        let res = service
            .update_identity(
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
                1731593928,
            )
            .await;

        assert!(res.is_err());
    }

    #[tokio::test]
    async fn identity_exists_calls_storage() {
        let mut storage = MockIdentityStoreApiMock::new();
        storage.expect_exists().returning(|| true);

        let service = get_service(storage);
        let res = service.identity_exists().await;

        assert!(res);
    }

    #[tokio::test]
    async fn get_identity_calls_storage() {
        let identity = empty_identity();
        let mut storage = MockIdentityStoreApiMock::new();
        storage.expect_get().returning(move || Ok(empty_identity()));

        let service = get_service(storage);
        let res = service.get_identity().await;

        assert!(res.is_ok());
        assert_eq!(res.unwrap(), identity);
    }

    #[tokio::test]
    async fn get_identity_propagates_errors() {
        let mut storage = MockIdentityStoreApiMock::new();
        storage.expect_get().returning(|| {
            Err(bcr_ebill_persistence::Error::Io(std::io::Error::other(
                "test error",
            )))
        });

        let service = get_service(storage);
        let res = service.get_identity().await;

        assert!(res.is_err());
    }

    #[tokio::test]
    async fn get_full_identity_calls_storage() {
        let identity = IdentityWithAll {
            identity: empty_identity(),
            key_pair: BcrKeys::new(),
        };
        let arced = Arc::new(identity.clone());
        let mut storage = MockIdentityStoreApiMock::new();
        storage
            .expect_get_full()
            .returning(move || Ok((*arced.clone()).clone()));

        let service = get_service(storage);
        let res = service.get_full_identity().await;

        assert!(res.is_ok());
        assert_eq!(res.unwrap().identity, identity.identity);
    }

    #[tokio::test]
    async fn get_full_identity_propagates_errors() {
        let mut storage = MockIdentityStoreApiMock::new();
        storage.expect_get_full().returning(|| {
            Err(bcr_ebill_persistence::Error::Io(std::io::Error::other(
                "test error",
            )))
        });

        let service = get_service(storage);
        let res = service.get_full_identity().await;

        assert!(res.is_err());
    }

    #[tokio::test]
    async fn recover_from_seedphrase_stores_key_and_seed() {
        let seed = "forward paper connect economy twelve debate cart isolate accident creek bind predict captain rifle glory cradle hip whisper wealth save buddy place develop dolphin";
        let expected_key = BcrKeys::from_private_key(
            &SecretKey::from_str(
                "f31e0373f6fa9f4835d49a278cd48f47ea115af7480edf435275a3c2dbb1f982",
            )
            .unwrap(),
        )
        .unwrap();
        let mut storage = MockIdentityStoreApiMock::new();
        storage
            .expect_save_key_pair()
            .with(eq(expected_key), eq(seed))
            .returning(|_, _| Ok(()));
        let service = get_service(storage);
        service
            .recover_from_seedphrase(seed)
            .await
            .expect("could not recover from seedphrase")
    }

    #[tokio::test]
    async fn set_current_personal_identity_fails_for_different_network_id() {
        let service = get_service(MockIdentityStoreApiMock::new());
        let mainnet_node_id = NodeId::new(BcrKeys::new().pub_key(), bitcoin::Network::Bitcoin);
        assert!(
            service
                .set_current_personal_identity(&mainnet_node_id)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn set_current_company_identity_fails_for_different_network_id() {
        let service = get_service(MockIdentityStoreApiMock::new());
        let mainnet_node_id = NodeId::new(BcrKeys::new().pub_key(), bitcoin::Network::Bitcoin);
        assert!(
            service
                .set_current_company_identity(&mainnet_node_id)
                .await
                .is_err()
        );
    }
}
