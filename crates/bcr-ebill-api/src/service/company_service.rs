use super::Result;
use crate::blockchain::Blockchain;
use crate::blockchain::company::{
    CompanyAddSignatoryBlockData, CompanyBlock, CompanyBlockchain, CompanyCreateBlockData,
    CompanyRemoveSignatoryBlockData, CompanyUpdateBlockData, SignatoryType,
};
use crate::blockchain::identity::{
    IdentityAddSignatoryBlockData, IdentityBlock, IdentityCreateCompanyBlockData,
    IdentityRemoveSignatoryBlockData,
};
use crate::data::validate_node_id_network;
use crate::data::{
    File, OptionalPostalAddress, PostalAddress,
    company::{Company, CompanyKeys},
    contact::{Contact, ContactType},
};
use crate::external::file_storage::FileStorageClientApi;
use crate::get_config;
use crate::persistence::company::{CompanyChainStoreApi, CompanyStoreApi};
use crate::persistence::identity::IdentityChainStoreApi;
use crate::util::BcrKeys;
use crate::{
    persistence::{
        contact::ContactStoreApi, file_upload::FileUploadStoreApi, identity::IdentityStoreApi,
    },
    util,
};
use async_trait::async_trait;
use bcr_ebill_core::identity::IdentityType;
use bcr_ebill_core::{NodeId, PublicKey, SecretKey, ServiceTraitBounds, ValidationError};
use log::{debug, error, info};
use std::sync::Arc;

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait CompanyServiceApi: ServiceTraitBounds {
    /// List signatories for company
    async fn list_signatories(&self, id: &NodeId) -> Result<Vec<Contact>>;

    /// Search companies
    async fn search(&self, search_term: &str) -> Result<Vec<Company>>;
    /// Get a list of companies
    async fn get_list_of_companies(&self) -> Result<Vec<Company>>;

    /// Get a company by id
    async fn get_company_by_id(&self, id: &NodeId) -> Result<Company>;

    /// Get a company and it's keys by id
    async fn get_company_and_keys_by_id(&self, id: &NodeId) -> Result<(Company, CompanyKeys)>;

    /// Create a new company
    async fn create_company(
        &self,
        name: String,
        country_of_registration: Option<String>,
        city_of_registration: Option<String>,
        postal_address: PostalAddress,
        email: String,
        registration_number: Option<String>,
        registration_date: Option<String>,
        proof_of_registration_file_upload_id: Option<String>,
        logo_file_upload_id: Option<String>,
        timestamp: u64,
    ) -> Result<Company>;

    /// Changes the given company fields for the given company, if they are set
    async fn edit_company(
        &self,
        id: &NodeId,
        name: Option<String>,
        email: Option<String>,
        postal_address: OptionalPostalAddress,
        country_of_registration: Option<String>,
        city_of_registration: Option<String>,
        registration_number: Option<String>,
        registration_date: Option<String>,
        logo_file_upload_id: Option<String>,
        proof_of_registration_file_upload_id: Option<String>,
        timestamp: u64,
    ) -> Result<()>;

    /// Adds another signatory to the given company
    async fn add_signatory(
        &self,
        id: &NodeId,
        signatory_node_id: NodeId,
        timestamp: u64,
    ) -> Result<()>;

    /// Removes a signatory from the given company
    async fn remove_signatory(
        &self,
        id: &NodeId,
        signatory_node_id: NodeId,
        timestamp: u64,
    ) -> Result<()>;

    /// opens and decrypts the attached file from the given company
    async fn open_and_decrypt_file(
        &self,
        company: Company,
        id: &NodeId,
        file_name: &str,
        private_key: &SecretKey,
    ) -> Result<Vec<u8>>;
}

/// The company service is responsible for managing the companies
#[derive(Clone)]
pub struct CompanyService {
    store: Arc<dyn CompanyStoreApi>,
    file_upload_store: Arc<dyn FileUploadStoreApi>,
    file_upload_client: Arc<dyn FileStorageClientApi>,
    identity_store: Arc<dyn IdentityStoreApi>,
    contact_store: Arc<dyn ContactStoreApi>,
    identity_blockchain_store: Arc<dyn IdentityChainStoreApi>,
    company_blockchain_store: Arc<dyn CompanyChainStoreApi>,
}

impl CompanyService {
    pub fn new(
        store: Arc<dyn CompanyStoreApi>,
        file_upload_store: Arc<dyn FileUploadStoreApi>,
        file_upload_client: Arc<dyn FileStorageClientApi>,
        identity_store: Arc<dyn IdentityStoreApi>,
        contact_store: Arc<dyn ContactStoreApi>,
        identity_blockchain_store: Arc<dyn IdentityChainStoreApi>,
        company_blockchain_store: Arc<dyn CompanyChainStoreApi>,
    ) -> Self {
        Self {
            store,
            file_upload_store,
            file_upload_client,
            identity_store,
            contact_store,
            identity_blockchain_store,
            company_blockchain_store,
        }
    }

    async fn process_upload_file(
        &self,
        upload_id: &Option<String>,
        id: &NodeId,
        public_key: &PublicKey,
        relay_url: &str,
    ) -> Result<Option<File>> {
        if let Some(upload_id) = upload_id {
            debug!("processing upload file for company {id}: {upload_id:?}");
            let (file_name, file_bytes) = &self
                .file_upload_store
                .read_temp_upload_file(upload_id)
                .await
                .map_err(|_| crate::service::Error::NoFileForFileUploadId)?;
            let file = self
                .encrypt_and_upload_file(file_name, file_bytes, id, public_key, relay_url)
                .await?;
            return Ok(Some(file));
        }
        Ok(None)
    }

    async fn encrypt_and_upload_file(
        &self,
        file_name: &str,
        file_bytes: &[u8],
        id: &NodeId,
        public_key: &PublicKey,
        relay_url: &str,
    ) -> Result<File> {
        let file_hash = util::sha256_hash(file_bytes);
        let encrypted = util::crypto::encrypt_ecies(file_bytes, public_key)?;
        let nostr_hash = self.file_upload_client.upload(relay_url, encrypted).await?;
        info!("Saved company file {file_name} with hash {file_hash} for company {id}");
        Ok(File {
            name: file_name.to_owned(),
            hash: file_hash,
            nostr_hash: nostr_hash.to_string(),
        })
    }
}

impl ServiceTraitBounds for CompanyService {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl CompanyServiceApi for CompanyService {
    async fn list_signatories(&self, id: &NodeId) -> Result<Vec<Contact>> {
        validate_node_id_network(id)?;
        if !self.store.exists(id).await {
            return Err(crate::service::Error::NotFound);
        }
        let company = self.store.get(id).await?;
        let contacts = self.contact_store.get_map().await?;

        let signatory_contacts: Vec<Contact> = company
            .signatories
            .iter()
            .filter_map(|node_id| contacts.get(node_id))
            .cloned()
            .collect();
        Ok(signatory_contacts)
    }

    async fn search(&self, search_term: &str) -> Result<Vec<Company>> {
        let results = self.store.search(search_term).await?;
        Ok(results)
    }

    async fn get_list_of_companies(&self) -> Result<Vec<Company>> {
        let results = self.store.get_all().await?;
        let companies: Vec<Company> = results
            .into_iter()
            .map(|(_id, (company, _keys))| company)
            .collect();
        Ok(companies)
    }

    async fn get_company_and_keys_by_id(&self, id: &NodeId) -> Result<(Company, CompanyKeys)> {
        validate_node_id_network(id)?;
        if !self.store.exists(id).await {
            return Err(crate::service::Error::NotFound);
        }
        let company = self.store.get(id).await?;
        let keys = self.store.get_key_pair(id).await?;
        Ok((company, keys))
    }

    async fn get_company_by_id(&self, id: &NodeId) -> Result<Company> {
        validate_node_id_network(id)?;
        let (company, _keys) = self.get_company_and_keys_by_id(id).await?;
        Ok(company)
    }

    async fn create_company(
        &self,
        name: String,
        country_of_registration: Option<String>,
        city_of_registration: Option<String>,
        postal_address: PostalAddress,
        email: String,
        registration_number: Option<String>,
        registration_date: Option<String>,
        proof_of_registration_file_upload_id: Option<String>,
        logo_file_upload_id: Option<String>,
        timestamp: u64,
    ) -> Result<Company> {
        debug!("creating company");
        let keys = BcrKeys::new();
        let private_key = keys.get_private_key();
        let public_key = keys.pub_key();

        let id = NodeId::new(public_key, get_config().bitcoin_network());

        let company_keys = CompanyKeys {
            private_key,
            public_key,
        };

        let full_identity = self.identity_store.get_full().await?;
        let nostr_relays = full_identity.identity.nostr_relays.clone();
        // company can only be created by identified identity
        if full_identity.identity.t == IdentityType::Anon {
            return Err(super::Error::Validation(
                ValidationError::IdentityCantBeAnon,
            ));
        }

        let (proof_of_registration_file, logo_file) = match nostr_relays.first() {
            Some(nostr_relay) => {
                // Save the files locally with the identity public key
                let proof_of_registration_file = self
                    .process_upload_file(
                        &proof_of_registration_file_upload_id,
                        &id,
                        &full_identity.key_pair.pub_key(),
                        nostr_relay,
                    )
                    .await?;

                let logo_file = self
                    .process_upload_file(
                        &logo_file_upload_id,
                        &id,
                        &full_identity.key_pair.pub_key(),
                        nostr_relay,
                    )
                    .await?;
                (proof_of_registration_file, logo_file)
            }
            None => (None, None),
        };

        self.store.save_key_pair(&id, &company_keys).await?;
        let company = Company {
            id: id.clone(),
            name,
            country_of_registration,
            city_of_registration,
            postal_address,
            email,
            registration_number,
            registration_date,
            proof_of_registration_file,
            logo_file,
            signatories: vec![full_identity.identity.node_id.clone()], // add caller as signatory
        };
        self.store.insert(&company).await?;

        let company_chain = CompanyBlockchain::new(
            &CompanyCreateBlockData::from(company.clone()),
            &full_identity.key_pair,
            &company_keys,
            timestamp,
        )?;
        let create_company_block = company_chain.get_first_block();

        let previous_block = self.identity_blockchain_store.get_latest_block().await?;
        let new_block = IdentityBlock::create_block_for_create_company(
            &previous_block,
            &IdentityCreateCompanyBlockData {
                company_id: id.clone(),
                block_hash: create_company_block.hash.clone(),
            },
            &full_identity.key_pair,
            timestamp,
        )?;

        self.company_blockchain_store
            .add_block(&id, create_company_block)
            .await?;
        self.identity_blockchain_store.add_block(&new_block).await?;
        debug!("company with id {id} created");

        // TODO NOSTR: create company topic and subscribe to it
        // TODO NOSTR: upload files to nostr

        // clean up temporary file uploads, if there are any, logging any errors
        for upload_id in [proof_of_registration_file_upload_id, logo_file_upload_id]
            .iter()
            .flatten()
        {
            if let Err(e) = self
                .file_upload_store
                .remove_temp_upload_folder(upload_id)
                .await
            {
                error!("Error while cleaning up temporary file uploads for {upload_id}: {e}");
            }
        }

        Ok(company)
    }

    async fn edit_company(
        &self,
        id: &NodeId,
        name: Option<String>,
        email: Option<String>,
        postal_address: OptionalPostalAddress,
        country_of_registration: Option<String>,
        city_of_registration: Option<String>,
        registration_number: Option<String>,
        registration_date: Option<String>,
        logo_file_upload_id: Option<String>,
        proof_of_registration_file_upload_id: Option<String>,
        timestamp: u64,
    ) -> Result<()> {
        debug!("editing company with id: {id}");
        validate_node_id_network(id)?;
        if !self.store.exists(id).await {
            debug!("company with id {id} does not exist");
            return Err(super::Error::NotFound);
        }
        let full_identity = self.identity_store.get_full().await?;
        let nostr_relays = full_identity.identity.nostr_relays.clone();
        // company can only be edited by identified identity
        if full_identity.identity.t == IdentityType::Anon {
            return Err(super::Error::Validation(
                ValidationError::IdentityCantBeAnon,
            ));
        }
        let node_id = full_identity.identity.node_id;
        let mut company = self.store.get(id).await?;
        let company_keys = self.store.get_key_pair(id).await?;

        if !company.signatories.contains(&node_id) {
            return Err(super::Error::Validation(
                ValidationError::CallerMustBeSignatory,
            ));
        }
        let mut changed = false;

        if let Some(ref name_to_set) = name {
            company.name = name_to_set.clone();
            changed = true;
        }

        if let Some(ref email_to_set) = email {
            company.email = email_to_set.clone();
            changed = true;
        }

        if let Some(ref postal_address_city_to_set) = postal_address.city {
            company.postal_address.city = postal_address_city_to_set.clone();
            changed = true;
        }

        if let Some(ref postal_address_country_to_set) = postal_address.country {
            company.postal_address.country = postal_address_country_to_set.clone();
            changed = true;
        }

        util::update_optional_field(
            &mut company.postal_address.zip,
            &postal_address.zip,
            &mut changed,
        );

        util::update_optional_field(
            &mut company.country_of_registration,
            &country_of_registration,
            &mut changed,
        );

        util::update_optional_field(
            &mut company.city_of_registration,
            &city_of_registration,
            &mut changed,
        );

        util::update_optional_field(
            &mut company.registration_date,
            &registration_date,
            &mut changed,
        );

        util::update_optional_field(
            &mut company.registration_number,
            &registration_number,
            &mut changed,
        );

        if let Some(ref postal_address_address_to_set) = postal_address.address {
            company.postal_address.address = postal_address_address_to_set.clone();
            changed = true;
        }

        if !changed
            && logo_file_upload_id.is_none()
            && proof_of_registration_file_upload_id.is_none()
        {
            return Ok(());
        }

        let (logo_file, proof_of_registration_file) = match nostr_relays.first() {
            Some(nostr_relay) => {
                let logo_file = self
                    .process_upload_file(
                        &logo_file_upload_id,
                        id,
                        &full_identity.key_pair.pub_key(),
                        nostr_relay,
                    )
                    .await?;
                // only override the picture, if there is a new one
                if logo_file.is_some() {
                    company.logo_file = logo_file.clone();
                }
                let proof_of_registration_file = self
                    .process_upload_file(
                        &proof_of_registration_file_upload_id,
                        id,
                        &full_identity.key_pair.pub_key(),
                        nostr_relay,
                    )
                    .await?;
                // only override the document, if there is a new one
                if proof_of_registration_file.is_some() {
                    company.proof_of_registration_file = proof_of_registration_file.clone();
                }
                (logo_file, proof_of_registration_file)
            }
            None => (None, None),
        };

        self.store.update(id, &company).await?;

        let previous_block = self.company_blockchain_store.get_latest_block(id).await?;
        let new_block = CompanyBlock::create_block_for_update(
            id.to_owned(),
            &previous_block,
            &CompanyUpdateBlockData {
                name,
                email,
                postal_address,
                country_of_registration,
                city_of_registration,
                registration_number,
                registration_date,
                logo_file,
                proof_of_registration_file,
            },
            &full_identity.key_pair,
            &company_keys,
            timestamp,
        )?;
        self.company_blockchain_store
            .add_block(id, &new_block)
            .await?;
        debug!("company with id {id} updated");

        if let Some(upload_id) = logo_file_upload_id {
            if let Err(e) = self
                .file_upload_store
                .remove_temp_upload_folder(&upload_id)
                .await
            {
                error!("Error while cleaning up temporary file uploads for {upload_id}: {e}");
            }
        }

        Ok(())
    }

    async fn add_signatory(
        &self,
        id: &NodeId,
        signatory_node_id: NodeId,
        timestamp: u64,
    ) -> Result<()> {
        debug!(
            "adding signatory {} to company with id: {id}",
            &signatory_node_id
        );
        validate_node_id_network(id)?;
        validate_node_id_network(&signatory_node_id)?;
        if !self.store.exists(id).await {
            return Err(super::Error::NotFound);
        }
        let full_identity = self.identity_store.get_full().await?;
        // only non-anon identities can add signatories
        if full_identity.identity.t == IdentityType::Anon {
            return Err(super::Error::Validation(
                ValidationError::IdentityCantBeAnon,
            ));
        }
        let contacts = self.contact_store.get_map().await?;
        let is_in_contacts = contacts.iter().any(|(node_id, contact)| {
            *node_id == signatory_node_id && contact.t == ContactType::Person // only non-anon persons can be added
        });
        if !is_in_contacts {
            return Err(super::Error::Validation(
                ValidationError::SignatoryNotInContacts(signatory_node_id.to_string()),
            ));
        }

        let mut company = self.store.get(id).await?;
        let company_keys = self.store.get_key_pair(id).await?;
        if company.signatories.contains(&signatory_node_id) {
            return Err(super::Error::Validation(
                ValidationError::SignatoryAlreadySignatory(signatory_node_id.to_string()),
            ));
        }
        company.signatories.push(signatory_node_id.clone());
        self.store.update(id, &company).await?;

        let previous_block = self.company_blockchain_store.get_latest_block(id).await?;
        let new_block = CompanyBlock::create_block_for_add_signatory(
            id.to_owned(),
            &previous_block,
            &CompanyAddSignatoryBlockData {
                signatory: signatory_node_id.clone(),
                t: SignatoryType::Solo,
            },
            &full_identity.key_pair,
            &company_keys,
            &signatory_node_id.pub_key(),
            timestamp,
        )?;

        let previous_identity_block = self.identity_blockchain_store.get_latest_block().await?;
        let new_identity_block = IdentityBlock::create_block_for_add_signatory(
            &previous_identity_block,
            &IdentityAddSignatoryBlockData {
                company_id: id.to_owned(),
                block_hash: new_block.hash.clone(),
                block_id: new_block.id,
                signatory: signatory_node_id.clone(),
            },
            &full_identity.key_pair,
            timestamp,
        )?;
        self.company_blockchain_store
            .add_block(id, &new_block)
            .await?;
        self.identity_blockchain_store
            .add_block(&new_identity_block)
            .await?;
        debug!(
            "added signatory {} to company with id: {id}",
            &signatory_node_id
        );

        // TODO NOSTR: propagate block to company topic
        // TODO NOSTR: propagate company and files to new signatory

        Ok(())
    }

    async fn remove_signatory(
        &self,
        id: &NodeId,
        signatory_node_id: NodeId,
        timestamp: u64,
    ) -> Result<()> {
        debug!(
            "removing signatory {} from company with id: {id}",
            &signatory_node_id
        );
        validate_node_id_network(id)?;
        validate_node_id_network(&signatory_node_id)?;
        if !self.store.exists(id).await {
            return Err(super::Error::NotFound);
        }

        let full_identity = self.identity_store.get_full().await?;
        // only non-anon identities can remove signatories
        if full_identity.identity.t == IdentityType::Anon {
            return Err(super::Error::Validation(
                ValidationError::IdentityCantBeAnon,
            ));
        }
        let mut company = self.store.get(id).await?;
        let company_keys = self.store.get_key_pair(id).await?;
        if company.signatories.len() == 1 {
            return Err(super::Error::Validation(
                ValidationError::CantRemoveLastSignatory,
            ));
        }
        if !company.signatories.contains(&signatory_node_id) {
            return Err(super::Error::Validation(ValidationError::NotASignatory(
                signatory_node_id.to_string(),
            )));
        }

        company.signatories.retain(|i| i != &signatory_node_id);
        self.store.update(id, &company).await?;

        if full_identity.identity.node_id == signatory_node_id {
            info!("Removing self from company {id}");
            self.store.remove(id).await?;
        }

        let previous_block = self.company_blockchain_store.get_latest_block(id).await?;
        let new_block = CompanyBlock::create_block_for_remove_signatory(
            id.to_owned(),
            &previous_block,
            &CompanyRemoveSignatoryBlockData {
                signatory: signatory_node_id.clone(),
            },
            &full_identity.key_pair,
            &company_keys,
            timestamp,
        )?;

        let previous_identity_block = self.identity_blockchain_store.get_latest_block().await?;
        let new_identity_block = IdentityBlock::create_block_for_remove_signatory(
            &previous_identity_block,
            &IdentityRemoveSignatoryBlockData {
                company_id: id.to_owned(),
                block_hash: new_block.hash.clone(),
                block_id: new_block.id,
                signatory: signatory_node_id.clone(),
            },
            &full_identity.key_pair,
            timestamp,
        )?;

        self.company_blockchain_store
            .add_block(id, &new_block)
            .await?;
        self.identity_blockchain_store
            .add_block(&new_identity_block)
            .await?;

        // TODO NOSTR: propagate block to company topic

        if full_identity.identity.node_id == signatory_node_id {
            // TODO NOSTR: stop susbcribing to company topic
            info!("Removed self from company {id} - deleting company chain");
            if let Err(e) = self.company_blockchain_store.remove(id).await {
                error!("Could not delete local company chain for {id}: {e}");
            }
        }
        debug!(
            "removed signatory {} to company with id: {id}",
            &signatory_node_id
        );

        Ok(())
    }

    async fn open_and_decrypt_file(
        &self,
        company: Company,
        id: &NodeId,
        file_name: &str,
        private_key: &SecretKey,
    ) -> Result<Vec<u8>> {
        debug!("getting file {file_name} for company with id: {id}",);
        validate_node_id_network(id)?;
        let nostr_relays = get_config().nostr_config.relays.clone();
        if let Some(nostr_relay) = nostr_relays.first() {
            let mut file = None;
            if let Some(logo_file) = company.logo_file {
                if logo_file.name == file_name {
                    file = Some(logo_file);
                }
            }

            if let Some(proof_of_registration_file) = company.proof_of_registration_file {
                if proof_of_registration_file.name == file_name {
                    file = Some(proof_of_registration_file);
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
                    error!("Hash for company file {file_name} did not match uploaded file");
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
        blockchain::{Blockchain, identity::IdentityBlockchain},
        data::identity::IdentityWithAll,
        external::file_storage::MockFileStorageClientApi,
        service::contact_service::tests::get_baseline_contact,
        tests::tests::{
            MockCompanyChainStoreApiMock, MockCompanyStoreApiMock, MockContactStoreApiMock,
            MockFileUploadStoreApiMock, MockIdentityChainStoreApiMock, MockIdentityStoreApiMock,
            empty_address, empty_identity, empty_optional_address, node_id_test,
            node_id_test_other, node_id_test_other2, private_key_test,
        },
    };
    use std::{collections::HashMap, str::FromStr};
    use util::BcrKeys;

    fn get_service(
        mock_storage: MockCompanyStoreApiMock,
        mock_file_upload_storage: MockFileUploadStoreApiMock,
        mock_file_upload_client: MockFileStorageClientApi,
        mock_identity_storage: MockIdentityStoreApiMock,
        mock_contacts_storage: MockContactStoreApiMock,
        mock_identity_chain_storage: MockIdentityChainStoreApiMock,
        mock_company_chain_storage: MockCompanyChainStoreApiMock,
    ) -> CompanyService {
        CompanyService::new(
            Arc::new(mock_storage),
            Arc::new(mock_file_upload_storage),
            Arc::new(mock_file_upload_client),
            Arc::new(mock_identity_storage),
            Arc::new(mock_contacts_storage),
            Arc::new(mock_identity_chain_storage),
            Arc::new(mock_company_chain_storage),
        )
    }

    fn get_storages() -> (
        MockCompanyStoreApiMock,
        MockFileUploadStoreApiMock,
        MockFileStorageClientApi,
        MockIdentityStoreApiMock,
        MockContactStoreApiMock,
        MockIdentityChainStoreApiMock,
        MockCompanyChainStoreApiMock,
    ) {
        (
            MockCompanyStoreApiMock::new(),
            MockFileUploadStoreApiMock::new(),
            MockFileStorageClientApi::new(),
            MockIdentityStoreApiMock::new(),
            MockContactStoreApiMock::new(),
            MockIdentityChainStoreApiMock::new(),
            MockCompanyChainStoreApiMock::new(),
        )
    }

    pub fn get_baseline_company_data() -> (NodeId, (Company, CompanyKeys)) {
        (
            node_id_test(),
            (
                Company {
                    id: node_id_test(),
                    name: "some_name".to_string(),
                    country_of_registration: Some("AT".to_string()),
                    city_of_registration: Some("Vienna".to_string()),
                    postal_address: empty_address(),
                    email: "company@example.com".to_string(),
                    registration_number: Some("some_number".to_string()),
                    registration_date: Some("2012-01-01".to_string()),
                    proof_of_registration_file: None,
                    logo_file: None,
                    signatories: vec![node_id_test()],
                },
                CompanyKeys {
                    private_key: private_key_test(),
                    public_key: node_id_test().pub_key(),
                },
            ),
        )
    }

    pub fn get_valid_company_block() -> CompanyBlock {
        let (_id, (company, company_keys)) = get_baseline_company_data();

        CompanyBlockchain::new(
            &CompanyCreateBlockData::from(company),
            &BcrKeys::new(),
            &company_keys,
            1731593928,
        )
        .unwrap()
        .get_latest_block()
        .to_owned()
    }

    #[tokio::test]
    async fn get_list_of_companies_baseline() {
        let (
            mut storage,
            file_upload_store,
            file_upload_client,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        storage.expect_get_all().returning(|| {
            let mut map = HashMap::new();
            let company_data = get_baseline_company_data();
            map.insert(company_data.0, company_data.1);
            Ok(map)
        });
        let service = get_service(
            storage,
            file_upload_store,
            file_upload_client,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );

        let res = service.get_list_of_companies().await;
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().len(), 1);
        assert_eq!(res.as_ref().unwrap()[0].id, node_id_test());
    }

    #[tokio::test]
    async fn get_list_of_companies_propagates_persistence_errors() {
        let (
            mut storage,
            file_upload_store,
            file_upload_client,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        storage.expect_get_all().returning(|| {
            Err(bcr_ebill_persistence::Error::Io(std::io::Error::other(
                "test error",
            )))
        });
        let service = get_service(
            storage,
            file_upload_store,
            file_upload_client,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service.get_list_of_companies().await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn get_company_by_id_baseline() {
        let (
            mut storage,
            file_upload_store,
            file_upload_client,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        storage.expect_exists().returning(|_| true);
        storage
            .expect_get()
            .returning(|_| Ok(get_baseline_company_data().1.0));
        storage
            .expect_get_key_pair()
            .returning(|_| Ok(get_baseline_company_data().1.1));
        let service = get_service(
            storage,
            file_upload_store,
            file_upload_client,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );

        let res = service.get_company_by_id(&node_id_test()).await;
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().id, node_id_test());
    }

    #[tokio::test]
    async fn get_company_by_id_fails_if_company_doesnt_exist() {
        let (
            mut storage,
            file_upload_store,
            file_upload_client,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        storage.expect_exists().returning(|_| false);
        let service = get_service(
            storage,
            file_upload_store,
            file_upload_client,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service.get_company_by_id(&node_id_test()).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn get_company_by_id_propagates_persistence_errors() {
        let (
            mut storage,
            file_upload_store,
            file_upload_client,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        storage.expect_exists().returning(|_| true);
        storage.expect_get().returning(|_| {
            Err(bcr_ebill_persistence::Error::Io(std::io::Error::other(
                "test error",
            )))
        });
        let service = get_service(
            storage,
            file_upload_store,
            file_upload_client,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service.get_company_by_id(&node_id_test()).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn create_company_baseline() {
        let (
            mut storage,
            mut file_upload_store,
            mut file_upload_client,
            mut identity_store,
            contact_store,
            mut identity_chain_store,
            mut company_chain_store,
        ) = get_storages();
        company_chain_store
            .expect_add_block()
            .returning(|_, _| Ok(()));
        file_upload_client.expect_upload().returning(|_, _| {
            Ok(nostr::hashes::sha256::Hash::from_str(
                "d277fe40da2609ca08215cdfbeac44835d4371a72f1416a63c87efd67ee24bfa",
            )
            .unwrap())
        });
        storage.expect_save_key_pair().returning(|_, _| Ok(()));
        storage.expect_insert().returning(|_| Ok(()));
        identity_store.expect_get_full().returning(|| {
            let mut identity = empty_identity();
            identity.nostr_relays = vec!["ws://localhost:8080".into()];
            Ok(IdentityWithAll {
                identity,
                key_pair: BcrKeys::new(),
            })
        });
        file_upload_store
            .expect_read_temp_upload_file()
            .returning(|_| Ok(("some_file".to_string(), "hello_world".as_bytes().to_vec())));
        file_upload_store
            .expect_remove_temp_upload_folder()
            .returning(|_| Ok(()));
        identity_chain_store
            .expect_get_latest_block()
            .returning(|| {
                let identity = empty_identity();
                Ok(
                    IdentityBlockchain::new(&identity.into(), &BcrKeys::new(), 1731593928)
                        .unwrap()
                        .get_latest_block()
                        .clone(),
                )
            });
        identity_chain_store
            .expect_add_block()
            .returning(|_| Ok(()));

        let service = get_service(
            storage,
            file_upload_store,
            file_upload_client,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );

        let res = service
            .create_company(
                "name".to_string(),
                Some("AT".to_string()),
                Some("Vienna".to_string()),
                empty_address(),
                "company@example.com".to_string(),
                Some("some_number".to_string()),
                Some("2012-01-01".to_string()),
                Some("some_file_id".to_string()),
                Some("some_other_file_id".to_string()),
                1731593928,
            )
            .await;
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().name, "name".to_string());
        assert_eq!(
            res.as_ref()
                .unwrap()
                .proof_of_registration_file
                .as_ref()
                .unwrap()
                .name,
            "some_file".to_string()
        );
        assert_eq!(
            res.as_ref().unwrap().logo_file.as_ref().unwrap().name,
            "some_file".to_string()
        );
    }

    #[tokio::test]
    async fn create_company_propagates_persistence_errors() {
        let (
            mut storage,
            file_upload_store,
            file_upload_client,
            mut identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        storage.expect_save_key_pair().returning(|_, _| Ok(()));
        storage.expect_insert().returning(|_| {
            Err(bcr_ebill_persistence::Error::Io(std::io::Error::other(
                "test error",
            )))
        });
        identity_store.expect_get_full().returning(|| {
            let identity = empty_identity();
            Ok(IdentityWithAll {
                identity,
                key_pair: BcrKeys::new(),
            })
        });
        let service = get_service(
            storage,
            file_upload_store,
            file_upload_client,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .create_company(
                "name".to_string(),
                Some("AT".to_string()),
                Some("Vienna".to_string()),
                empty_address(),
                "company@example.com".to_string(),
                Some("some_number".to_string()),
                Some("2012-01-01".to_string()),
                None,
                None,
                1731593928,
            )
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn edit_company_baseline() {
        let keys = BcrKeys::new();
        let node_id = NodeId::new(keys.pub_key(), bitcoin::Network::Testnet);
        let (
            mut storage,
            mut file_upload_store,
            mut file_upload_client,
            mut identity_store,
            contact_store,
            identity_chain_store,
            mut company_chain_store,
        ) = get_storages();
        company_chain_store
            .expect_get_latest_block()
            .returning(|_| Ok(get_valid_company_block()));
        company_chain_store
            .expect_add_block()
            .returning(|_, _| Ok(()));
        let node_id_clone = node_id.clone();
        storage.expect_get().returning(move |_| {
            let mut data = get_baseline_company_data().1.0;
            data.signatories = vec![node_id_clone.clone()];
            Ok(data)
        });
        storage
            .expect_get_key_pair()
            .returning(|_| Ok(get_baseline_company_data().1.1));
        storage.expect_exists().returning(|_| true);
        storage.expect_update().returning(|_, _| Ok(()));
        file_upload_client.expect_upload().returning(|_, _| {
            Ok(nostr::hashes::sha256::Hash::from_str(
                "d277fe40da2609ca08215cdfbeac44835d4371a72f1416a63c87efd67ee24bfa",
            )
            .unwrap())
        });
        identity_store.expect_get_full().returning(move || {
            let mut identity = empty_identity();
            identity.node_id = node_id.clone();
            Ok(IdentityWithAll {
                identity,
                key_pair: keys.clone(),
            })
        });
        file_upload_store
            .expect_read_temp_upload_file()
            .returning(|_| Ok(("some_file".to_string(), "hello_world".as_bytes().to_vec())));
        file_upload_store
            .expect_remove_temp_upload_folder()
            .returning(|_| Ok(()));
        let service = get_service(
            storage,
            file_upload_store,
            file_upload_client,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .edit_company(
                &node_id_test(),
                Some("name".to_string()),
                Some("company@example.com".to_string()),
                empty_optional_address(),
                None,
                None,
                None,
                None,
                Some("some_file_id".to_string()),
                None,
                1731593928,
            )
            .await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn edit_company_fails_if_company_doesnt_exist() {
        let (
            mut storage,
            file_upload_store,
            file_upload_client,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        storage.expect_exists().returning(|_| false);
        let service = get_service(
            storage,
            file_upload_store,
            file_upload_client,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .edit_company(
                &node_id_test_other(),
                Some("name".to_string()),
                Some("company@example.com".to_string()),
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
    }

    #[tokio::test]
    async fn edit_company_fails_if_caller_is_not_signatory() {
        let (
            mut storage,
            file_upload_store,
            file_upload_client,
            mut identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        storage.expect_exists().returning(|_| false);
        storage.expect_get().returning(|_| {
            let mut data = get_baseline_company_data().1.0;
            data.signatories = vec![node_id_test_other()];
            Ok(data)
        });
        identity_store.expect_get_full().returning(|| {
            let identity = empty_identity();
            Ok(IdentityWithAll {
                identity,
                key_pair: BcrKeys::new(),
            })
        });
        let service = get_service(
            storage,
            file_upload_store,
            file_upload_client,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .edit_company(
                &node_id_test(),
                Some("name".to_string()),
                Some("company@example.com".to_string()),
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
    }

    #[tokio::test]
    async fn edit_company_propagates_persistence_errors() {
        let (
            mut storage,
            file_upload_store,
            file_upload_client,
            mut identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        let keys = BcrKeys::new();
        let node_id = NodeId::new(keys.pub_key(), bitcoin::Network::Testnet);
        let node_id_clone = node_id.clone();
        storage.expect_get().returning(move |_| {
            let mut data = get_baseline_company_data().1.0;
            data.signatories = vec![node_id_clone.clone()];
            Ok(data)
        });
        storage
            .expect_get_key_pair()
            .returning(|_| Ok(get_baseline_company_data().1.1));
        storage.expect_exists().returning(|_| true);
        storage.expect_update().returning(|_, _| {
            Err(bcr_ebill_persistence::Error::Io(std::io::Error::other(
                "test error",
            )))
        });
        identity_store.expect_get_full().returning(move || {
            let mut identity = empty_identity();
            identity.node_id = node_id.clone();
            Ok(IdentityWithAll {
                identity,
                key_pair: keys.clone(),
            })
        });
        let service = get_service(
            storage,
            file_upload_store,
            file_upload_client,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .edit_company(
                &node_id_test(),
                Some("name".to_string()),
                Some("company@example.com".to_string()),
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
    }

    #[tokio::test]
    async fn add_signatory_baseline() {
        let (
            mut storage,
            file_upload_store,
            file_upload_client,
            mut identity_store,
            mut contact_store,
            mut identity_chain_store,
            mut company_chain_store,
        ) = get_storages();
        let signatory_node_id = NodeId::new(BcrKeys::new().pub_key(), bitcoin::Network::Testnet);
        storage.expect_exists().returning(|_| true);
        storage.expect_update().returning(|_, _| Ok(()));
        storage
            .expect_get_key_pair()
            .returning(|_| Ok(get_baseline_company_data().1.1));
        company_chain_store
            .expect_get_latest_block()
            .returning(|_| Ok(get_valid_company_block()));
        company_chain_store
            .expect_add_block()
            .returning(|_, _| Ok(()));
        let signatory_node_id_clone = signatory_node_id.clone();
        contact_store.expect_get_map().returning(move || {
            let mut map = HashMap::new();
            let mut contact = get_baseline_contact();
            contact.node_id = signatory_node_id_clone.clone();
            map.insert(signatory_node_id_clone.clone(), contact);
            Ok(map)
        });
        storage
            .expect_get()
            .returning(|_| Ok(get_baseline_company_data().1.0));
        identity_store.expect_get_full().returning(|| {
            let keys = BcrKeys::new();
            let mut identity = empty_identity();
            identity.node_id = NodeId::new(keys.pub_key(), bitcoin::Network::Testnet);
            Ok(IdentityWithAll {
                identity,
                key_pair: keys,
            })
        });
        identity_chain_store
            .expect_get_latest_block()
            .returning(|| {
                let identity = empty_identity();
                Ok(
                    IdentityBlockchain::new(&identity.into(), &BcrKeys::new(), 1731593928)
                        .unwrap()
                        .get_latest_block()
                        .clone(),
                )
            });
        identity_chain_store
            .expect_add_block()
            .returning(|_| Ok(()));
        let service = get_service(
            storage,
            file_upload_store,
            file_upload_client,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .add_signatory(&node_id_test(), signatory_node_id, 1731593928)
            .await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn add_signatory_fails_if_signatory_in_contacts_but_not_a_person() {
        let (
            mut storage,
            file_upload_store,
            file_upload_client,
            mut identity_store,
            mut contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        let signatory_node_id = NodeId::new(BcrKeys::new().pub_key(), bitcoin::Network::Testnet);
        storage.expect_exists().returning(|_| true);
        let signatory_node_id_clone = signatory_node_id.clone();
        contact_store.expect_get_map().returning(move || {
            let mut map = HashMap::new();
            let mut contact = get_baseline_contact();
            contact.node_id = signatory_node_id_clone.clone();
            contact.t = ContactType::Company;
            map.insert(signatory_node_id_clone.clone(), contact);
            Ok(map)
        });
        identity_store.expect_get_full().returning(|| {
            let identity = empty_identity();
            Ok(IdentityWithAll {
                identity,
                key_pair: BcrKeys::new(),
            })
        });
        let service = get_service(
            storage,
            file_upload_store,
            file_upload_client,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .add_signatory(&node_id_test(), signatory_node_id, 1731593928)
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn add_signatory_fails_if_signatory_not_in_contacts() {
        let (
            mut storage,
            file_upload_store,
            file_upload_client,
            mut identity_store,
            mut contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        storage.expect_exists().returning(|_| true);
        contact_store
            .expect_get_map()
            .returning(|| Ok(HashMap::new()));
        identity_store.expect_get_full().returning(|| {
            let identity = empty_identity();
            Ok(IdentityWithAll {
                identity,
                key_pair: BcrKeys::new(),
            })
        });
        let service = get_service(
            storage,
            file_upload_store,
            file_upload_client,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .add_signatory(&node_id_test(), node_id_test_other(), 1731593928)
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn add_signatory_fails_if_company_doesnt_exist() {
        let (
            mut storage,
            file_upload_store,
            file_upload_client,
            mut identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        storage.expect_exists().returning(|_| false);
        identity_store.expect_get_full().returning(|| {
            let identity = empty_identity();
            Ok(IdentityWithAll {
                identity,
                key_pair: BcrKeys::new(),
            })
        });
        let service = get_service(
            storage,
            file_upload_store,
            file_upload_client,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .add_signatory(&node_id_test(), node_id_test_other(), 1731593928)
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn add_signatory_fails_if_signatory_is_already_signatory() {
        let (
            mut storage,
            file_upload_store,
            file_upload_client,
            mut identity_store,
            mut contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        storage.expect_exists().returning(|_| true);
        identity_store.expect_get_full().returning(|| {
            let identity = empty_identity();
            Ok(IdentityWithAll {
                identity,
                key_pair: BcrKeys::new(),
            })
        });
        contact_store.expect_get_map().returning(|| {
            let mut map = HashMap::new();
            let contact = get_baseline_contact();
            map.insert(node_id_test(), contact);
            Ok(map)
        });
        storage.expect_get().returning(|_| {
            let mut data = get_baseline_company_data().1.0;
            data.signatories.push(node_id_test());
            Ok(data)
        });
        storage
            .expect_get_key_pair()
            .returning(|_| Ok(get_baseline_company_data().1.1));
        let service = get_service(
            storage,
            file_upload_store,
            file_upload_client,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .add_signatory(&node_id_test(), node_id_test(), 1731593928)
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn add_signatory_propagates_persistence_errors() {
        let (
            mut storage,
            file_upload_store,
            file_upload_client,
            mut identity_store,
            mut contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        storage.expect_exists().returning(|_| true);
        identity_store.expect_get_full().returning(|| {
            let identity = empty_identity();
            Ok(IdentityWithAll {
                identity,
                key_pair: BcrKeys::new(),
            })
        });
        contact_store.expect_get_map().returning(|| {
            let mut map = HashMap::new();
            let contact = get_baseline_contact();
            map.insert(node_id_test(), contact);
            Ok(map)
        });
        storage.expect_update().returning(|_, _| {
            Err(bcr_ebill_persistence::Error::Io(std::io::Error::other(
                "test error",
            )))
        });
        storage
            .expect_get()
            .returning(|_| Ok(get_baseline_company_data().1.0));
        storage
            .expect_get_key_pair()
            .returning(|_| Ok(get_baseline_company_data().1.1));
        let service = get_service(
            storage,
            file_upload_store,
            file_upload_client,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .add_signatory(&node_id_test(), node_id_test(), 1731593928)
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn remove_signatory_baseline() {
        let (
            mut storage,
            file_upload_store,
            file_upload_client,
            mut identity_store,
            contact_store,
            mut identity_chain_store,
            mut company_chain_store,
        ) = get_storages();
        company_chain_store
            .expect_get_latest_block()
            .returning(|_| Ok(get_valid_company_block()));
        company_chain_store
            .expect_add_block()
            .returning(|_, _| Ok(()));
        storage.expect_exists().returning(|_| true);
        storage.expect_get().returning(|_| {
            let mut data = get_baseline_company_data().1.0;
            data.signatories.push(node_id_test_other2());
            data.signatories.push(node_id_test_other());
            Ok(data)
        });
        storage
            .expect_get_key_pair()
            .returning(|_| Ok(get_baseline_company_data().1.1));
        identity_store.expect_get_full().returning(|| {
            let identity = empty_identity();
            Ok(IdentityWithAll {
                identity,
                key_pair: BcrKeys::new(),
            })
        });
        storage.expect_update().returning(|_, _| Ok(()));
        identity_chain_store
            .expect_get_latest_block()
            .returning(|| {
                let identity = empty_identity();
                Ok(
                    IdentityBlockchain::new(&identity.into(), &BcrKeys::new(), 1731593928)
                        .unwrap()
                        .get_latest_block()
                        .clone(),
                )
            });
        identity_chain_store
            .expect_add_block()
            .returning(|_| Ok(()));
        let service = get_service(
            storage,
            file_upload_store,
            file_upload_client,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .remove_signatory(&node_id_test(), node_id_test_other(), 1731593928)
            .await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn remove_signatory_fails_if_company_doesnt_exist() {
        let (
            mut storage,
            file_upload_store,
            file_upload_client,
            mut identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        storage.expect_exists().returning(|_| false);
        identity_store.expect_get_full().returning(|| {
            let identity = empty_identity();
            Ok(IdentityWithAll {
                identity,
                key_pair: BcrKeys::new(),
            })
        });
        let service = get_service(
            storage,
            file_upload_store,
            file_upload_client,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .remove_signatory(&node_id_test(), node_id_test_other(), 1731593928)
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn remove_signatory_removing_self_removes_company() {
        let keys = BcrKeys::new();
        let (
            mut storage,
            file_upload_store,
            file_upload_client,
            mut identity_store,
            contact_store,
            mut identity_chain_store,
            mut company_chain_store,
        ) = get_storages();
        company_chain_store
            .expect_get_latest_block()
            .returning(|_| Ok(get_valid_company_block()));
        company_chain_store
            .expect_add_block()
            .returning(|_, _| Ok(()));
        company_chain_store.expect_remove().returning(|_| Ok(()));
        storage.expect_exists().returning(|_| true);
        let keys_clone = keys.clone();
        storage.expect_get().returning(move |_| {
            let mut data = get_baseline_company_data().1.0;
            data.signatories.push(node_id_test());
            data.signatories.push(NodeId::new(
                keys_clone.clone().pub_key(),
                bitcoin::Network::Testnet,
            ));
            Ok(data)
        });
        storage
            .expect_get_key_pair()
            .returning(|_| Ok(get_baseline_company_data().1.1));
        let keys_clone_clone = keys.clone();
        identity_store.expect_get_full().returning(move || {
            let mut identity = empty_identity();
            identity.node_id = NodeId::new(
                keys_clone_clone.clone().pub_key(),
                bitcoin::Network::Testnet,
            );
            Ok(IdentityWithAll {
                identity,
                key_pair: keys_clone_clone.clone(),
            })
        });
        storage.expect_update().returning(|_, _| Ok(()));
        storage.expect_remove().returning(|_| Ok(()));
        let keys_clone2 = keys.clone();
        identity_chain_store
            .expect_get_latest_block()
            .returning(move || {
                let identity = empty_identity();
                Ok(
                    IdentityBlockchain::new(&identity.into(), &keys_clone2, 1731593928)
                        .unwrap()
                        .get_latest_block()
                        .clone(),
                )
            });
        identity_chain_store
            .expect_add_block()
            .returning(|_| Ok(()));
        let service = get_service(
            storage,
            file_upload_store,
            file_upload_client,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .remove_signatory(
                &node_id_test(),
                NodeId::new(keys.pub_key(), bitcoin::Network::Testnet),
                1731593928,
            )
            .await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn remove_signatory_fails_if_signatory_is_not_in_company() {
        let (
            mut storage,
            file_upload_store,
            file_upload_client,
            mut identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        storage.expect_exists().returning(|_| true);
        storage.expect_get().returning(|_| {
            let mut data = get_baseline_company_data().1.0;
            data.signatories.push(node_id_test_other());
            data.signatories.push(node_id_test());
            Ok(data)
        });
        storage
            .expect_get_key_pair()
            .returning(|_| Ok(get_baseline_company_data().1.1));
        identity_store.expect_get_full().returning(|| {
            let identity = empty_identity();
            Ok(IdentityWithAll {
                identity,
                key_pair: BcrKeys::new(),
            })
        });
        let service = get_service(
            storage,
            file_upload_store,
            file_upload_client,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .remove_signatory(&node_id_test(), node_id_test_other2(), 1731593928)
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn remove_signatory_fails_on_last_signatory() {
        let (
            mut storage,
            file_upload_store,
            file_upload_client,
            mut identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        storage.expect_exists().returning(|_| true);
        storage.expect_get().returning(|_| {
            let data = get_baseline_company_data().1.0;
            Ok(data)
        });
        storage
            .expect_get_key_pair()
            .returning(|_| Ok(get_baseline_company_data().1.1));
        identity_store.expect_get_full().returning(|| {
            let identity = empty_identity();
            Ok(IdentityWithAll {
                identity,
                key_pair: BcrKeys::new(),
            })
        });
        let service = get_service(
            storage,
            file_upload_store,
            file_upload_client,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .remove_signatory(&node_id_test(), node_id_test(), 1731593928)
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn remove_signatory_propagates_persistence_errors() {
        let (
            mut storage,
            file_upload_store,
            file_upload_client,
            mut identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        storage.expect_exists().returning(|_| true);
        storage.expect_get().returning(|_| {
            let mut data = get_baseline_company_data().1.0;
            data.signatories.push(node_id_test());
            data.signatories.push(node_id_test_other());
            Ok(data)
        });
        storage
            .expect_get_key_pair()
            .returning(|_| Ok(get_baseline_company_data().1.1));
        identity_store.expect_get_full().returning(|| {
            let identity = empty_identity();
            Ok(IdentityWithAll {
                identity,
                key_pair: BcrKeys::new(),
            })
        });
        storage.expect_update().returning(|_, _| {
            Err(bcr_ebill_persistence::Error::Io(std::io::Error::other(
                "test error",
            )))
        });
        let service = get_service(
            storage,
            file_upload_store,
            file_upload_client,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .remove_signatory(&node_id_test(), node_id_test(), 1731593928)
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn save_encrypt_open_decrypt_compare_hashes() {
        let company_id = node_id_test();
        let file_name = "file_00000000-0000-0000-0000-000000000000.pdf";
        let file_bytes = String::from("hello world").as_bytes().to_vec();

        let expected_encrypted =
            util::crypto::encrypt_ecies(&file_bytes, &node_id_test().pub_key()).unwrap();

        let (
            storage,
            file_upload_store,
            mut file_upload_client,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();

        file_upload_client
            .expect_upload()
            .times(1)
            .returning(|_, _| {
                Ok(nostr::hashes::sha256::Hash::from_str(
                    "d277fe40da2609ca08215cdfbeac44835d4371a72f1416a63c87efd67ee24bfa",
                )
                .unwrap())
            });

        file_upload_client
            .expect_download()
            .times(1)
            .returning(move |_, _| Ok(expected_encrypted.clone()));
        let service = get_service(
            storage,
            file_upload_store,
            file_upload_client,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );

        let file = service
            .encrypt_and_upload_file(
                file_name,
                &file_bytes,
                &company_id,
                &node_id_test().pub_key(),
                "nostr_relay",
            )
            .await
            .unwrap();
        assert_eq!(
            file.hash,
            String::from("DULfJyE3WQqNxy3ymuhAChyNR3yufT88pmqvAazKFMG4")
        );
        assert_eq!(file.name, String::from(file_name));

        let mut company = get_baseline_company_data().1.0;
        company.proof_of_registration_file = Some(File {
            name: file_name.to_owned(),
            hash: file.hash.clone(),
            nostr_hash: "d277fe40da2609ca08215cdfbeac44835d4371a72f1416a63c87efd67ee24bfa".into(),
        });

        let decrypted = service
            .open_and_decrypt_file(company, &company_id, file_name, &private_key_test())
            .await
            .unwrap();
        assert_eq!(std::str::from_utf8(&decrypted).unwrap(), "hello world");
    }

    #[tokio::test]
    async fn save_encrypt_propagates_upload_error() {
        let (
            storage,
            file_upload_store,
            mut file_upload_client,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        file_upload_client.expect_upload().returning(|_, _| {
            Err(crate::external::Error::ExternalFileStorageApi(
                crate::external::file_storage::Error::InvalidRelayUrl,
            ))
        });
        let service = get_service(
            storage,
            file_upload_store,
            file_upload_client,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );

        assert!(
            service
                .encrypt_and_upload_file(
                    "file_name",
                    &[],
                    &node_id_test(),
                    &node_id_test().pub_key(),
                    "nostr_relay"
                )
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn open_decrypt_propagates_read_file_error() {
        let (
            storage,
            file_upload_store,
            mut file_upload_client,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        file_upload_client.expect_upload().returning(|_, _| {
            Err(crate::external::Error::ExternalFileStorageApi(
                crate::external::file_storage::Error::InvalidRelayUrl,
            ))
        });
        let service = get_service(
            storage,
            file_upload_store,
            file_upload_client,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );

        assert!(
            service
                .open_and_decrypt_file(
                    get_baseline_company_data().1.0,
                    &node_id_test(),
                    "test",
                    &private_key_test()
                )
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn list_signatories_baseline() {
        let (
            mut storage,
            file_upload_store,
            file_upload_client,
            identity_store,
            mut contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        storage.expect_exists().returning(|_| true);
        storage.expect_get().returning(|_| {
            let mut data = get_baseline_company_data().1.0;
            data.signatories.push(node_id_test_other());
            Ok(data)
        });

        contact_store.expect_get_map().returning(move || {
            let mut map = HashMap::new();
            let mut contact = get_baseline_contact();
            contact.node_id = node_id_test();
            map.insert(contact.node_id.clone(), contact);
            Ok(map)
        });

        let service = get_service(
            storage,
            file_upload_store,
            file_upload_client,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );

        let res = service.list_signatories(&node_id_test()).await;
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn wrong_network_failures() {
        let (
            storage,
            file_upload_store,
            file_upload_client,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        let mainnet_node_id = NodeId::new(BcrKeys::new().pub_key(), bitcoin::Network::Bitcoin);
        let service = get_service(
            storage,
            file_upload_store,
            file_upload_client,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        assert!(service.list_signatories(&mainnet_node_id).await.is_err());
        assert!(
            service
                .get_company_and_keys_by_id(&mainnet_node_id)
                .await
                .is_err()
        );
        assert!(service.get_company_by_id(&mainnet_node_id).await.is_err());
        assert!(
            service
                .edit_company(
                    &mainnet_node_id,
                    None,
                    None,
                    OptionalPostalAddress::empty(),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    1731593928
                )
                .await
                .is_err()
        );
        assert!(
            service
                .add_signatory(
                    &mainnet_node_id.clone(),
                    mainnet_node_id.clone(),
                    1731593928
                )
                .await
                .is_err()
        );
        assert!(
            service
                .remove_signatory(&mainnet_node_id.clone(), mainnet_node_id, 1731593928)
                .await
                .is_err()
        );
    }
}
