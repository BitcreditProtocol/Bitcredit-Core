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
use crate::data::{
    File, OptionalPostalAddress, PostalAddress,
    company::{Company, CompanyKeys},
    contact::{Contact, ContactType},
};
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
use bcr_ebill_core::ValidationError;
use bcr_ebill_core::identity::IdentityType;
use log::{debug, error, info};
use std::sync::Arc;

#[async_trait]
pub trait CompanyServiceApi: Send + Sync {
    /// List signatories for company
    async fn list_signatories(&self, id: &str) -> Result<Vec<Contact>>;

    /// Search companies
    async fn search(&self, search_term: &str) -> Result<Vec<Company>>;
    /// Get a list of companies
    async fn get_list_of_companies(&self) -> Result<Vec<Company>>;

    /// Get a company by id
    async fn get_company_by_id(&self, id: &str) -> Result<Company>;

    /// Get a company and it's keys by id
    async fn get_company_and_keys_by_id(&self, id: &str) -> Result<(Company, CompanyKeys)>;

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
        id: &str,
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
        id: &str,
        signatory_node_id: String,
        timestamp: u64,
    ) -> Result<()>;

    /// Removes a signatory from the given company
    async fn remove_signatory(
        &self,
        id: &str,
        signatory_node_id: String,
        timestamp: u64,
    ) -> Result<()>;

    /// Encrypts and saves the given uploaded file, returning the file name, as well as the hash of
    /// the unencrypted file
    async fn encrypt_and_save_uploaded_file(
        &self,
        file_name: &str,
        file_bytes: &[u8],
        id: &str,
        public_key: &str,
    ) -> Result<File>;

    /// opens and decrypts the attached file from the given company
    async fn open_and_decrypt_file(
        &self,
        id: &str,
        file_name: &str,
        private_key: &str,
    ) -> Result<Vec<u8>>;
}

/// The company service is responsible for managing the companies
#[derive(Clone)]
pub struct CompanyService {
    store: Arc<dyn CompanyStoreApi>,
    file_upload_store: Arc<dyn FileUploadStoreApi>,
    identity_store: Arc<dyn IdentityStoreApi>,
    contact_store: Arc<dyn ContactStoreApi>,
    identity_blockchain_store: Arc<dyn IdentityChainStoreApi>,
    company_blockchain_store: Arc<dyn CompanyChainStoreApi>,
}

impl CompanyService {
    pub fn new(
        store: Arc<dyn CompanyStoreApi>,
        file_upload_store: Arc<dyn FileUploadStoreApi>,
        identity_store: Arc<dyn IdentityStoreApi>,
        contact_store: Arc<dyn ContactStoreApi>,
        identity_blockchain_store: Arc<dyn IdentityChainStoreApi>,
        company_blockchain_store: Arc<dyn CompanyChainStoreApi>,
    ) -> Self {
        Self {
            store,
            file_upload_store,
            identity_store,
            contact_store,
            identity_blockchain_store,
            company_blockchain_store,
        }
    }

    async fn process_upload_file(
        &self,
        upload_id: &Option<String>,
        id: &str,
        public_key: &str,
    ) -> Result<Option<File>> {
        if let Some(upload_id) = upload_id {
            debug!("processing upload file for company {id}: {upload_id:?}");
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
}

#[async_trait]
impl CompanyServiceApi for CompanyService {
    async fn list_signatories(&self, id: &str) -> Result<Vec<Contact>> {
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

    async fn get_company_and_keys_by_id(&self, id: &str) -> Result<(Company, CompanyKeys)> {
        if !self.store.exists(id).await {
            return Err(crate::service::Error::NotFound);
        }
        let company = self.store.get(id).await?;
        let keys = self.store.get_key_pair(id).await?;
        Ok((company, keys))
    }

    async fn get_company_by_id(&self, id: &str) -> Result<Company> {
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
        let private_key = keys.get_private_key_string();
        let public_key = keys.get_public_key();

        let id = keys.get_public_key();

        let company_keys = CompanyKeys {
            private_key: private_key.to_string(),
            public_key: public_key.clone(),
        };

        let full_identity = self.identity_store.get_full().await?;
        // company can only be created by identified identity
        if full_identity.identity.t == IdentityType::Anon {
            return Err(super::Error::Validation(
                ValidationError::IdentityCantBeAnon,
            ));
        }

        // Save the files locally with the identity public key
        let proof_of_registration_file = self
            .process_upload_file(
                &proof_of_registration_file_upload_id,
                &id,
                &full_identity.key_pair.get_public_key(),
            )
            .await?;

        let logo_file = self
            .process_upload_file(
                &logo_file_upload_id,
                &id,
                &full_identity.key_pair.get_public_key(),
            )
            .await?;

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
        id: &str,
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
        if !self.store.exists(id).await {
            debug!("company with id {id} does not exist");
            return Err(super::Error::NotFound);
        }
        let full_identity = self.identity_store.get_full().await?;
        // company can only be edited by identified identity
        if full_identity.identity.t == IdentityType::Anon {
            return Err(super::Error::Validation(
                ValidationError::IdentityCantBeAnon,
            ));
        }
        let node_id = full_identity.identity.node_id;
        let mut company = self.store.get(id).await?;
        let company_keys = self.store.get_key_pair(id).await?;

        if !company.signatories.contains(&node_id.to_string()) {
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

        let logo_file = self
            .process_upload_file(
                &logo_file_upload_id,
                id,
                &full_identity.key_pair.get_public_key(),
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
                &full_identity.key_pair.get_public_key(),
            )
            .await?;
        // only override the document, if there is a new one
        if proof_of_registration_file.is_some() {
            company.proof_of_registration_file = proof_of_registration_file.clone();
        }

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
        id: &str,
        signatory_node_id: String,
        timestamp: u64,
    ) -> Result<()> {
        debug!(
            "adding signatory {} to company with id: {id}",
            &signatory_node_id
        );
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
                ValidationError::SignatoryNotInContacts(signatory_node_id),
            ));
        }

        let mut company = self.store.get(id).await?;
        let company_keys = self.store.get_key_pair(id).await?;
        if company.signatories.contains(&signatory_node_id) {
            return Err(super::Error::Validation(
                ValidationError::SignatoryAlreadySignatory(signatory_node_id),
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
            &signatory_node_id,
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
        id: &str,
        signatory_node_id: String,
        timestamp: u64,
    ) -> Result<()> {
        debug!(
            "removing signatory {} from company with id: {id}",
            &signatory_node_id
        );
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
                signatory_node_id,
            )));
        }

        company.signatories.retain(|i| i != &signatory_node_id);
        self.store.update(id, &company).await?;

        if full_identity.identity.node_id == signatory_node_id {
            info!("Removing self from company {id}");
            let _ = self.file_upload_store.delete_attached_files(id).await;
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

    async fn encrypt_and_save_uploaded_file(
        &self,
        file_name: &str,
        file_bytes: &[u8],
        id: &str,
        public_key: &str,
    ) -> Result<File> {
        let file_hash = util::sha256_hash(file_bytes);
        let encrypted = util::crypto::encrypt_ecies(file_bytes, public_key)?;
        self.file_upload_store
            .save_attached_file(&encrypted, id, file_name)
            .await?;
        info!("Saved company file {file_name} with hash {file_hash} for company {id}");
        Ok(File {
            name: file_name.to_owned(),
            hash: file_hash,
        })
    }

    async fn open_and_decrypt_file(
        &self,
        id: &str,
        file_name: &str,
        private_key: &str,
    ) -> Result<Vec<u8>> {
        debug!("getting file {file_name} for company with id: {id}",);
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
        blockchain::{Blockchain, identity::IdentityBlockchain},
        data::identity::IdentityWithAll,
        service::contact_service::tests::get_baseline_contact,
        tests::tests::{
            MockCompanyChainStoreApiMock, MockCompanyStoreApiMock, MockContactStoreApiMock,
            MockFileUploadStoreApiMock, MockIdentityChainStoreApiMock, MockIdentityStoreApiMock,
            TEST_NODE_ID_SECP, TEST_PRIVATE_KEY_SECP, TEST_PUB_KEY_SECP, empty_address,
            empty_identity, empty_optional_address,
        },
    };
    use mockall::predicate::{always, eq};
    use std::collections::HashMap;
    use util::BcrKeys;

    fn get_service(
        mock_storage: MockCompanyStoreApiMock,
        mock_file_upload_storage: MockFileUploadStoreApiMock,
        mock_identity_storage: MockIdentityStoreApiMock,
        mock_contacts_storage: MockContactStoreApiMock,
        mock_identity_chain_storage: MockIdentityChainStoreApiMock,
        mock_company_chain_storage: MockCompanyChainStoreApiMock,
    ) -> CompanyService {
        CompanyService::new(
            Arc::new(mock_storage),
            Arc::new(mock_file_upload_storage),
            Arc::new(mock_identity_storage),
            Arc::new(mock_contacts_storage),
            Arc::new(mock_identity_chain_storage),
            Arc::new(mock_company_chain_storage),
        )
    }

    fn get_storages() -> (
        MockCompanyStoreApiMock,
        MockFileUploadStoreApiMock,
        MockIdentityStoreApiMock,
        MockContactStoreApiMock,
        MockIdentityChainStoreApiMock,
        MockCompanyChainStoreApiMock,
    ) {
        (
            MockCompanyStoreApiMock::new(),
            MockFileUploadStoreApiMock::new(),
            MockIdentityStoreApiMock::new(),
            MockContactStoreApiMock::new(),
            MockIdentityChainStoreApiMock::new(),
            MockCompanyChainStoreApiMock::new(),
        )
    }

    pub fn get_baseline_company_data() -> (String, (Company, CompanyKeys)) {
        (
            TEST_PUB_KEY_SECP.to_owned(),
            (
                Company {
                    id: TEST_PUB_KEY_SECP.to_owned(),
                    name: "some_name".to_string(),
                    country_of_registration: Some("AT".to_string()),
                    city_of_registration: Some("Vienna".to_string()),
                    postal_address: empty_address(),
                    email: "company@example.com".to_string(),
                    registration_number: Some("some_number".to_string()),
                    registration_date: Some("2012-01-01".to_string()),
                    proof_of_registration_file: None,
                    logo_file: None,
                    signatories: vec![TEST_PUB_KEY_SECP.to_string()],
                },
                CompanyKeys {
                    private_key: TEST_PRIVATE_KEY_SECP.to_string(),
                    public_key: TEST_PUB_KEY_SECP.to_string(),
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
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );

        let res = service.get_list_of_companies().await;
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().len(), 1);
        assert_eq!(res.as_ref().unwrap()[0].id, TEST_PUB_KEY_SECP.to_string());
    }

    #[tokio::test]
    async fn get_list_of_companies_propagates_persistence_errors() {
        let (
            mut storage,
            file_upload_store,
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
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );

        let res = service.get_company_by_id(TEST_PUB_KEY_SECP).await;
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().id, TEST_PUB_KEY_SECP.to_string());
    }

    #[tokio::test]
    async fn get_company_by_id_fails_if_company_doesnt_exist() {
        let (
            mut storage,
            file_upload_store,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        storage.expect_exists().returning(|_| false);
        let service = get_service(
            storage,
            file_upload_store,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service.get_company_by_id("some_id").await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn get_company_by_id_propagates_persistence_errors() {
        let (
            mut storage,
            file_upload_store,
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
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service.get_company_by_id("some_id").await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn create_company_baseline() {
        let (
            mut storage,
            mut file_upload_store,
            mut identity_store,
            contact_store,
            mut identity_chain_store,
            mut company_chain_store,
        ) = get_storages();
        company_chain_store
            .expect_add_block()
            .returning(|_, _| Ok(()));
        file_upload_store
            .expect_save_attached_file()
            .returning(|_, _, _| Ok(()));
        storage.expect_save_key_pair().returning(|_, _| Ok(()));
        storage.expect_insert().returning(|_| Ok(()));
        identity_store.expect_get_full().returning(|| {
            let identity = empty_identity();
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
        assert!(!res.as_ref().unwrap().id.is_empty());
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
        let node_id = keys.get_public_key();
        let (
            mut storage,
            mut file_upload_store,
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
        file_upload_store
            .expect_save_attached_file()
            .returning(|_, _, _| Ok(()));
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
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .edit_company(
                TEST_PUB_KEY_SECP,
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
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        storage.expect_exists().returning(|_| false);
        let service = get_service(
            storage,
            file_upload_store,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .edit_company(
                "some_id",
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
            mut identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        storage.expect_exists().returning(|_| false);
        storage.expect_get().returning(|_| {
            let mut data = get_baseline_company_data().1.0;
            data.signatories = vec!["some_other_dude".to_string()];
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
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .edit_company(
                "some_id",
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
            mut identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        let keys = BcrKeys::new();
        let node_id = keys.get_public_key();
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
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .edit_company(
                "some_id",
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
            mut identity_store,
            mut contact_store,
            mut identity_chain_store,
            mut company_chain_store,
        ) = get_storages();
        let signatory_node_id = BcrKeys::new().get_public_key();
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
            identity.node_id = keys.get_public_key();
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
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .add_signatory(TEST_PUB_KEY_SECP, signatory_node_id, 1731593928)
            .await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn add_signatory_fails_if_signatory_in_contacts_but_not_a_person() {
        let (
            mut storage,
            file_upload_store,
            mut identity_store,
            mut contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        let signatory_node_id = BcrKeys::new().get_public_key();
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
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .add_signatory(TEST_PUB_KEY_SECP, signatory_node_id, 1731593928)
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn add_signatory_fails_if_signatory_not_in_contacts() {
        let (
            mut storage,
            file_upload_store,
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
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .add_signatory(
                TEST_PUB_KEY_SECP,
                "new_signatory_node_id".to_string(),
                1731593928,
            )
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn add_signatory_fails_if_company_doesnt_exist() {
        let (
            mut storage,
            file_upload_store,
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
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .add_signatory(
                TEST_PUB_KEY_SECP,
                "new_signatory_node_id".to_string(),
                1731593928,
            )
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn add_signatory_fails_if_signatory_is_already_signatory() {
        let (
            mut storage,
            file_upload_store,
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
            map.insert(TEST_NODE_ID_SECP.to_owned(), contact);
            Ok(map)
        });
        storage.expect_get().returning(|_| {
            let mut data = get_baseline_company_data().1.0;
            data.signatories.push(TEST_NODE_ID_SECP.to_string());
            Ok(data)
        });
        storage
            .expect_get_key_pair()
            .returning(|_| Ok(get_baseline_company_data().1.1));
        let service = get_service(
            storage,
            file_upload_store,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .add_signatory(TEST_PUB_KEY_SECP, TEST_NODE_ID_SECP.to_string(), 1731593928)
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn add_signatory_propagates_persistence_errors() {
        let (
            mut storage,
            file_upload_store,
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
            map.insert(TEST_NODE_ID_SECP.to_owned(), contact);
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
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .add_signatory(TEST_PUB_KEY_SECP, TEST_NODE_ID_SECP.to_string(), 1731593928)
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn remove_signatory_baseline() {
        let (
            mut storage,
            file_upload_store,
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
            data.signatories.push("new_signatory_node_id".to_string());
            data.signatories
                .push("some_other_dude_or_dudette".to_string());
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
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .remove_signatory(
                TEST_PUB_KEY_SECP,
                "new_signatory_node_id".to_string(),
                1731593928,
            )
            .await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn remove_signatory_fails_if_company_doesnt_exist() {
        let (
            mut storage,
            file_upload_store,
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
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .remove_signatory(
                TEST_PUB_KEY_SECP,
                "new_signatory_node_id".to_string(),
                1731593928,
            )
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn remove_signatory_removing_self_removes_company() {
        let keys = BcrKeys::new();
        let (
            mut storage,
            mut file_upload_store,
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
        file_upload_store
            .expect_delete_attached_files()
            .returning(|_| Ok(()));
        storage.expect_exists().returning(|_| true);
        let keys_clone = keys.clone();
        storage.expect_get().returning(move |_| {
            let mut data = get_baseline_company_data().1.0;
            data.signatories.push("the founder".to_string());
            data.signatories.push(keys_clone.clone().get_public_key());
            Ok(data)
        });
        storage
            .expect_get_key_pair()
            .returning(|_| Ok(get_baseline_company_data().1.1));
        let keys_clone_clone = keys.clone();
        identity_store.expect_get_full().returning(move || {
            let mut identity = empty_identity();
            identity.node_id = keys_clone_clone.clone().get_public_key();
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
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .remove_signatory(TEST_PUB_KEY_SECP, keys.get_public_key(), 1731593928)
            .await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn remove_signatory_fails_if_signatory_is_not_in_company() {
        let (
            mut storage,
            file_upload_store,
            mut identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        storage.expect_exists().returning(|_| true);
        storage.expect_get().returning(|_| {
            let mut data = get_baseline_company_data().1.0;
            data.signatories
                .push("some_other_dude_or_dudette".to_string());
            data.signatories.push("the_founder".to_string());
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
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .remove_signatory(
                TEST_PUB_KEY_SECP,
                "new_signatory_node_id".to_string(),
                1731593928,
            )
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn remove_signatory_fails_on_last_signatory() {
        let (
            mut storage,
            file_upload_store,
            mut identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        storage.expect_exists().returning(|_| true);
        storage.expect_get().returning(|_| {
            let mut data = get_baseline_company_data().1.0;
            data.signatories.push("the_founder".to_string());
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
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .remove_signatory(
                TEST_PUB_KEY_SECP,
                "new_signatory_node_id".to_string(),
                1731593928,
            )
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn remove_signatory_propagates_persistence_errors() {
        let (
            mut storage,
            file_upload_store,
            mut identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        storage.expect_exists().returning(|_| true);
        storage.expect_get().returning(|_| {
            let mut data = get_baseline_company_data().1.0;
            data.signatories.push("new_signatory_node_id".to_string());
            data.signatories
                .push("some_other_dude_or_dudette".to_string());
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
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .remove_signatory(
                TEST_PUB_KEY_SECP,
                "new_signatory_node_id".to_string(),
                1731593928,
            )
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn save_encrypt_open_decrypt_compare_hashes() {
        let company_id = "00000000-0000-0000-0000-000000000000";
        let file_name = "file_00000000-0000-0000-0000-000000000000.pdf";
        let file_bytes = String::from("hello world").as_bytes().to_vec();
        let expected_encrypted =
            util::crypto::encrypt_ecies(&file_bytes, TEST_PUB_KEY_SECP).unwrap();

        let (
            storage,
            mut file_upload_store,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        file_upload_store
            .expect_save_attached_file()
            .with(always(), eq(company_id), eq(file_name))
            .times(1)
            .returning(|_, _, _| Ok(()));

        file_upload_store
            .expect_open_attached_file()
            .with(eq(company_id), eq(file_name))
            .times(1)
            .returning(move |_, _| Ok(expected_encrypted.clone()));
        let service = get_service(
            storage,
            file_upload_store,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );

        let file = service
            .encrypt_and_save_uploaded_file(file_name, &file_bytes, company_id, TEST_PUB_KEY_SECP)
            .await
            .unwrap();
        assert_eq!(
            file.hash,
            String::from("DULfJyE3WQqNxy3ymuhAChyNR3yufT88pmqvAazKFMG4")
        );
        assert_eq!(file.name, String::from(file_name));

        let decrypted = service
            .open_and_decrypt_file(company_id, file_name, TEST_PRIVATE_KEY_SECP)
            .await
            .unwrap();
        assert_eq!(std::str::from_utf8(&decrypted).unwrap(), "hello world");
    }

    #[tokio::test]
    async fn save_encrypt_propagates_write_file_error() {
        let (
            storage,
            mut file_upload_store,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        file_upload_store
            .expect_save_attached_file()
            .returning(|_, _, _| {
                Err(bcr_ebill_persistence::Error::Io(std::io::Error::other(
                    "test error",
                )))
            });
        let service = get_service(
            storage,
            file_upload_store,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );

        assert!(
            service
                .encrypt_and_save_uploaded_file("file_name", &[], "test", TEST_PUB_KEY_SECP)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn open_decrypt_propagates_read_file_error() {
        let (
            storage,
            mut file_upload_store,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        file_upload_store
            .expect_open_attached_file()
            .returning(|_, _| {
                Err(bcr_ebill_persistence::Error::Io(std::io::Error::other(
                    "test error",
                )))
            });
        let service = get_service(
            storage,
            file_upload_store,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );

        assert!(
            service
                .open_and_decrypt_file(TEST_PUB_KEY_SECP, "test", TEST_PRIVATE_KEY_SECP)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn list_signatories_baseline() {
        let (
            mut storage,
            file_upload_store,
            identity_store,
            mut contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        storage.expect_exists().returning(|_| true);
        storage.expect_get().returning(|_| {
            let mut data = get_baseline_company_data().1.0;
            data.signatories.push("new_signatory_node_id".to_string());
            data.signatories
                .push("some_other_dude_or_dudette".to_string());
            Ok(data)
        });

        contact_store.expect_get_map().returning(move || {
            let mut map = HashMap::new();
            let mut contact = get_baseline_contact();
            contact.node_id = "new_signatory_node_id".to_owned();
            map.insert(contact.node_id.clone(), contact);
            Ok(map)
        });

        let service = get_service(
            storage,
            file_upload_store,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );

        let res = service.list_signatories(TEST_PUB_KEY_SECP).await;
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().len(), 1);
    }
}
