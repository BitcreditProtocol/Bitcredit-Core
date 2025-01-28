use super::behaviour::{
    file_request_for_bill, file_request_for_bill_attachment, file_request_for_bill_keys,
    file_request_for_company_chain, file_request_for_company_data, file_request_for_company_keys,
    file_request_for_company_logo, file_request_for_company_proof, parse_inbound_file_request,
    BillAttachmentFileRequest, BillFileRequest, BillKeysFileRequest, Command, CompanyChainRequest,
    CompanyDataRequest, CompanyEvent, CompanyKeysRequest, CompanyLogoRequest, CompanyProofRequest,
    Event, FileResponse, ParsedInboundFileRequest,
};
use super::{GossipsubEvent, GossipsubEventId, Result};
use crate::blockchain::bill::BillBlockchain;
use crate::blockchain::company::CompanyBlockchain;
use crate::blockchain::Blockchain;
use crate::constants::{BILLS_PREFIX, BILL_PREFIX, COMPANIES_PREFIX, COMPANY_PREFIX};
use crate::persistence::bill::{
    bill_chain_from_bytes, bill_chain_to_bytes, bill_keys_from_bytes, bill_keys_to_bytes,
    BillChainStoreApi, BillStoreApi,
};
use crate::persistence::company::{
    company_chain_from_bytes, company_chain_to_bytes, company_from_bytes, company_keys_from_bytes,
    company_keys_to_bytes, company_to_bytes, CompanyChainStoreApi, CompanyStoreApi,
};
use crate::persistence::file_upload::FileUploadStoreApi;
use crate::persistence::identity::IdentityStoreApi;
use crate::service::bill_service::BillKeys;
use crate::service::company_service::{Company, CompanyKeys};
use crate::{blockchain, util};
use borsh::{from_slice, to_vec};
use future::{try_join_all, BoxFuture};
use futures::channel::mpsc::Receiver;
use futures::channel::{mpsc, oneshot};
use futures::prelude::*;
use libp2p::kad::record::Record;
use libp2p::request_response::ResponseChannel;
use libp2p::PeerId;
use log::{error, info};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::broadcast;

/// The DHT client
#[derive(Clone)]
pub struct Client {
    /// The sender to send events to the event loop
    pub(super) sender: mpsc::Sender<Command>,
    bill_store: Arc<dyn BillStoreApi>,
    bill_blockchain_store: Arc<dyn BillChainStoreApi>,
    company_store: Arc<dyn CompanyStoreApi>,
    company_blockchain_store: Arc<dyn CompanyChainStoreApi>,
    identity_store: Arc<dyn IdentityStoreApi>,
    file_upload_store: Arc<dyn FileUploadStoreApi>,
}

impl Client {
    pub fn new(
        sender: mpsc::Sender<Command>,
        bill_store: Arc<dyn BillStoreApi>,
        bill_blockchain_store: Arc<dyn BillChainStoreApi>,
        company_store: Arc<dyn CompanyStoreApi>,
        company_blockchain_store: Arc<dyn CompanyChainStoreApi>,
        identity_store: Arc<dyn IdentityStoreApi>,
        file_upload_store: Arc<dyn FileUploadStoreApi>,
    ) -> Self {
        Self {
            sender,
            bill_store,
            bill_blockchain_store,
            company_store,
            company_blockchain_store,
            identity_store,
            file_upload_store,
        }
    }

    /// Runs the dht client, listening for incoming events from the event loop
    pub async fn run(
        mut self,
        mut network_events: Receiver<Event>,
        mut shutdown_dht_client_receiver: broadcast::Receiver<bool>,
    ) {
        loop {
            tokio::select! {
                event = network_events.next() => {
                    if let Some(evt) = event {
                        if let Err(e) = self.handle_event(evt).await {
                            error!("Error while handling event in DHT client: {e}");
                        }
                    }
                },
                _ = shutdown_dht_client_receiver.recv() => {
                    info!("Shutting down dht client...");
                    break;
                }
            }
        }
    }

    // --------------------------------------------------------------
    // Company-related logic ---------------------------------------
    // --------------------------------------------------------------

    fn company_key(&self, company_id: &str) -> String {
        format!("{COMPANY_PREFIX}{company_id}")
    }

    fn node_request_for_companies(&self, node_id: &str) -> String {
        format!("{COMPANIES_PREFIX}{node_id}")
    }

    /// Gets the list of companies from the network for the local node and gets the companies that
    /// aren't locally available from the network and starts providing them and subscribing to them
    pub async fn check_companies(&mut self) -> Result<()> {
        log::info!("Checking for new companies...");
        let local_node_id = self.identity_store.get().await?.node_id;
        let node_request = self.node_request_for_companies(&local_node_id);
        let companies_for_node = self.get_record(node_request.clone()).await?.value;
        if companies_for_node.is_empty() {
            return Ok(());
        }
        let companies: Vec<String> = from_slice(&companies_for_node)?;
        let local_companies: Vec<String> = self
            .company_store
            .get_all()
            .await?
            .iter()
            .map(|(id, (_, _))| id.to_string())
            .collect();

        let local_but_not_remote: Vec<String> = local_companies
            .into_iter()
            .filter(|item| !companies.contains(item))
            .collect();

        // Remove the companies, we have locally, but where the network tells us we're not a part
        // of anymore
        for company in local_but_not_remote {
            let _ = self.file_upload_store.delete_attached_files(&company).await;
            self.company_store.remove(&company).await?;
            self.company_blockchain_store.remove(&company).await?;
            self.stop_providing_company(&company).await?;
            self.unsubscribe_from_company_topic(&company).await?;
        }

        // Add companies the network tells us we're part of, but we don't have locally
        for company in companies {
            if self.company_store.exists(&company).await {
                continue;
            }
            if let Err(e) = self
                .get_company_data_from_the_network(&company, &local_node_id)
                .await
            {
                error!("Could not get company data from network for {company}: {e}");
                continue;
            }
            self.start_providing_company(&company).await?;
            self.subscribe_to_company_topic(&company).await?;
        }

        Ok(())
    }

    async fn get_company_data_from_the_network(
        &mut self,
        company_id: &str,
        local_node_id: &str,
    ) -> Result<()> {
        let mut providers = self.get_company_providers(company_id).await?;
        if let Some(local_peer_id) = providers
            .iter()
            .find(|p| util::crypto::is_peer_id_from_this_node_id(local_node_id, p))
            .cloned()
        {
            providers.remove(&local_peer_id);
        }
        if providers.is_empty() {
            error!("Get Company Files: No providers found for {company_id}");
            return Ok(());
        }
        let company = self
            .request_company_data(company_id, local_node_id, &providers)
            .await?;

        let company_keys = self
            .request_company_keys(company_id, local_node_id, &providers)
            .await?;

        let company_chain = self
            .request_company_chain(company_id, local_node_id, &providers)
            .await?;

        // like with bills, we don't fail on not being able to fetch files
        let mut logo_file: Option<Vec<u8>> = None;
        if let Some(ref logo) = company.logo_file {
            let file_request = file_request_for_company_logo(local_node_id, company_id, &logo.name);
            match self
                .request_company_file(company_id, file_request, &providers, &logo.hash, &logo.name)
                .await
            {
                Err(e) => {
                    logo_file = None;
                    error!("Could not fetch company logo file for {company_id}: {e}");
                }
                Ok(bytes) => {
                    logo_file = Some(bytes);
                }
            };
        }
        let mut proof_file: Option<Vec<u8>> = None;
        if let Some(ref proof) = company.proof_of_registration_file {
            let file_request =
                file_request_for_company_proof(local_node_id, company_id, &proof.name);
            match self
                .request_company_file(
                    company_id,
                    file_request,
                    &providers,
                    &proof.hash,
                    &proof.name,
                )
                .await
            {
                Err(e) => {
                    proof_file = None;
                    error!("Could not fetch company proof file for {company_id}: {e}");
                }
                Ok(bytes) => {
                    proof_file = Some(bytes);
                }
            };
        }

        if !company_chain.is_chain_valid() {
            error!("Fetched chain for {company_id} was invalid");
            return Err(crate::dht::Error::Blockchain(
                blockchain::Error::BlockchainInvalid,
            ));
        }
        for block in company_chain.blocks() {
            self.company_blockchain_store
                .add_block(company_id, block)
                .await?;
        }

        self.company_store.insert(&company).await?;
        self.company_store
            .save_key_pair(company_id, &company_keys)
            .await?;

        if logo_file.is_some() || proof_file.is_some() {
            if let Some(encrypted_logo_bytes) = logo_file {
                if let Some(ref file) = company.logo_file {
                    self.file_upload_store
                        .save_attached_file(&encrypted_logo_bytes, company_id, &file.name)
                        .await?;
                }
            }

            if let Some(encrypted_proof_bytes) = proof_file {
                if let Some(ref file) = company.proof_of_registration_file {
                    self.file_upload_store
                        .save_attached_file(&encrypted_proof_bytes, company_id, &file.name)
                        .await?;
                }
            }
        }
        Ok(())
    }

    async fn request_company_data(
        &mut self,
        company_id: &str,
        local_node_id: &str,
        providers: &HashSet<PeerId>,
    ) -> Result<Company> {
        let requests = self.create_file_requests_for_peers(
            file_request_for_company_data(local_node_id, company_id),
            providers,
        );

        match futures::future::select_ok(requests).await {
            Err(e) => Err(super::Error::NoProviders(format!(
                "Get Company Data: None of the providers returned the file for {company_id}: {e}",
            ))),
            Ok(file_content) => {
                let company = company_from_bytes(&file_content.0)?;
                Ok(company)
            }
        }
    }

    async fn request_company_keys(
        &mut self,
        company_id: &str,
        local_node_id: &str,
        providers: &HashSet<PeerId>,
    ) -> Result<CompanyKeys> {
        let identity_keys = self.identity_store.get_key_pair().await?;
        let requests = self.create_file_requests_for_peers(
            file_request_for_company_keys(local_node_id, company_id),
            providers,
        );

        match futures::future::select_ok(requests).await {
            Err(e) => Err(super::Error::NoProviders(format!(
                "Get Company Keys: None of the providers returned the file for {company_id}: {e}",
            ))),
            Ok(file_content) => {
                let encrypted_bytes = file_content.0;
                let decrypted_bytes = util::crypto::decrypt_ecies(
                    &encrypted_bytes,
                    &identity_keys.get_private_key_string(),
                )?;
                let company_keys = company_keys_from_bytes(&decrypted_bytes)?;
                Ok(company_keys)
            }
        }
    }

    async fn request_company_chain(
        &mut self,
        company_id: &str,
        local_node_id: &str,
        providers: &HashSet<PeerId>,
    ) -> Result<CompanyBlockchain> {
        let identity_keys = self.identity_store.get_key_pair().await?;
        let requests = self.create_file_requests_for_peers(
            file_request_for_company_chain(local_node_id, company_id),
            providers,
        );

        match futures::future::select_ok(requests).await {
            Err(e) => Err(super::Error::NoProviders(format!(
                "Get Company Chain: None of the providers returned the file for {company_id}: {e}",
            ))),
            Ok(file_content) => {
                let encrypted_bytes = file_content.0;
                let decrypted_bytes = util::crypto::decrypt_ecies(
                    &encrypted_bytes,
                    &identity_keys.get_private_key_string(),
                )?;
                let company_chain = company_chain_from_bytes(&decrypted_bytes)?;
                Ok(company_chain)
            }
        }
    }

    async fn request_company_file(
        &mut self,
        company_id: &str,
        file_request: String,
        providers: &HashSet<PeerId>,
        hash: &str,
        file_name: &str,
    ) -> Result<Vec<u8>> {
        let identity_keys = self.identity_store.get_key_pair().await?;
        let requests = self.create_file_requests_for_peers(file_request, providers);

        match futures::future::select_ok(requests).await {
            Err(e) => Err(super::Error::NoProviders(format!(
                "Get Company File: None of the providers returned the file for {company_id}: {e}",
            ))),
            Ok(file_content) => {
                let encrypted_bytes = file_content.0;
                let decrypted_bytes = util::crypto::decrypt_ecies(
                    &encrypted_bytes,
                    &identity_keys.get_private_key_string(),
                )?;
                let remote_hash = util::sha256_hash(&decrypted_bytes);
                if hash != remote_hash.as_str() {
                    return Err(super::Error::FileHashesDidNotMatch(format!("Get Company File: Hashes didn't match for company {company_id} and file name {file_name}, remote: {remote_hash}, local: {hash}")));
                }
                let encrypted_bytes =
                    util::crypto::encrypt_ecies(&decrypted_bytes, &identity_keys.get_public_key())?;
                Ok(encrypted_bytes)
            }
        }
    }

    /// Subscribes to all locally available companies
    pub async fn subscribe_to_all_companies_topics(&mut self) -> Result<()> {
        let companies = self.company_store.get_all().await?;

        if !companies.is_empty() {
            let tasks = companies.into_iter().map(|(id, (_, _))| {
                let mut self_clone = self.clone();
                async move { self_clone.subscribe_to_bill_topic(&id).await }
            });

            try_join_all(tasks).await?;
        }
        Ok(())
    }

    /// Starts providing all locally available companies
    pub async fn start_providing_companies(&mut self) -> Result<()> {
        let companies = self.company_store.get_all().await?;

        if !companies.is_empty() {
            let tasks = companies.into_iter().map(|(id, (_, _))| {
                let mut self_clone = self.clone();
                async move { self_clone.start_providing_company(&id).await }
            });

            try_join_all(tasks).await?;
        }
        Ok(())
    }

    /// Puts all signatories of every local company to the record of the respective company in the DHT
    pub async fn put_companies_for_signatories(&mut self) -> Result<()> {
        log::info!("Putting signatories for local companies in the DHT");
        let companies = self.company_store.get_all().await?;

        // for each signatory, make one set_record with a list of the companies
        if !companies.is_empty() {
            // collect companies for each unique signatory
            let mut signatory_companies_map: HashMap<String, Vec<String>> = HashMap::new();
            for (company_id, (company, _)) in companies {
                for signatory in company.signatories {
                    signatory_companies_map
                        .entry(signatory.clone())
                        .or_default()
                        .push(company_id.clone());
                }
            }

            // for each signatory, set the collected companies on the DHT
            let tasks = signatory_companies_map
                .into_iter()
                .map(|(signatory, company_ids)| {
                    let mut self_clone = self.clone();
                    async move {
                        self_clone
                            .add_companies_to_dht_for_node(company_ids, &signatory)
                            .await
                    }
                });

            try_join_all(tasks).await?;
        }

        Ok(())
    }

    /// Adds the given list of companies to the DHT for the node_id, if the data from the DHT is
    /// empty, or invalid, we just set the given list, otherwise we merge the unique elements of both
    pub async fn add_companies_to_dht_for_node(
        &mut self,
        company_ids: Vec<String>,
        node_id: &str,
    ) -> Result<()> {
        if company_ids.is_empty() {
            return Ok(());
        }

        let node_request = self.node_request_for_companies(node_id);
        match self.get_record(node_request.clone()).await {
            Ok(companies_record) => {
                let companies_for_node = companies_record.value;
                if companies_for_node.is_empty() {
                    self.put_record(node_request, to_vec(&company_ids)?).await?;
                } else {
                    match from_slice::<Vec<String>>(&companies_for_node) {
                        Ok(dht_record) => {
                            let mut unique_elements: HashSet<String> = HashSet::new();
                            unique_elements.extend(dht_record.clone().into_iter());
                            unique_elements.extend(company_ids.into_iter());
                            let result: Vec<String> = unique_elements.into_iter().collect();

                            if !dht_record.eq(&result) {
                                self.put_record(node_request.clone(), to_vec(&result)?)
                                    .await?;
                            }
                        }
                        Err(e) => {
                            error!("Could not parse company data in dht for {node_id}: {e}");
                            self.put_record(node_request.clone(), to_vec(&company_ids)?)
                                .await?;
                        }
                    }
                }
            }
            Err(_) => {
                self.put_record(node_request, to_vec(&company_ids)?).await?;
            }
        }
        Ok(())
    }

    /// Removes the given company from the list of companies for the given node - if the data is empty,
    /// or invalid, we don't do anything. Otherwise, we remove the given company id from the DHT value,
    /// if it contains it
    pub async fn remove_company_from_dht_for_node(
        &mut self,
        company_id: &str,
        node_id: &str,
    ) -> Result<()> {
        let node_request = self.node_request_for_companies(node_id);
        if let Ok(companies_record) = self.get_record(node_request.clone()).await {
            let companies_for_node = companies_record.value;
            if !companies_for_node.is_empty() {
                match from_slice::<Vec<String>>(&companies_for_node) {
                    Ok(dht_record) => {
                        let mut record_for_saving_in_dht = dht_record.clone();
                        record_for_saving_in_dht.retain(|item| item != company_id);

                        if !dht_record.eq(&record_for_saving_in_dht) {
                            self.put_record(
                                node_request.clone(),
                                to_vec(&record_for_saving_in_dht)?,
                            )
                            .await?;
                        }
                    }
                    Err(e) => {
                        error!("Could not parse company data in dht for {node_id} when trying to remove company {company_id}: {e}");
                    }
                }
            }
        }

        Ok(())
    }
    /// Adds the given company to the list of companies for the given node - if the data is empty,
    /// or invalid, we just push our local data. Otherwise, we add the given company id to the DHT,
    /// if it doesn't already contain it
    pub async fn add_company_to_dht_for_node(
        &mut self,
        company_id: &str,
        node_id: &str,
    ) -> Result<()> {
        let node_request = self.node_request_for_companies(node_id);
        let mut record_for_saving_in_dht: Vec<String> = vec![];
        match self.get_record(node_request.clone()).await {
            Err(_) => {
                record_for_saving_in_dht.push(company_id.to_owned());
                self.put_record(node_request, to_vec(&record_for_saving_in_dht)?)
                    .await?;
            }
            Ok(companies_record) => {
                let companies_for_node = companies_record.value;
                if companies_for_node.is_empty() {
                    record_for_saving_in_dht.push(company_id.to_owned());
                    self.put_record(node_request, to_vec(&record_for_saving_in_dht)?)
                        .await?;
                } else {
                    match from_slice::<Vec<String>>(&companies_for_node) {
                        Ok(dht_record) => {
                            record_for_saving_in_dht = dht_record.clone();
                            if !record_for_saving_in_dht.contains(&company_id.to_string()) {
                                record_for_saving_in_dht.push(company_id.to_owned());
                            }
                            if !dht_record.eq(&record_for_saving_in_dht) {
                                self.put_record(
                                    node_request.clone(),
                                    to_vec(&record_for_saving_in_dht)?,
                                )
                                .await?;
                            }
                        }
                        Err(e) => {
                            error!("Could not parse company data in dht for {node_id}: {e}");
                            self.put_record(
                                node_request.clone(),
                                to_vec(&vec![company_id.to_owned()])?,
                            )
                            .await?;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    // ---------------------------------------------------------
    // Bill-related logic --------------------------------------
    // ---------------------------------------------------------

    fn bill_key(&self, bill_id: &str) -> String {
        format!("{BILL_PREFIX}{bill_id}")
    }

    fn node_request_for_bills(&self, node_id: &str) -> String {
        format!("{BILLS_PREFIX}{node_id}")
    }

    /// Checks the bill record for the local node, adding missing bills and starts providing them, if necessary
    pub async fn update_bills_table(&mut self, node_id: &str) -> Result<()> {
        let node_request = self.node_request_for_bills(node_id);

        let bill_ids = self.bill_store.get_ids().await?;
        match self.get_record(node_request.clone()).await {
            Err(_) => {
                let mut new_record = Vec::with_capacity(bill_ids.len());
                for bill_id in bill_ids {
                    new_record.push(bill_id.clone());
                    self.start_providing_bill(&bill_id).await?;
                }
                if !new_record.is_empty() {
                    self.put_record(node_request.clone(), to_vec(&new_record)?)
                        .await?;
                }
            }
            Ok(bills_record) => {
                let value = bills_record.value;
                if !value.is_empty() {
                    let record_in_dht: Vec<String> = from_slice(&value)?;
                    let mut new_record = record_in_dht.clone();

                    for bill_id in bill_ids {
                        if !record_in_dht.contains(&bill_id) {
                            new_record.push(bill_id.clone());
                            self.start_providing_bill(&bill_id).await?;
                        }
                    }
                    if !record_in_dht.eq(&new_record) {
                        self.put_record(node_request.clone(), to_vec(&new_record)?)
                            .await?;
                    }
                } else {
                    let mut new_record = Vec::with_capacity(bill_ids.len());
                    for bill_id in bill_ids {
                        new_record.push(bill_id.clone());
                        self.start_providing_bill(&bill_id).await?;
                    }
                    if !new_record.is_empty() {
                        self.put_record(node_request.clone(), to_vec(&new_record)?)
                            .await?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Starts providing all locally available bills
    pub async fn start_providing_bills(&mut self) -> Result<()> {
        let bills = self.bill_store.get_ids().await?;
        for bill in bills {
            self.start_providing_bill(&bill).await?;
        }
        Ok(())
    }

    /// Adds the given bill for the given node id - if the data is empty, or invalid, we just push
    /// our data on the DHT, otherwise we check, if we have data the DHT doesn't have and add that
    pub async fn add_bill_to_dht_for_node(&mut self, bill_id: &str, node_id: &str) -> Result<()> {
        let node_request = self.node_request_for_bills(node_id);
        let mut record_for_saving_in_dht: Vec<String> = vec![];
        match self.get_record(node_request.clone()).await {
            Ok(bills_record) => {
                let list_bills_for_node = bills_record.value;
                match from_slice::<Vec<String>>(&list_bills_for_node) {
                    Ok(dht_record) => {
                        record_for_saving_in_dht = dht_record.clone();
                        if !record_for_saving_in_dht.iter().any(|b| b == bill_id) {
                            record_for_saving_in_dht.push(bill_id.to_owned());
                        }
                        if !dht_record.eq(&record_for_saving_in_dht) {
                            self.put_record(
                                node_request.clone(),
                                to_vec(&record_for_saving_in_dht)?,
                            )
                            .await?;
                        }
                    }
                    Err(e) => {
                        error!("Could not parse bill data in dht for {}: {e}", &bill_id);
                        self.put_record(node_request.clone(), to_vec(&vec![bill_id.to_owned()])?)
                            .await?;
                    }
                }
            }
            Err(_) => {
                record_for_saving_in_dht.push(bill_id.to_owned());
                self.put_record(node_request.clone(), to_vec(&record_for_saving_in_dht)?)
                    .await?;
            }
        }

        Ok(())
    }

    /// Checks the DHT for new bills, fetching the bill data, keys and files for them
    pub async fn check_new_bills(&mut self) -> Result<()> {
        let local_node_id = self.identity_store.get().await?.node_id;
        let node_request = self.node_request_for_bills(&local_node_id);
        if let Ok(list_bills_for_node) = self.get_record(node_request.clone()).await {
            let bills_for_node = list_bills_for_node.value;

            if bills_for_node.is_empty() {
                return Ok(());
            }

            let bills: Vec<String> = from_slice(&bills_for_node)?;
            for bill_id in bills {
                if self.bill_store.exists(&bill_id).await {
                    continue;
                }
                if let Err(e) = self
                    .get_bill_data_from_the_network(&bill_id, &local_node_id)
                    .await
                {
                    error!("Could not get bill data from network for {bill_id}: {e}");
                    continue;
                };
                self.start_providing_bill(&bill_id).await?;
                self.subscribe_to_bill_topic(&bill_id).await?;
            }
        }
        Ok(())
    }

    /// Fetches the bill blockchain, keys and attached file data for the given bill from the network and then persists it locally
    pub async fn get_bill_data_from_the_network(
        &mut self,
        bill_id: &str,
        local_node_id: &str,
    ) -> Result<()> {
        let mut providers = self.get_bill_providers(bill_id).await?;
        if let Some(local_peer_id) = providers
            .iter()
            .find(|p| util::crypto::is_peer_id_from_this_node_id(local_node_id, p))
            .cloned()
        {
            providers.remove(&local_peer_id);
        }
        if providers.is_empty() {
            error!("Get Bill Files: No providers found for {bill_id}");
            return Ok(());
        }

        let chain = self
            .request_bill_data(bill_id, local_node_id, &providers)
            .await?;

        let bill_keys = self
            .request_key_data(bill_id, local_node_id, &providers)
            .await?;

        let bill = chain.get_first_version_bill(&bill_keys)?;
        let mut file_map: HashMap<String, Vec<u8>> = HashMap::new();
        for file in bill.files {
            let (file_name, file_bytes) = self
                .request_bill_attachment_data(
                    bill_id,
                    &file.name,
                    &file.hash,
                    &bill_keys,
                    local_node_id,
                    &providers,
                )
                .await?;
            file_map.insert(file_name, file_bytes);
        }

        if !chain.is_chain_valid() {
            error!("Fetched chain for {bill_id} was invalid");
            return Err(crate::dht::Error::Blockchain(
                blockchain::Error::BlockchainInvalid,
            ));
        }
        for block in chain.blocks() {
            self.bill_blockchain_store.add_block(bill_id, block).await?;
        }

        self.bill_store.save_keys(bill_id, &bill_keys).await?;

        for (file_name, file_bytes) in file_map.iter() {
            self.file_upload_store
                .save_attached_file(file_bytes, bill_id, file_name)
                .await?;
        }

        Ok(())
    }

    /// Requests the data file for the given bill, saving it locally
    async fn request_bill_data(
        &mut self,
        name: &str,
        local_node_id: &str,
        providers: &HashSet<PeerId>,
    ) -> Result<BillBlockchain> {
        let requests = self
            .create_file_requests_for_peers(file_request_for_bill(local_node_id, name), providers);

        match futures::future::select_ok(requests).await {
            Err(e) => Err(super::Error::NoProviders(format!(
                "Get Bill: None of the providers returned the file for {name}: {e}",
            ))),
            Ok(file_content) => {
                let chain = bill_chain_from_bytes(&file_content.0)?;
                Ok(chain)
            }
        }
    }

    /// Requests the given file for the given bill id, decrypting it, checking it's hash,
    /// encrypting it and returning it's bytes with it's file name
    async fn request_bill_attachment_data(
        &mut self,
        bill_id: &str,
        file_name: &str,
        hash: &str,
        bill_keys: &BillKeys,
        local_node_id: &str,
        providers: &HashSet<PeerId>,
    ) -> Result<(String, Vec<u8>)> {
        let pr_key = self
            .identity_store
            .get_key_pair()
            .await?
            .get_private_key_string();
        let requests = self.create_file_requests_for_peers(
            file_request_for_bill_attachment(local_node_id, bill_id, file_name),
            providers,
        );
        match futures::future::select_ok(requests).await {
            Err(e) => Err(super::Error::NoFileFromProviders(format!(
                "Get Bill Attachment: None of the providers returned the file for {bill_id}: {e}"
            ))),
            Ok(file_content) => {
                let bytes = file_content.0;
                // decrypt file using identity private key and check hash
                let decrypted_with_identity_key = util::crypto::decrypt_ecies(&bytes, &pr_key)?;
                let decrypted_with_bill_key = util::crypto::decrypt_ecies(
                    &decrypted_with_identity_key,
                    &bill_keys.private_key,
                )?;
                let remote_hash = util::sha256_hash(&decrypted_with_bill_key);
                if hash != remote_hash.as_str() {
                    return Err(super::Error::FileHashesDidNotMatch(format!("Get Bill Attachment: Hashes didn't match for bill {bill_id} and file name {file_name}, remote: {remote_hash}, local: {hash}")));
                }
                // encrypt with bill public key
                let encrypted =
                    util::crypto::encrypt_ecies(&decrypted_with_bill_key, &bill_keys.public_key)?;
                Ok((file_name.to_string(), encrypted))
            }
        }
    }

    /// Requests the keys file for the given bill, decrypting it and saving it locally
    async fn request_key_data(
        &mut self,
        name: &str,
        local_node_id: &str,
        providers: &HashSet<PeerId>,
    ) -> Result<BillKeys> {
        let pr_key = self
            .identity_store
            .get_key_pair()
            .await?
            .get_private_key_string();
        let requests = self.create_file_requests_for_peers(
            file_request_for_bill_keys(local_node_id, name),
            providers,
        );

        match futures::future::select_ok(requests).await {
            Err(e) => Err(super::Error::NoFileFromProviders(format!(
                "Get Bill Keys: None of the providers returned the file for {name}: {e}"
            ))),
            Ok(file_content) => {
                let bytes = file_content.0;
                let key_bytes_decrypted = util::crypto::decrypt_ecies(&bytes, &pr_key)?;

                let bill_keys = bill_keys_from_bytes(&key_bytes_decrypted)?;
                Ok(bill_keys)
            }
        }
    }

    /// Puts all participants of every local bill to the record of the respective bill in the DHT
    pub async fn put_bills_for_parties(&mut self) -> Result<()> {
        let bill_ids = self.bill_store.get_ids().await?;

        for bill in bill_ids {
            let bill_keys = self.bill_store.get_keys(&bill).await?;
            let chain = self.bill_blockchain_store.get_chain(&bill).await?;
            let nodes = chain.get_all_nodes_from_bill(&bill_keys)?;
            for node in nodes {
                self.add_bill_to_dht_for_node(&bill, &node).await?;
            }
        }
        Ok(())
    }

    /// Subscribes to all locally available bills
    pub async fn subscribe_to_all_bills_topics(&mut self) -> Result<()> {
        let bill_ids = self.bill_store.get_ids().await?;

        for bill in bill_ids {
            self.subscribe_to_bill_topic(&bill).await?;
        }
        Ok(())
    }

    /// Asks on the topic to receive the current chain of all local bills
    pub async fn receive_updates_for_all_bills_topics(&mut self) -> Result<()> {
        let bill_ids = self.bill_store.get_ids().await?;

        for bill in bill_ids {
            let event =
                GossipsubEvent::new(GossipsubEventId::CommandGetBillBlockchain, vec![0; 24]);
            let message = event.to_byte_array()?;

            self.add_message_to_bill_topic(message, &bill).await?;
        }
        Ok(())
    }

    // -------------------------------------------------------------
    // Utility Functions for the DHT -------------------------------
    // -------------------------------------------------------------

    fn create_file_requests_for_peers<'a>(
        &'a mut self,
        file_request: String,
        providers: &'a HashSet<PeerId>,
    ) -> impl Iterator<Item = BoxFuture<'a, Result<Vec<u8>>>> {
        providers.iter().map(move |peer| {
            let mut cloned_client = self.clone();
            let cloned_fr = file_request.clone();
            async move { cloned_client.request_file(peer.to_owned(), cloned_fr).await }.boxed()
        })
    }

    async fn add_message_to_topic(&mut self, msg: Vec<u8>, topic: String) -> Result<()> {
        self.send_message(msg, topic).await?;
        Ok(())
    }

    /// Sends the given message to the given bill topic via the event loop
    pub async fn add_message_to_bill_topic(&mut self, msg: Vec<u8>, topic: &str) -> Result<()> {
        let key = self.bill_key(topic);
        self.add_message_to_topic(msg, key).await?;
        Ok(())
    }

    /// Sends the given message to the given company topic via the event loop
    pub async fn add_message_to_company_topic(&mut self, msg: Vec<u8>, topic: &str) -> Result<()> {
        let key = self.company_key(topic);
        self.add_message_to_topic(msg, key).await?;
        Ok(())
    }

    async fn subscribe_to_topic(&mut self, topic: String) -> Result<()> {
        self.sender
            .send(Command::SubscribeToTopic { topic })
            .await?;
        Ok(())
    }

    async fn unsubscribe_from_topic(&mut self, topic: String) -> Result<()> {
        self.sender
            .send(Command::UnsubscribeFromTopic { topic })
            .await?;
        Ok(())
    }

    /// Subscribe to the given bill topic via the event loop
    pub async fn subscribe_to_bill_topic(&mut self, topic: &str) -> Result<()> {
        let key = self.bill_key(topic);
        self.subscribe_to_topic(key).await?;
        Ok(())
    }

    /// Subscribe to the given company topic via the event loop
    pub async fn subscribe_to_company_topic(&mut self, topic: &str) -> Result<()> {
        let key = self.company_key(topic);
        self.subscribe_to_topic(key).await?;
        Ok(())
    }

    /// Unsubscribe from the given company topic via the event loop
    pub async fn unsubscribe_from_company_topic(&mut self, topic: &str) -> Result<()> {
        let key = self.company_key(topic);
        self.unsubscribe_from_topic(key).await?;
        Ok(())
    }

    /// Send the given message to the given topic via the event loop
    pub async fn send_message(&mut self, msg: Vec<u8>, topic: String) -> Result<()> {
        self.sender
            .send(Command::SendMessage { msg, topic })
            .await?;
        Ok(())
    }

    /// Puts the given value into the DHT at the given key via the event loop
    pub async fn put_record(&mut self, key: String, value: Vec<u8>) -> Result<()> {
        self.sender.send(Command::PutRecord { key, value }).await?;
        Ok(())
    }

    /// Gets the record for the given key via the event loop
    pub async fn get_record(&mut self, key: String) -> Result<Record> {
        let (sender, receiver) = oneshot::channel();
        self.sender.send(Command::GetRecord { key, sender }).await?;
        let record = receiver.await?;
        record.map_err(|e| super::Error::GetRecord(e.to_string()))
    }

    async fn start_providing(&mut self, entry: String) -> Result<()> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Command::StartProviding { entry, sender })
            .await?;
        receiver.await?;
        Ok(())
    }

    async fn stop_providing(&mut self, entry: String) -> Result<()> {
        self.sender.send(Command::StopProviding { entry }).await?;
        Ok(())
    }

    /// Adds the current node to the list of providers for the given bill via the event loop
    pub async fn start_providing_bill(&mut self, bill_id: &str) -> Result<()> {
        let key = self.bill_key(bill_id);
        self.start_providing(key).await?;
        Ok(())
    }

    /// Adds the current node to the list of providers for the given company via the event loop
    pub async fn start_providing_company(&mut self, company_id: &str) -> Result<()> {
        let key = self.company_key(company_id);
        self.start_providing(key).await?;
        Ok(())
    }

    /// Removes the current node from the list of providers for the given company via the event loop
    pub async fn stop_providing_company(&mut self, company_id: &str) -> Result<()> {
        let key = self.company_key(company_id);
        self.stop_providing(key).await?;
        Ok(())
    }

    /// Gets the providers for the given file via the event loop
    async fn get_providers(&mut self, entry: String) -> Result<HashSet<PeerId>> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Command::GetProviders { entry, sender })
            .await
            .expect("Command receiver not to be dropped.");
        let providers = receiver.await?;
        Ok(providers)
    }

    /// Gets the providers for the given bill via the event loop
    pub async fn get_bill_providers(&mut self, bill_id: &str) -> Result<HashSet<PeerId>> {
        let entry = self.bill_key(bill_id);
        let providers = self.get_providers(entry).await?;
        Ok(providers)
    }

    /// Gets the providers for the given company via the event loop
    pub async fn get_company_providers(&mut self, company_id: &str) -> Result<HashSet<PeerId>> {
        let entry = self.company_key(company_id);
        let providers = self.get_providers(entry).await?;
        Ok(providers)
    }

    /// Request the given file via the event loop
    async fn request_file(&mut self, peer: PeerId, file_name: String) -> Result<Vec<u8>> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Command::RequestFile {
                file_name,
                peer,
                sender,
            })
            .await?;
        let res = receiver.await?;
        res.map_err(|e| super::Error::RequestFile(e.to_string()))
    }

    /// Respond with the given file via the event loop
    async fn respond_file(
        &mut self,
        file: Vec<u8>,
        channel: ResponseChannel<FileResponse>,
    ) -> Result<()> {
        self.sender
            .send(Command::RespondFile { file, channel })
            .await?;
        Ok(())
    }

    // -----------------------------------------------------
    // Event Handling --------------------------------------
    // -----------------------------------------------------

    // We check if the node id is part of the signatories, and if so, send the
    // company data
    async fn handle_company_data_file_request(
        &mut self,
        company_id: &str,
        node_id: &str,
    ) -> Result<Vec<u8>> {
        let company = self.company_store.get(company_id).await?;
        if company.signatories.iter().any(|v| v == node_id) {
            let bytes = company_to_bytes(&company)?;
            Ok(bytes)
        } else {
            Err(super::Error::CallerNotSignatoryOfCompany(
                node_id.to_owned(),
                company_id.to_owned(),
            ))
        }
    }

    // We check if the node id is part of the signatories, and if so, send the
    // company keys encrypted with the node's public key
    async fn handle_company_keys_file_request(
        &mut self,
        company_id: &str,
        node_id: &str,
    ) -> Result<Vec<u8>> {
        let company = self.company_store.get(company_id).await?;
        if company.signatories.iter().any(|v| v == node_id) {
            let keys = self.company_store.get_key_pair(company_id).await?;
            let bytes = company_keys_to_bytes(&keys)?;
            let file_encrypted = util::crypto::encrypt_ecies(&bytes, node_id)?;
            Ok(file_encrypted)
        } else {
            Err(super::Error::CallerNotSignatoryOfCompany(
                node_id.to_owned(),
                company_id.to_owned(),
            ))
        }
    }

    // We check if the node id is part of the signatories, and if so, send the
    // company chain encrypted with the node's public key
    async fn handle_company_chain_file_request(
        &mut self,
        company_id: &str,
        node_id: &str,
    ) -> Result<Vec<u8>> {
        let company = self.company_store.get(company_id).await?;
        if company.signatories.iter().any(|v| v == node_id) {
            let chain = self.company_blockchain_store.get_chain(company_id).await?;
            let bytes = company_chain_to_bytes(&chain)?;
            let file_encrypted = util::crypto::encrypt_ecies(&bytes, node_id)?;
            Ok(file_encrypted)
        } else {
            Err(super::Error::CallerNotSignatoryOfCompany(
                node_id.to_owned(),
                company_id.to_owned(),
            ))
        }
    }

    // We check if the node id is part of the signatories, and if so,
    // open the logo file, if there is one, decrypt it and send the
    // given file, encrypted with the node's public key
    async fn handle_company_logo_file_request(
        &mut self,
        company_id: &str,
        node_id: &str,
        file_name: &str,
    ) -> Result<Vec<u8>> {
        let company = self.company_store.get(company_id).await?;
        if company.signatories.iter().any(|v| v == node_id) {
            if let Some(logo) = company.logo_file {
                if logo.name == *file_name {
                    let bytes = self
                        .handle_company_file_request_for_file(company_id, node_id, file_name)
                        .await?;
                    Ok(bytes)
                } else {
                    Err(super::Error::NoFileForCompanyFound(
                        file_name.to_owned(),
                        company_id.to_owned(),
                    ))
                }
            } else {
                Err(super::Error::NoFileForCompanyFound(
                    file_name.to_owned(),
                    company_id.to_owned(),
                ))
            }
        } else {
            Err(super::Error::CallerNotSignatoryOfCompany(
                node_id.to_owned(),
                company_id.to_owned(),
            ))
        }
    }

    // We check if the node id is part of the signatories, and if so,
    // open the logo file, if there is one, decrypt it and send the
    // given file, encrypted with the node's public key
    async fn handle_company_proof_file_request(
        &mut self,
        company_id: &str,
        node_id: &str,
        file_name: &str,
    ) -> Result<Vec<u8>> {
        let company = self.company_store.get(company_id).await?;
        if company.signatories.iter().any(|v| v == node_id) {
            if let Some(proof) = company.proof_of_registration_file {
                if proof.name == *file_name {
                    let bytes = self
                        .handle_company_file_request_for_file(company_id, node_id, file_name)
                        .await?;
                    Ok(bytes)
                } else {
                    Err(super::Error::NoFileForCompanyFound(
                        file_name.to_owned(),
                        company_id.to_owned(),
                    ))
                }
            } else {
                Err(super::Error::NoFileForCompanyFound(
                    file_name.to_owned(),
                    company_id.to_owned(),
                ))
            }
        } else {
            Err(super::Error::CallerNotSignatoryOfCompany(
                node_id.to_owned(),
                company_id.to_owned(),
            ))
        }
    }

    async fn handle_company_file_request_for_file(
        &mut self,
        company_id: &str,
        node_id: &str,
        file_name: &str,
    ) -> Result<Vec<u8>> {
        let bytes = self
            .file_upload_store
            .open_attached_file(company_id, file_name)
            .await?;
        let identity_private_key = self
            .identity_store
            .get_key_pair()
            .await?
            .get_private_key_string();
        let decrypted_bytes = util::crypto::decrypt_ecies(&bytes, &identity_private_key)?;
        let file_encrypted = util::crypto::encrypt_ecies(&decrypted_bytes, node_id)?;
        Ok(file_encrypted)
    }

    async fn handle_bill_file_request(&mut self, bill_id: &str) -> Result<Vec<u8>> {
        let local_chain = self.bill_blockchain_store.get_chain(bill_id).await?;
        let bytes = bill_chain_to_bytes(&local_chain)?;
        Ok(bytes)
    }

    async fn handle_bill_file_request_for_keys(
        &mut self,
        bill_id: &str,
        node_id: &str,
    ) -> Result<Vec<u8>> {
        let _chain = self.bill_blockchain_store.get_chain(bill_id).await?;
        let bill_keys = self.bill_store.get_keys(bill_id).await?;
        // TODO: RE-ADD this check later
        // if chain
        //     .get_all_nodes_from_bill(&bill_keys)?
        //     .iter()
        //     .any(|n| n == node_id)
        // {
        let bytes = bill_keys_to_bytes(&bill_keys)?;
        let file_encrypted = util::crypto::encrypt_ecies(&bytes, node_id)?;
        Ok(file_encrypted)
        // } else {
        //     Err(super::Error::CallerNotPartOfBill(
        //         node_id.to_owned(),
        //         bill_id.to_string(),
        //     ))
        // }
    }

    async fn handle_bill_file_request_for_attachment(
        &mut self,
        bill_id: &str,
        node_id: &str,
        file_name: &str,
    ) -> Result<Vec<u8>> {
        let _chain = self.bill_blockchain_store.get_chain(bill_id).await?;
        let _bill_keys = self.bill_store.get_keys(bill_id).await?;
        // TODO: RE-ADD this check later
        // if chain
        //     .get_all_nodes_from_bill(&bill_keys)?
        //     .iter()
        //     .any(|n| n == node_id)
        // {
        let file = self
            .file_upload_store
            .open_attached_file(bill_id, file_name)
            .await?;
        let file_encrypted = util::crypto::encrypt_ecies(&file, node_id)?;
        Ok(file_encrypted)
        // } else {
        //     Err(super::Error::CallerNotPartOfBill(
        //         node_id.to_owned(),
        //         bill_id.to_string(),
        //     ))
        // }
    }

    // -------------------------------------------------------------
    // Request handling code ---------------------------------------
    // -------------------------------------------------------------
    /// Handles incoming requests
    async fn handle_event(&mut self, event: Event) -> Result<()> {
        match event {
            Event::CompanyUpdate {
                event,
                company_id,
                signatory,
            } => {
                match event {
                    CompanyEvent::AddSignatory => {
                        info!("Handling AddSignatory event for {company_id} and {signatory}");
                        // add the signatory that we get from the DHT
                        if let Ok(mut company) = self.company_store.get(&company_id).await {
                            company.signatories.push(signatory.clone());
                            if let Err(e) = self.company_store.update(&company_id, &company).await {
                                error!(
                                    "Could not remove signatory {signatory} from {company_id}: {e}"
                                );
                            }
                        }
                        if let Ok(identity) = self.identity_store.get().await {
                            // If we are added, start providing and subscribe
                            if signatory == identity.node_id {
                                info!("Got from DHT, that we were added to company {company_id} - refreshing data from the network");
                                if let Err(e) = self
                                    .get_company_data_from_the_network(
                                        &company_id,
                                        &identity.node_id,
                                    )
                                    .await
                                {
                                    error!("Could not remove local company {company_id}: {e}");
                                }
                                if let Err(e) = self.start_providing_company(&company_id).await {
                                    error!("Could not start providing company {company_id}: {e}");
                                }
                                if let Err(e) = self.subscribe_to_company_topic(&company_id).await {
                                    error!(
                                        "Could not start subscribing to company {company_id}: {e}"
                                    );
                                }
                            }
                        }
                    }
                    CompanyEvent::RemoveSignatory => {
                        info!("Handling RemoveSignatory event for {company_id} and {signatory}");
                        // remove the signatory that we get from the DHT
                        if let Ok(mut company) = self.company_store.get(&company_id).await {
                            company.signatories.retain(|i| i != &signatory);
                            if let Err(e) = self.company_store.update(&company_id, &company).await {
                                error!(
                                    "Could not remove signatory {signatory} from {company_id}: {e}"
                                );
                            }
                        }
                        if let Ok(identity) = self.identity_store.get().await {
                            // If we are removed, remove the local company
                            if signatory == identity.node_id {
                                info!("Got from DHT, that we were removed from company {company_id} - deleting company locally");

                                let _ = self
                                    .file_upload_store
                                    .delete_attached_files(&company_id)
                                    .await;
                                if let Err(e) = self.company_store.remove(&company_id).await {
                                    error!("Could not remove local company {company_id}: {e}");
                                }
                                if let Err(e) =
                                    self.company_blockchain_store.remove(&company_id).await
                                {
                                    error!(
                                        "Could not remove local company chain {company_id}: {e}"
                                    );
                                }
                                if let Err(e) = self.stop_providing_company(&company_id).await {
                                    error!("Could not stop providing company {company_id}: {e}");
                                }
                                if let Err(e) =
                                    self.unsubscribe_from_company_topic(&company_id).await
                                {
                                    error!(
                                        "Could not stop subscribing to company {company_id}: {e}"
                                    );
                                }
                            }
                        }
                    }
                }
            }
            Event::InboundRequest {
                request,
                channel,
                peer,
            } => {
                match parse_inbound_file_request(&request, &peer) {
                    Err(e) => {
                        error!("Could not handle inbound request {request}: {e}")
                    }
                    Ok(parsed) => {
                        match parsed {
                            ParsedInboundFileRequest::CompanyData(CompanyDataRequest {
                                company_id,
                                node_id,
                            }) => {
                                let bytes = self
                                    .handle_company_data_file_request(&company_id, &node_id)
                                    .await?;
                                self.respond_file(bytes, channel).await?;
                            }
                            ParsedInboundFileRequest::CompanyKeys(CompanyKeysRequest {
                                node_id,
                                company_id,
                            }) => {
                                let bytes = self
                                    .handle_company_keys_file_request(&company_id, &node_id)
                                    .await?;
                                self.respond_file(bytes, channel).await?;
                            }
                            ParsedInboundFileRequest::CompanyChain(CompanyChainRequest {
                                node_id,
                                company_id,
                            }) => {
                                let bytes = self
                                    .handle_company_chain_file_request(&company_id, &node_id)
                                    .await?;
                                self.respond_file(bytes, channel).await?;
                            }
                            ParsedInboundFileRequest::CompanyLogo(CompanyLogoRequest {
                                node_id,
                                company_id,
                                file_name,
                            }) => {
                                let bytes = self
                                    .handle_company_logo_file_request(
                                        &company_id,
                                        &node_id,
                                        &file_name,
                                    )
                                    .await?;
                                self.respond_file(bytes, channel).await?;
                            }
                            ParsedInboundFileRequest::CompanyProof(CompanyProofRequest {
                                node_id,
                                company_id,
                                file_name,
                            }) => {
                                let bytes = self
                                    .handle_company_proof_file_request(
                                        &company_id,
                                        &node_id,
                                        &file_name,
                                    )
                                    .await?;
                                self.respond_file(bytes, channel).await?;
                            }
                            // We can send the bill to anyone requesting it, since the content is encrypted
                            // and is useless without the keys
                            ParsedInboundFileRequest::Bill(BillFileRequest { bill_id }) => {
                                let bytes = self.handle_bill_file_request(&bill_id).await?;
                                self.respond_file(bytes, channel).await?;
                            }
                            // We check if the requester is part of the bill and if so, we get their
                            // identity from DHT and encrypt the file with their public key
                            ParsedInboundFileRequest::BillKeys(BillKeysFileRequest {
                                node_id,
                                bill_id,
                            }) => {
                                let bytes = self
                                    .handle_bill_file_request_for_keys(&bill_id, &node_id)
                                    .await?;
                                self.respond_file(bytes, channel).await?;
                            }
                            // We only send attachments (encrypted with the bill public key) to participants of the bill, encrypted with their public key
                            ParsedInboundFileRequest::BillAttachment(
                                BillAttachmentFileRequest {
                                    node_id,
                                    bill_id,
                                    file_name,
                                },
                            ) => {
                                let bytes = self
                                    .handle_bill_file_request_for_attachment(
                                        &bill_id, &node_id, &file_name,
                                    )
                                    .await?;
                                self.respond_file(bytes, channel).await?;
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        constants::{
            BILL_ATTACHMENT_PREFIX, COMPANY_CHAIN_PREFIX, COMPANY_KEY_PREFIX, COMPANY_LOGO_PREFIX,
            COMPANY_PROOF_PREFIX, KEY_PREFIX,
        },
        persistence::{
            bill::{MockBillChainStoreApi, MockBillStoreApi},
            company::{MockCompanyChainStoreApi, MockCompanyStoreApi},
            file_upload::MockFileUploadStoreApi,
            identity::MockIdentityStoreApi,
        },
        service::{
            bill_service::tests::{get_baseline_bill, get_genesis_chain},
            company_service::CompanyToReturn,
            identity_service::Identity,
        },
        tests::tests::{TEST_NODE_ID_SECP, TEST_PRIVATE_KEY_SECP, TEST_PUB_KEY_SECP},
        web::data::{File, PostalAddress},
    };
    use blockchain::company::CompanyCreateBlockData;
    use futures::channel::mpsc::{self, Sender};
    use libp2p::kad::record::{Key, Record};
    use std::collections::{HashMap, HashSet};
    use util::BcrKeys;

    fn get_baseline_company_data(id: &str) -> (String, (Company, CompanyKeys)) {
        (
            id.to_string(),
            (
                Company {
                    id: id.to_string(),
                    name: "some_name".to_string(),
                    country_of_registration: "AT".to_string(),
                    city_of_registration: "Vienna".to_string(),
                    postal_address: PostalAddress::new_empty(),
                    email: "company@example.com".to_string(),
                    registration_number: "some_number".to_string(),
                    registration_date: "2012-01-01".to_string(),
                    proof_of_registration_file: None,
                    logo_file: None,
                    signatories: vec![],
                },
                CompanyKeys {
                    private_key: TEST_PRIVATE_KEY_SECP.to_string(),
                    public_key: TEST_PUB_KEY_SECP.to_string(),
                },
            ),
        )
    }

    fn get_client() -> Client {
        let (sender, _) = mpsc::channel(0);
        Client::new(
            sender,
            Arc::new(MockBillStoreApi::new()),
            Arc::new(MockBillChainStoreApi::new()),
            Arc::new(MockCompanyStoreApi::new()),
            Arc::new(MockCompanyChainStoreApi::new()),
            Arc::new(MockIdentityStoreApi::new()),
            Arc::new(MockFileUploadStoreApi::new()),
        )
    }

    fn get_client_chan(sender: Sender<Command>) -> Client {
        Client::new(
            sender,
            Arc::new(MockBillStoreApi::new()),
            Arc::new(MockBillChainStoreApi::new()),
            Arc::new(MockCompanyStoreApi::new()),
            Arc::new(MockCompanyChainStoreApi::new()),
            Arc::new(MockIdentityStoreApi::new()),
            Arc::new(MockFileUploadStoreApi::new()),
        )
    }

    fn get_client_chan_stores(
        mock_bill_storage: MockBillStoreApi,
        mock_bill_blockchain_storage: MockBillChainStoreApi,
        mock_company_storage: MockCompanyStoreApi,
        mock_company_blockchain_storage: MockCompanyChainStoreApi,
        mock_identity_storage: MockIdentityStoreApi,
        mock_file_upload_storage: MockFileUploadStoreApi,
        sender: Sender<Command>,
    ) -> Client {
        Client::new(
            sender,
            Arc::new(mock_bill_storage),
            Arc::new(mock_bill_blockchain_storage),
            Arc::new(mock_company_storage),
            Arc::new(mock_company_blockchain_storage),
            Arc::new(mock_identity_storage),
            Arc::new(mock_file_upload_storage),
        )
    }

    fn get_storages() -> (
        MockBillStoreApi,
        MockBillChainStoreApi,
        MockCompanyStoreApi,
        MockCompanyChainStoreApi,
        MockIdentityStoreApi,
        MockFileUploadStoreApi,
    ) {
        (
            MockBillStoreApi::new(),
            MockBillChainStoreApi::new(),
            MockCompanyStoreApi::new(),
            MockCompanyChainStoreApi::new(),
            MockIdentityStoreApi::new(),
            MockFileUploadStoreApi::new(),
        )
    }

    fn get_valid_company_chain(company_id: &str) -> CompanyBlockchain {
        let (id, (company, company_keys)) = get_baseline_company_data(company_id);
        let to_return = CompanyToReturn::from(id, company);

        CompanyBlockchain::new(
            &CompanyCreateBlockData::from(to_return),
            &BcrKeys::new(),
            &company_keys,
            1731593928,
        )
        .unwrap()
    }

    #[test]
    fn company_key() {
        assert_eq!(get_client().company_key("id"), "COMPANYid".to_string());
    }

    #[test]
    fn bill_key() {
        assert_eq!(get_client().bill_key("id"), "BILLid".to_string());
    }

    #[test]
    fn node_request_for_companies() {
        assert_eq!(
            get_client().node_request_for_companies("nodeid"),
            "COMPANIESnodeid".to_string()
        );
    }

    #[test]
    fn node_request_for_bills() {
        assert_eq!(
            get_client().node_request_for_bills("nodeid"),
            "BILLSnodeid".to_string()
        );
    }

    #[tokio::test]
    async fn get_company_providers() {
        let (sender, mut receiver) = mpsc::channel(10);

        tokio::spawn(async move {
            if let Some(Command::GetProviders { entry, sender }) = receiver.next().await {
                assert_eq!(entry, "COMPANYcompany_id".to_string());

                let mut res = HashSet::new();
                res.insert(PeerId::random());
                sender.send(res).unwrap();
            } else {
                panic!("No command received");
            }
        });
        let result = get_client_chan(sender)
            .get_company_providers("company_id")
            .await
            .unwrap();
        assert!(result.len() == 1);
    }

    #[tokio::test]
    async fn get_bill_providers() {
        let (sender, mut receiver) = mpsc::channel(10);

        tokio::spawn(async move {
            if let Some(Command::GetProviders { entry, sender }) = receiver.next().await {
                assert_eq!(entry, "BILLbill_id".to_string());

                let mut res = HashSet::new();
                res.insert(PeerId::random());
                sender.send(res).unwrap();
            } else {
                panic!("No command received");
            }
        });
        let result = get_client_chan(sender)
            .get_bill_providers("bill_id")
            .await
            .unwrap();
        assert!(result.len() == 1);
    }

    #[tokio::test]
    async fn start_providing_bill() {
        let (sender, mut receiver) = mpsc::channel(10);

        tokio::spawn(async move {
            if let Some(Command::StartProviding { entry, sender }) = receiver.next().await {
                assert_eq!(entry, "BILLbill_id".to_string());
                sender.send(()).unwrap();
            } else {
                panic!("No command received");
            }
        });
        let result = get_client_chan(sender)
            .start_providing_bill("bill_id")
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn start_providing_company() {
        let (sender, mut receiver) = mpsc::channel(10);

        tokio::spawn(async move {
            if let Some(Command::StartProviding { entry, sender }) = receiver.next().await {
                assert_eq!(entry, "COMPANYcompany_id".to_string());
                sender.send(()).unwrap();
            } else {
                panic!("No command received");
            }
        });
        let result = get_client_chan(sender)
            .start_providing_company("company_id")
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn stop_providing_company() {
        let (sender, mut receiver) = mpsc::channel(10);

        tokio::spawn(async move {
            if let Some(Command::StopProviding { entry }) = receiver.next().await {
                assert_eq!(entry, "COMPANYcompany_id".to_string());
            } else {
                panic!("No command received");
            }
        });
        let result = get_client_chan(sender)
            .stop_providing_company("company_id")
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn get_record() {
        let (sender, mut receiver) = mpsc::channel(10);

        tokio::spawn(async move {
            if let Some(Command::GetRecord { key, sender }) = receiver.next().await {
                assert_eq!(key, "key".to_string());
                sender
                    .send(Ok(Record::new(Key::new(&"key".to_string()), vec![])))
                    .unwrap();
            } else {
                panic!("No command received");
            }
        });
        let result = get_client_chan(sender).get_record("key".to_string()).await;
        assert!(result.is_ok());
        assert!(result.unwrap().value.is_empty());
    }

    #[tokio::test]
    async fn put_record() {
        let (sender, mut receiver) = mpsc::channel(10);

        tokio::spawn(async move {
            if let Some(Command::PutRecord { key, value }) = receiver.next().await {
                assert_eq!(key, "key".to_string());
                assert!(value.is_empty());
            } else {
                panic!("No command received");
            }
        });
        let result = get_client_chan(sender)
            .put_record("key".to_string(), vec![])
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn subscribe_to_bill_topic() {
        let (sender, mut receiver) = mpsc::channel(10);
        let result = get_client_chan(sender)
            .subscribe_to_bill_topic("bill_id")
            .await;
        assert!(result.is_ok());
        match receiver.next().await.unwrap() {
            Command::SubscribeToTopic { topic } => {
                assert_eq!(topic, "BILLbill_id".to_string());
            }
            _ => panic!("got wrong command"),
        };
    }

    #[tokio::test]
    async fn subscribe_to_company_topic() {
        let (sender, mut receiver) = mpsc::channel(10);
        let result = get_client_chan(sender)
            .subscribe_to_company_topic("company_id")
            .await;
        assert!(result.is_ok());
        match receiver.next().await.unwrap() {
            Command::SubscribeToTopic { topic } => {
                assert_eq!(topic, "COMPANYcompany_id".to_string());
            }
            _ => panic!("got wrong command"),
        };
    }

    #[tokio::test]
    async fn unsubscribe_from_company_topic() {
        let (sender, mut receiver) = mpsc::channel(10);
        let result = get_client_chan(sender)
            .unsubscribe_from_company_topic("company_id")
            .await;
        assert!(result.is_ok());
        match receiver.next().await.unwrap() {
            Command::UnsubscribeFromTopic { topic } => {
                assert_eq!(topic, "COMPANYcompany_id".to_string());
            }
            _ => panic!("got wrong command"),
        };
    }

    #[tokio::test]
    async fn add_message_to_bill_topic() {
        let (sender, mut receiver) = mpsc::channel(10);
        let result = get_client_chan(sender)
            .add_message_to_bill_topic(vec![], "bill_id")
            .await;
        assert!(result.is_ok());
        match receiver.next().await.unwrap() {
            Command::SendMessage { msg, topic } => {
                assert_eq!(topic, "BILLbill_id".to_string());
                assert!(msg.is_empty());
            }
            _ => panic!("got wrong command"),
        };
    }

    #[tokio::test]
    async fn add_message_to_company_topic() {
        let (sender, mut receiver) = mpsc::channel(10);
        let result = get_client_chan(sender)
            .add_message_to_company_topic(vec![], "company_id")
            .await;
        assert!(result.is_ok());
        match receiver.next().await.unwrap() {
            Command::SendMessage { msg, topic } => {
                assert_eq!(topic, "COMPANYcompany_id".to_string());
                assert!(msg.is_empty());
            }
            _ => panic!("got wrong command"),
        };
    }

    #[tokio::test]
    async fn subscribe_to_all_companies_topics() {
        let (sender, receiver) = mpsc::channel(10);
        let (
            bill_store,
            bill_chain_store,
            mut company_store,
            company_blockchain_store,
            identity_store,
            file_upload_store,
        ) = get_storages();
        company_store.expect_get_all().returning(|| {
            let mut map = HashMap::new();
            let company_1 = get_baseline_company_data("company_1");
            let company_2 = get_baseline_company_data("company_2");
            map.insert(String::from("company_1"), (company_1.1 .0, company_1.1 .1));
            map.insert(String::from("company_2"), (company_2.1 .0, company_2.1 .1));
            Ok(map)
        });
        let result = get_client_chan_stores(
            bill_store,
            bill_chain_store,
            company_store,
            company_blockchain_store,
            identity_store,
            file_upload_store,
            sender,
        )
        .subscribe_to_all_companies_topics()
        .await;
        assert!(result.is_ok());
        assert_eq!(receiver.count().await, 2);
    }

    #[tokio::test]
    async fn start_providing_companies_does_nothing_if_no_companies() {
        let (sender, _receiver) = mpsc::channel(10);
        let (
            bill_store,
            bill_chain_store,
            mut company_store,
            company_blockchain_store,
            identity_store,
            file_upload_store,
        ) = get_storages();
        company_store
            .expect_get_all()
            .returning(|| Ok(HashMap::new()));
        let result = get_client_chan_stores(
            bill_store,
            bill_chain_store,
            company_store,
            company_blockchain_store,
            identity_store,
            file_upload_store,
            sender,
        )
        .start_providing_companies()
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn start_providing_companies_calls_start_provide_for_each_company() {
        let (sender, mut receiver) = mpsc::channel(10);
        let (
            bill_store,
            bill_chain_store,
            mut company_store,
            company_blockchain_store,
            identity_store,
            file_upload_store,
        ) = get_storages();
        company_store.expect_get_all().returning(|| {
            let mut map = HashMap::new();
            let company_1 = get_baseline_company_data("company_1");
            let company_2 = get_baseline_company_data("company_2");
            map.insert(String::from("company_1"), (company_1.1 .0, company_1.1 .1));
            map.insert(String::from("company_2"), (company_2.1 .0, company_2.1 .1));
            Ok(map)
        });

        tokio::spawn(async move {
            let mut count = 0;
            while let Some(Command::StartProviding { entry: _, sender }) = receiver.next().await {
                sender.send(()).unwrap();
                count += 1;
            }
            assert!(count == 2);
        });

        let result = get_client_chan_stores(
            bill_store,
            bill_chain_store,
            company_store,
            company_blockchain_store,
            identity_store,
            file_upload_store,
            sender,
        )
        .start_providing_companies()
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn put_companies_for_signatories() {
        let (sender, mut receiver) = mpsc::channel(10);
        let (
            bill_store,
            bill_chain_store,
            mut company_store,
            company_blockchain_store,
            identity_store,
            file_upload_store,
        ) = get_storages();
        company_store.expect_get_all().returning(|| {
            let mut map = HashMap::new();
            let mut company_1 = get_baseline_company_data("company_1");
            company_1.1 .0.signatories.push("signatory_1".to_string());
            map.insert(String::from("company_1"), (company_1.1 .0, company_1.1 .1));
            Ok(map)
        });

        tokio::spawn(async move {
            while let Some(event) = receiver.next().await {
                match event {
                    Command::PutRecord { key, value } => {
                        assert_eq!(key, "COMPANIESsignatory_1".to_string());
                        let parsed: Vec<String> = from_slice(&value).unwrap();
                        assert!(parsed.contains(&String::from("company_1")));
                        assert!(parsed.contains(&String::from("company_2")));
                        assert!(parsed.len() == 2);
                    }
                    Command::GetRecord { key, sender } => {
                        assert_eq!(key, "COMPANIESsignatory_1".to_string());
                        sender
                            .send(Ok(Record::new(
                                Key::new(&"COMPANIESsignatory_1".to_string()),
                                to_vec(&vec!["company_2".to_string()]).unwrap(),
                            )))
                            .unwrap();
                    }
                    _ => panic!("wrong event"),
                }
            }
        });

        let result = get_client_chan_stores(
            bill_store,
            bill_chain_store,
            company_store,
            company_blockchain_store,
            identity_store,
            file_upload_store,
            sender,
        )
        .put_companies_for_signatories()
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn add_companies_to_dht_for_node() {
        let (sender, mut receiver) = mpsc::channel(10);

        tokio::spawn(async move {
            while let Some(event) = receiver.next().await {
                match event {
                    Command::PutRecord { key, value } => {
                        assert_eq!(key, "COMPANIESmy_node_id".to_string());
                        let parsed: Vec<String> = from_slice(&value).unwrap();
                        assert!(parsed.contains(&String::from("company_1")));
                        assert!(parsed.contains(&String::from("company_2")));
                        assert!(parsed.len() == 2);
                    }
                    Command::GetRecord { key, sender } => {
                        assert_eq!(key, "COMPANIESmy_node_id".to_string());
                        sender
                            .send(Ok(Record::new(
                                Key::new(&"COMPANIESmy_node_id".to_string()),
                                to_vec(&vec!["company_1".to_string()]).unwrap(),
                            )))
                            .unwrap();
                    }
                    _ => panic!("wrong event"),
                }
            }
        });

        let result = get_client_chan(sender)
            .add_companies_to_dht_for_node(
                vec![String::from("company_1"), String::from("company_2")],
                "my_node_id",
            )
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn add_companies_to_dht_for_node_does_nothing_on_empty_list() {
        let result = get_client()
            .add_companies_to_dht_for_node(vec![], "my_node_id")
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn add_companies_to_dht_for_node_puts_given_ids_if_result_from_dht_empty() {
        let (sender, mut receiver) = mpsc::channel(10);

        tokio::spawn(async move {
            while let Some(event) = receiver.next().await {
                match event {
                    Command::PutRecord { key, value } => {
                        assert_eq!(key, "COMPANIESmy_node_id".to_string());
                        let parsed: Vec<String> = from_slice(&value).unwrap();
                        assert!(parsed.contains(&String::from("company_1")));
                        assert!(parsed.contains(&String::from("company_2")));
                        assert!(parsed.len() == 2);
                    }
                    Command::GetRecord { key, sender } => {
                        assert_eq!(key, "COMPANIESmy_node_id".to_string());
                        let result: Vec<String> = vec![];
                        sender
                            .send(Ok(Record::new(
                                Key::new(&"COMPANIESmy_node_id".to_string()),
                                to_vec(&result).unwrap(),
                            )))
                            .unwrap();
                    }
                    _ => panic!("wrong event"),
                }
            }
        });

        let result = get_client_chan(sender)
            .add_companies_to_dht_for_node(
                vec![String::from("company_1"), String::from("company_2")],
                "my_node_id",
            )
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn add_companies_to_dht_for_node_puts_given_ids_if_result_from_dht_is_invalid() {
        let (sender, mut receiver) = mpsc::channel(10);

        tokio::spawn(async move {
            while let Some(event) = receiver.next().await {
                match event {
                    Command::PutRecord { key, value } => {
                        assert_eq!(key, "COMPANIESmy_node_id".to_string());
                        let parsed: Vec<String> = from_slice(&value).unwrap();
                        assert!(parsed.contains(&String::from("company_1")));
                        assert!(parsed.contains(&String::from("company_2")));
                        assert!(parsed.len() == 2);
                    }
                    Command::GetRecord { key, sender } => {
                        assert_eq!(key, "COMPANIESmy_node_id".to_string());
                        let result: String = String::from("hello world"); // this is invalid, since
                                                                          // we expect a vec
                        sender
                            .send(Ok(Record::new(
                                Key::new(&"COMPANIESmy_node_id".to_string()),
                                to_vec(&result).unwrap(),
                            )))
                            .unwrap();
                    }
                    _ => panic!("wrong event"),
                }
            }
        });

        let result = get_client_chan(sender)
            .add_companies_to_dht_for_node(
                vec![String::from("company_1"), String::from("company_2")],
                "my_node_id",
            )
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn remove_company_from_dht_for_node() {
        let (sender, mut receiver) = mpsc::channel(10);

        tokio::spawn(async move {
            while let Some(event) = receiver.next().await {
                match event {
                    Command::PutRecord { key, value } => {
                        assert_eq!(key, "COMPANIESmy_node_id".to_string());
                        let parsed: Vec<String> = from_slice(&value).unwrap();
                        assert!(parsed.contains(&String::from("company_1")));
                        assert!(parsed.len() == 1);
                    }
                    Command::GetRecord { key, sender } => {
                        assert_eq!(key, "COMPANIESmy_node_id".to_string());
                        sender
                            .send(Ok(Record::new(
                                Key::new(&"COMPANIESmy_node_id".to_string()),
                                to_vec(&vec!["company_1".to_string(), "company_2".to_string()])
                                    .unwrap(),
                            )))
                            .unwrap();
                    }
                    _ => panic!("wrong event"),
                }
            }
        });

        let result = get_client_chan(sender)
            .remove_company_from_dht_for_node("company_2", "my_node_id")
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn add_company_to_dht_for_node() {
        let (sender, mut receiver) = mpsc::channel(10);

        tokio::spawn(async move {
            while let Some(event) = receiver.next().await {
                match event {
                    Command::PutRecord { key, value } => {
                        assert_eq!(key, "COMPANIESmy_node_id".to_string());
                        let parsed: Vec<String> = from_slice(&value).unwrap();
                        assert!(parsed.contains(&String::from("company_1")));
                        assert!(parsed.contains(&String::from("company_2")));
                        assert!(parsed.len() == 2);
                    }
                    Command::GetRecord { key, sender } => {
                        assert_eq!(key, "COMPANIESmy_node_id".to_string());
                        sender
                            .send(Ok(Record::new(
                                Key::new(&"COMPANIESmy_node_id".to_string()),
                                to_vec(&vec!["company_2".to_string()]).unwrap(),
                            )))
                            .unwrap();
                    }
                    _ => panic!("wrong event"),
                }
            }
        });

        let result = get_client_chan(sender)
            .add_company_to_dht_for_node("company_1", "my_node_id")
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn add_company_to_dht_for_node_puts_given_id_if_result_from_dht_is_invalid() {
        let (sender, mut receiver) = mpsc::channel(10);

        tokio::spawn(async move {
            while let Some(event) = receiver.next().await {
                match event {
                    Command::PutRecord { key, value } => {
                        assert_eq!(key, "COMPANIESmy_node_id".to_string());
                        let parsed: Vec<String> = from_slice(&value).unwrap();
                        assert!(parsed.contains(&String::from("company_1")));
                        assert!(parsed.len() == 1);
                    }
                    Command::GetRecord { key, sender } => {
                        assert_eq!(key, "COMPANIESmy_node_id".to_string());
                        let result: String = String::from("hello world"); // this is invalid, since
                                                                          // we expect a vec
                        sender
                            .send(Ok(Record::new(
                                Key::new(&"COMPANIESmy_node_id".to_string()),
                                to_vec(&result).unwrap(),
                            )))
                            .unwrap();
                    }
                    _ => panic!("wrong event"),
                }
            }
        });

        let result = get_client_chan(sender)
            .add_company_to_dht_for_node("company_1", "my_node_id")
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn add_company_to_dht_for_node_puts_given_id_if_result_from_dht_is_empty() {
        let (sender, mut receiver) = mpsc::channel(10);

        tokio::spawn(async move {
            while let Some(event) = receiver.next().await {
                match event {
                    Command::PutRecord { key, value } => {
                        assert_eq!(key, "COMPANIESmy_node_id".to_string());
                        let parsed: Vec<String> = from_slice(&value).unwrap();
                        assert!(parsed.contains(&String::from("company_1")));
                        assert!(parsed.len() == 1);
                    }
                    Command::GetRecord { key, sender } => {
                        assert_eq!(key, "COMPANIESmy_node_id".to_string());
                        let result: Vec<String> = vec![];
                        sender
                            .send(Ok(Record::new(
                                Key::new(&"COMPANIESmy_node_id".to_string()),
                                to_vec(&result).unwrap(),
                            )))
                            .unwrap();
                    }
                    _ => panic!("wrong event"),
                }
            }
        });

        let result = get_client_chan(sender)
            .add_company_to_dht_for_node("company_1", "my_node_id")
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn handle_company_data_file_request() {
        let (sender, _receiver) = mpsc::channel(10);
        let (
            bill_store,
            bill_chain_store,
            mut company_store,
            company_blockchain_store,
            identity_store,
            file_upload_store,
        ) = get_storages();
        let mut company = get_baseline_company_data("some_id").1 .0;
        company.signatories.push("some_node_id".to_string());
        let company_clone = company.clone();
        company_store
            .expect_get()
            .returning(move |_| Ok(company_clone.clone()));

        let result = get_client_chan_stores(
            bill_store,
            bill_chain_store,
            company_store,
            company_blockchain_store,
            identity_store,
            file_upload_store,
            sender,
        )
        .handle_company_data_file_request("some_id", "some_node_id")
        .await;
        assert!(result.is_ok());
        assert_eq!(
            result.as_ref().unwrap().len(),
            company_to_bytes(&company).unwrap().len()
        );
    }

    #[tokio::test]
    async fn handle_company_data_file_request_not_if_not_signatory() {
        let (sender, _receiver) = mpsc::channel(10);
        let (
            bill_store,
            bill_chain_store,
            mut company_store,
            company_blockchain_store,
            identity_store,
            file_upload_store,
        ) = get_storages();
        let mut company = get_baseline_company_data("some_id").1 .0;
        company.signatories.push("some_other_node_id".to_string());
        let company_clone = company.clone();
        company_store
            .expect_get()
            .returning(move |_| Ok(company_clone.clone()));

        let result = get_client_chan_stores(
            bill_store,
            bill_chain_store,
            company_store,
            company_blockchain_store,
            identity_store,
            file_upload_store,
            sender,
        )
        .handle_company_data_file_request("some_id", "some_node_id")
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handle_company_keys_file_request() {
        let (sender, _receiver) = mpsc::channel(10);
        let (
            bill_store,
            bill_chain_store,
            mut company_store,
            company_blockchain_store,
            identity_store,
            file_upload_store,
        ) = get_storages();
        let mut company = get_baseline_company_data("some_id").1 .0;
        company.signatories.push(TEST_NODE_ID_SECP.to_string());
        let company_clone = company.clone();
        company_store
            .expect_get()
            .returning(move |_| Ok(company_clone.clone()));
        company_store.expect_get_key_pair().returning(move |_| {
            Ok(CompanyKeys {
                public_key: TEST_PUB_KEY_SECP.to_string(),
                private_key: TEST_PRIVATE_KEY_SECP.to_string(),
            })
        });

        let result = get_client_chan_stores(
            bill_store,
            bill_chain_store,
            company_store,
            company_blockchain_store,
            identity_store,
            file_upload_store,
            sender,
        )
        .handle_company_keys_file_request("some_id", TEST_NODE_ID_SECP)
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn handle_company_keys_file_request_not_if_not_signatory() {
        let (sender, _receiver) = mpsc::channel(10);
        let (
            bill_store,
            bill_chain_store,
            mut company_store,
            company_blockchain_store,
            identity_store,
            file_upload_store,
        ) = get_storages();
        let mut company = get_baseline_company_data("some_id").1 .0;
        company.signatories.push("some_other_node_id".to_string());
        let company_clone = company.clone();
        company_store
            .expect_get()
            .returning(move |_| Ok(company_clone.clone()));

        let result = get_client_chan_stores(
            bill_store,
            bill_chain_store,
            company_store,
            company_blockchain_store,
            identity_store,
            file_upload_store,
            sender,
        )
        .handle_company_keys_file_request("some_id", "some_node_id")
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handle_company_chain_file_request() {
        let (sender, _receiver) = mpsc::channel(10);
        let (
            bill_store,
            bill_chain_store,
            mut company_store,
            mut company_blockchain_store,
            identity_store,
            file_upload_store,
        ) = get_storages();
        let mut company = get_baseline_company_data("some_id").1 .0;
        company.signatories.push(TEST_NODE_ID_SECP.to_string());
        let company_clone = company.clone();
        company_store
            .expect_get()
            .returning(move |_| Ok(company_clone.clone()));
        company_blockchain_store
            .expect_get_chain()
            .returning(|_| Ok(get_valid_company_chain("some_id")));

        let result = get_client_chan_stores(
            bill_store,
            bill_chain_store,
            company_store,
            company_blockchain_store,
            identity_store,
            file_upload_store,
            sender,
        )
        .handle_company_chain_file_request("some_id", TEST_NODE_ID_SECP)
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn handle_company_chain_file_request_not_if_not_signatory() {
        let (sender, _receiver) = mpsc::channel(10);
        let (
            bill_store,
            bill_chain_store,
            mut company_store,
            company_blockchain_store,
            identity_store,
            file_upload_store,
        ) = get_storages();
        let mut company = get_baseline_company_data("some_id").1 .0;
        company.signatories.push("some_other_node_id".to_string());
        let company_clone = company.clone();
        company_store
            .expect_get()
            .returning(move |_| Ok(company_clone.clone()));

        let result = get_client_chan_stores(
            bill_store,
            bill_chain_store,
            company_store,
            company_blockchain_store,
            identity_store,
            file_upload_store,
            sender,
        )
        .handle_company_chain_file_request("some_id", "some_node_id")
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handle_company_logo_file_request() {
        let (sender, _receiver) = mpsc::channel(10);
        let (
            bill_store,
            bill_chain_store,
            mut company_store,
            company_blockchain_store,
            mut identity_store,
            mut file_upload_store,
        ) = get_storages();
        let mut company = get_baseline_company_data("some_id").1 .0;
        company.logo_file = Some(File {
            name: "file.pdf".to_string(),
            hash: "some_hash".to_string(),
        });
        company.signatories.push(TEST_NODE_ID_SECP.to_owned());
        let company_clone = company.clone();
        company_store
            .expect_get()
            .returning(move |_| Ok(company_clone.clone()));
        file_upload_store
            .expect_open_attached_file()
            .returning(|_, _| {
                Ok(util::crypto::encrypt_ecies("Hello".as_bytes(), TEST_PUB_KEY_SECP).unwrap())
            });
        identity_store
            .expect_get_key_pair()
            .returning(|| Ok(BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap()));

        let result = get_client_chan_stores(
            bill_store,
            bill_chain_store,
            company_store,
            company_blockchain_store,
            identity_store,
            file_upload_store,
            sender,
        )
        .handle_company_logo_file_request("some_id", TEST_NODE_ID_SECP, "file.pdf")
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn handle_company_logo_file_request_not_if_not_signatory() {
        let (sender, _receiver) = mpsc::channel(10);
        let (
            bill_store,
            bill_chain_store,
            mut company_store,
            company_blockchain_store,
            identity_store,
            file_upload_store,
        ) = get_storages();
        let mut company = get_baseline_company_data("some_id").1 .0;
        company.logo_file = Some(File {
            name: "file.pdf".to_string(),
            hash: "some_hash".to_string(),
        });
        company.signatories.push("some_other_node_id".to_string());
        let company_clone = company.clone();
        company_store
            .expect_get()
            .returning(move |_| Ok(company_clone.clone()));

        let result = get_client_chan_stores(
            bill_store,
            bill_chain_store,
            company_store,
            company_blockchain_store,
            identity_store,
            file_upload_store,
            sender,
        )
        .handle_company_logo_file_request("some_id", "some_node_id", "file.pdf")
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handle_company_logo_file_request_not_if_no_file() {
        let (sender, _receiver) = mpsc::channel(10);
        let (
            bill_store,
            bill_chain_store,
            mut company_store,
            company_blockchain_store,
            identity_store,
            file_upload_store,
        ) = get_storages();
        let mut company = get_baseline_company_data("some_id").1 .0;
        company.logo_file = None;
        company.signatories.push("some_node_id".to_string());
        let company_clone = company.clone();
        company_store
            .expect_get()
            .returning(move |_| Ok(company_clone.clone()));

        let result = get_client_chan_stores(
            bill_store,
            bill_chain_store,
            company_store,
            company_blockchain_store,
            identity_store,
            file_upload_store,
            sender,
        )
        .handle_company_logo_file_request("some_id", "some_node_id", "file.pdf")
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handle_company_logo_file_request_not_if_wrong_file() {
        let (sender, _receiver) = mpsc::channel(10);
        let (
            bill_store,
            bill_chain_store,
            mut company_store,
            company_blockchain_store,
            identity_store,
            file_upload_store,
        ) = get_storages();
        let mut company = get_baseline_company_data("some_id").1 .0;
        company.logo_file = Some(File {
            name: "other_file.pdf".to_string(),
            hash: "some_hash".to_string(),
        });
        company.signatories.push("some_node_id".to_string());
        let company_clone = company.clone();
        company_store
            .expect_get()
            .returning(move |_| Ok(company_clone.clone()));

        let result = get_client_chan_stores(
            bill_store,
            bill_chain_store,
            company_store,
            company_blockchain_store,
            identity_store,
            file_upload_store,
            sender,
        )
        .handle_company_logo_file_request("some_id", "some_node_id", "file.pdf")
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handle_company_proof_file_request() {
        let (sender, _receiver) = mpsc::channel(10);
        let (
            bill_store,
            bill_chain_store,
            mut company_store,
            company_blockchain_store,
            mut identity_store,
            mut file_upload_store,
        ) = get_storages();
        let mut company = get_baseline_company_data("some_id").1 .0;
        company.proof_of_registration_file = Some(File {
            name: "file.pdf".to_string(),
            hash: "some_hash".to_string(),
        });
        company.signatories.push(TEST_NODE_ID_SECP.to_owned());
        let company_clone = company.clone();
        company_store
            .expect_get()
            .returning(move |_| Ok(company_clone.clone()));
        file_upload_store
            .expect_open_attached_file()
            .returning(|_, _| {
                Ok(util::crypto::encrypt_ecies("Hello".as_bytes(), TEST_PUB_KEY_SECP).unwrap())
            });
        identity_store
            .expect_get_key_pair()
            .returning(|| Ok(BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap()));

        let result = get_client_chan_stores(
            bill_store,
            bill_chain_store,
            company_store,
            company_blockchain_store,
            identity_store,
            file_upload_store,
            sender,
        )
        .handle_company_proof_file_request("some_id", TEST_NODE_ID_SECP, "file.pdf")
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn handle_company_proof_file_request_not_if_not_signatory() {
        let (sender, _receiver) = mpsc::channel(10);
        let (
            bill_store,
            bill_chain_store,
            mut company_store,
            company_blockchain_store,
            identity_store,
            file_upload_store,
        ) = get_storages();
        let mut company = get_baseline_company_data("some_id").1 .0;
        company.proof_of_registration_file = Some(File {
            name: "file.pdf".to_string(),
            hash: "some_hash".to_string(),
        });
        company.signatories.push("some_other_node_id".to_string());
        let company_clone = company.clone();
        company_store
            .expect_get()
            .returning(move |_| Ok(company_clone.clone()));

        let result = get_client_chan_stores(
            bill_store,
            bill_chain_store,
            company_store,
            company_blockchain_store,
            identity_store,
            file_upload_store,
            sender,
        )
        .handle_company_proof_file_request("some_id", "some_node_id", "file.pdf")
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handle_company_proof_file_request_not_if_no_file() {
        let (sender, _receiver) = mpsc::channel(10);
        let (
            bill_store,
            bill_chain_store,
            mut company_store,
            company_blockchain_store,
            identity_store,
            file_upload_store,
        ) = get_storages();
        let mut company = get_baseline_company_data("some_id").1 .0;
        company.proof_of_registration_file = None;
        company.signatories.push("some_node_id".to_string());
        let company_clone = company.clone();
        company_store
            .expect_get()
            .returning(move |_| Ok(company_clone.clone()));

        let result = get_client_chan_stores(
            bill_store,
            bill_chain_store,
            company_store,
            company_blockchain_store,
            identity_store,
            file_upload_store,
            sender,
        )
        .handle_company_proof_file_request("some_id", "some_node_id", "file.pdf")
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handle_company_proof_file_request_not_if_wrong_file() {
        let (sender, _receiver) = mpsc::channel(10);
        let (
            bill_store,
            bill_chain_store,
            mut company_store,
            company_blockchain_store,
            identity_store,
            file_upload_store,
        ) = get_storages();
        let mut company = get_baseline_company_data("some_id").1 .0;
        company.proof_of_registration_file = Some(File {
            name: "other_file.pdf".to_string(),
            hash: "some_hash".to_string(),
        });
        company.signatories.push("some_node_id".to_string());
        let company_clone = company.clone();
        company_store
            .expect_get()
            .returning(move |_| Ok(company_clone.clone()));

        let result = get_client_chan_stores(
            bill_store,
            bill_chain_store,
            company_store,
            company_blockchain_store,
            identity_store,
            file_upload_store,
            sender,
        )
        .handle_company_proof_file_request("some_id", "some_node_id", "file.pdf")
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn check_companies_baseline() {
        let (sender, mut receiver) = mpsc::channel(10);
        let (
            bill_store,
            bill_chain_store,
            mut company_store,
            mut company_blockchain_store,
            mut identity_store,
            mut file_upload_store,
        ) = get_storages();
        let keys = BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap();
        let node_id = keys.get_public_key();
        let provider_peer = PeerId::random();

        company_store.expect_get_all().returning(|| {
            let mut map = HashMap::new();
            let company_1 = get_baseline_company_data("company_1");
            let company_2 = get_baseline_company_data("company_2");
            map.insert(String::from("company_1"), (company_1.1 .0, company_1.1 .1));
            map.insert(String::from("company_2"), (company_2.1 .0, company_2.1 .1));
            Ok(map)
        });

        company_blockchain_store
            .expect_add_block()
            .returning(|_, _| Ok(()));
        company_blockchain_store
            .expect_remove()
            .returning(|_| Ok(()));

        let node_id_clone = node_id.clone();
        identity_store.expect_get().returning(move || {
            let mut identity = Identity::new_empty();
            identity.node_id = node_id_clone.clone();
            Ok(identity)
        });

        identity_store
            .expect_get_key_pair()
            .returning(move || Ok(keys.clone()));

        company_store.expect_remove().returning(|_| Ok(()));
        company_store
            .expect_exists()
            .returning(|id| id == "company_1");
        company_store.expect_insert().returning(|_| Ok(()));
        company_store
            .expect_save_key_pair()
            .returning(|_, _| Ok(()));

        file_upload_store
            .expect_delete_attached_files()
            .returning(|_| Ok(()));
        file_upload_store
            .expect_save_attached_file()
            .returning(|_, _, _| Ok(()));

        tokio::spawn(async move {
            while let Some(event) = receiver.next().await {
                match event {
                    Command::GetRecord { key, sender } => {
                        assert_eq!(key, format!("COMPANIES{}", &node_id));
                        let result: Vec<String> =
                            vec!["company_1".to_string(), "company_3".to_string()];
                        sender
                            .send(Ok(Record::new(
                                Key::new(&format!("COMPANIES{}", &node_id)),
                                to_vec(&result).unwrap(),
                            )))
                            .unwrap();
                    }
                    Command::GetProviders { entry, sender } => {
                        assert_eq!(entry, "COMPANYcompany_3".to_string());

                        let mut res = HashSet::new();
                        res.insert(provider_peer);
                        sender.send(res).unwrap();
                    }
                    Command::RequestFile {
                        sender,
                        file_name,
                        peer,
                    } => {
                        assert_eq!(peer, provider_peer);
                        let mut company_data = get_baseline_company_data("company_3");
                        let file_bytes = "helloworld".to_string().into_bytes();
                        company_data.1 .0.logo_file = Some(File {
                            name: "logo.png".to_string(),
                            hash: util::sha256_hash(&file_bytes),
                        });
                        company_data.1 .0.proof_of_registration_file = Some(File {
                            name: "proof.pdf".to_string(),
                            hash: util::sha256_hash(&file_bytes),
                        });
                        if file_name.contains(COMPANY_KEY_PREFIX) {
                            sender
                                .send(Ok(util::crypto::encrypt_ecies(
                                    &company_keys_to_bytes(&company_data.1 .1).unwrap(),
                                    TEST_PUB_KEY_SECP,
                                )
                                .unwrap()))
                                .unwrap();
                        } else if file_name.contains(COMPANY_LOGO_PREFIX)
                            || file_name.contains(COMPANY_PROOF_PREFIX)
                        {
                            sender
                                .send(Ok(util::crypto::encrypt_ecies(
                                    &file_bytes,
                                    TEST_PUB_KEY_SECP,
                                )
                                .unwrap()))
                                .unwrap();
                        } else if file_name.contains(COMPANY_CHAIN_PREFIX) {
                            let chain = get_valid_company_chain("company_3");
                            let chain_bytes = company_chain_to_bytes(&chain).unwrap();
                            sender
                                .send(Ok(util::crypto::encrypt_ecies(
                                    &chain_bytes,
                                    TEST_PUB_KEY_SECP,
                                )
                                .unwrap()))
                                .unwrap();
                        } else if file_name.contains(COMPANY_PREFIX) {
                            sender
                                .send(Ok(company_to_bytes(&company_data.1 .0).unwrap()))
                                .unwrap();
                        } else {
                            panic!("wrong file request: {file_name}");
                        }
                    }
                    Command::StopProviding { entry } => {
                        assert_eq!(entry, "COMPANYcompany_2".to_string());
                    }
                    Command::StartProviding { entry, sender } => {
                        assert_eq!(entry, "COMPANYcompany_3".to_string());
                        sender.send(()).unwrap();
                    }
                    Command::SubscribeToTopic { topic } => {
                        assert_eq!(topic, "COMPANYcompany_3".to_string());
                    }
                    Command::UnsubscribeFromTopic { topic } => {
                        assert_eq!(topic, "COMPANYcompany_2".to_string());
                    }
                    _ => panic!("wrong event: {event:?}"),
                }
            }
        });

        let result = get_client_chan_stores(
            bill_store,
            bill_chain_store,
            company_store,
            company_blockchain_store,
            identity_store,
            file_upload_store,
            sender,
        )
        .check_companies()
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn check_new_bills_baseline() {
        let (sender, mut receiver) = mpsc::channel(10);
        let (
            mut bill_store,
            mut bill_chain_store,
            company_store,
            company_blockchain_store,
            mut identity_store,
            mut file_upload_store,
        ) = get_storages();
        let keys = BcrKeys::from_private_key(TEST_PRIVATE_KEY_SECP).unwrap();
        let node_id = keys.get_public_key();
        let provider_peer = PeerId::random();

        let node_id_clone = node_id.clone();
        identity_store.expect_get().returning(move || {
            let mut identity = Identity::new_empty();
            identity.node_id = node_id_clone.clone();
            Ok(identity)
        });

        identity_store
            .expect_get_key_pair()
            .returning(move || Ok(keys.clone()));

        bill_store.expect_exists().returning(|id| id == "bill_1");
        bill_chain_store.expect_add_block().returning(|_, _| Ok(()));
        bill_store.expect_save_keys().returning(|_, _| Ok(()));

        file_upload_store
            .expect_save_attached_file()
            .returning(|_, _, _| Ok(()));

        tokio::spawn(async move {
            while let Some(event) = receiver.next().await {
                match event {
                    Command::GetRecord { key, sender } => {
                        assert_eq!(key, format!("BILLS{}", node_id));
                        let result: Vec<String> = vec!["bill_1".to_string(), "bill_2".to_string()];
                        sender
                            .send(Ok(Record::new(
                                Key::new(&format!("BILLS{}", node_id)),
                                to_vec(&result).unwrap(),
                            )))
                            .unwrap();
                    }
                    Command::GetProviders { entry, sender } => {
                        assert_eq!(entry, "BILLbill_2".to_string());

                        let mut res = HashSet::new();
                        res.insert(provider_peer);
                        sender.send(res).unwrap();
                    }
                    Command::RequestFile {
                        sender,
                        file_name,
                        peer,
                    } => {
                        assert_eq!(peer, provider_peer);
                        let file_bytes = "helloworld".to_string().into_bytes();

                        if file_name.contains(KEY_PREFIX) {
                            let keys = BillKeys {
                                private_key: TEST_PRIVATE_KEY_SECP.to_string(),
                                public_key: TEST_PUB_KEY_SECP.to_string(),
                            };
                            sender
                                .send(Ok(util::crypto::encrypt_ecies(
                                    &to_vec(&keys).unwrap(),
                                    TEST_PUB_KEY_SECP,
                                )
                                .unwrap()))
                                .unwrap();
                        } else if file_name.contains(BILL_ATTACHMENT_PREFIX) {
                            // file is doubly encrypted - once with bill key, once with pub key of
                            // receiver
                            sender
                                .send(Ok(util::crypto::encrypt_ecies(
                                    &util::crypto::encrypt_ecies(&file_bytes, TEST_PUB_KEY_SECP)
                                        .unwrap(),
                                    TEST_PUB_KEY_SECP,
                                )
                                .unwrap()))
                                .unwrap();
                        } else if file_name.contains(BILL_PREFIX) {
                            let mut bill = get_baseline_bill("bill_2");
                            bill.files.push(File {
                                name: "invoice.pdf".to_string(),
                                hash: util::sha256_hash(&file_bytes),
                            });
                            let chain = get_genesis_chain(Some(bill));
                            sender.send(Ok(to_vec(&chain).unwrap())).unwrap()
                        } else {
                            panic!("wrong file request: {file_name}");
                        }
                    }
                    Command::StartProviding { entry, sender } => {
                        assert_eq!(entry, "BILLbill_2".to_string());
                        sender.send(()).unwrap();
                    }
                    Command::SubscribeToTopic { topic } => {
                        assert_eq!(topic, "BILLbill_2".to_string());
                    }
                    _ => panic!("wrong event: {event:?}"),
                }
            }
        });

        let result = get_client_chan_stores(
            bill_store,
            bill_chain_store,
            company_store,
            company_blockchain_store,
            identity_store,
            file_upload_store,
            sender,
        )
        .check_new_bills()
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn add_bill_to_dht_for_node() {
        let (sender, mut receiver) = mpsc::channel(10);

        tokio::spawn(async move {
            while let Some(event) = receiver.next().await {
                match event {
                    Command::PutRecord { key, value } => {
                        assert_eq!(key, "BILLSmy_node_id".to_string());
                        let parsed: Vec<String> = from_slice(&value).unwrap();
                        assert!(parsed.contains(&String::from("bill_1")));
                        assert!(parsed.contains(&String::from("bill_2")));
                        assert!(parsed.len() == 2);
                    }
                    Command::GetRecord { key, sender } => {
                        assert_eq!(key, "BILLSmy_node_id".to_string());
                        sender
                            .send(Ok(Record::new(
                                Key::new(&"BILLSmy_node_id".to_string()),
                                to_vec(&vec!["bill_2".to_string()]).unwrap(),
                            )))
                            .unwrap();
                    }
                    _ => panic!("wrong event"),
                }
            }
        });

        let result = get_client_chan(sender)
            .add_bill_to_dht_for_node("bill_1", "my_node_id")
            .await;
        assert!(result.is_ok());
    }
}
