#[cfg(test)]
#[allow(clippy::module_inception)]
pub mod tests {
    use crate::CourtConfig;
    use crate::service::notification_service::{self, chain_keys::ChainKeyServiceApi};
    use crate::{
        CONFIG, DbContext, DevModeConfig, MintConfig, NostrConfig, PaymentConfig,
        data::bill::BillKeys,
    };
    use async_trait::async_trait;
    use bcr_ebill_core::{
        NodeId, OptionalPostalAddress, PostalAddress, PublicKey, SecretKey, ServiceTraitBounds,
        bill::{BillId, BitcreditBill, BitcreditBillResult, PaymentState},
        blockchain::{
            BlockchainType,
            bill::{BillBlock, BillBlockchain, BillOpCode},
            company::{CompanyBlock, CompanyBlockchain},
            identity::{IdentityBlock, IdentityBlockchain},
        },
        company::{Company, CompanyKeys},
        contact::{BillIdentParticipant, BillParticipant, Contact, ContactType},
        identity::{ActiveIdentityState, Identity, IdentityType, IdentityWithAll},
        identity_proof::{IdentityProof, IdentityProofStatus},
        mint::{MintOffer, MintRequest, MintRequestStatus},
        nostr_contact::{HandshakeStatus, NostrContact, NostrPublicKey, TrustLevel},
        notification::{ActionType, Notification, NotificationType},
        util::crypto::BcrKeys,
    };
    use bcr_ebill_persistence::identity_proof::IdentityProofStoreApi;
    use bcr_ebill_persistence::notification::EmailNotificationStoreApi;
    use bcr_ebill_persistence::{
        BackupStoreApi, ContactStoreApi, NostrEventOffset, NostrEventOffsetStoreApi,
        NotificationStoreApi, Result, SurrealDbConfig,
        bill::{BillChainStoreApi, BillStoreApi},
        company::{CompanyChainStoreApi, CompanyStoreApi},
        file_upload::FileUploadStoreApi,
        identity::{IdentityChainStoreApi, IdentityStoreApi},
        mint::MintStoreApi,
        nostr::{
            NostrChainEvent, NostrChainEventStoreApi, NostrContactStoreApi, NostrQueuedMessage,
            NostrQueuedMessageStoreApi,
        },
        notification::NotificationFilter,
    };
    use std::{
        collections::{HashMap, HashSet},
        str::FromStr,
    };
    use std::{path::Path, sync::Arc};

    // Need to wrap mocks, because traits are in a different crate
    mockall::mock! {
        pub ContactStoreApiMock {}

        impl ServiceTraitBounds for ContactStoreApiMock {}

        #[async_trait]
        impl ContactStoreApi for ContactStoreApiMock {
            async fn search(&self, search_term: &str) -> Result<Vec<Contact>>;
            async fn get_map(&self) -> Result<HashMap<NodeId, Contact>>;
            async fn get(&self, node_id: &NodeId) -> Result<Option<Contact>>;
            async fn insert(&self, node_id: &NodeId, data: Contact) -> Result<()>;
            async fn delete(&self, node_id: &NodeId) -> Result<()>;
            async fn update(&self, node_id: &NodeId, data: Contact) -> Result<()>;
        }
    }

    mockall::mock! {
        pub MintStore {}

        impl ServiceTraitBounds for MintStore {}

        #[async_trait]
        impl MintStoreApi for MintStore {
            async fn exists_for_bill(&self, requester_node_id: &NodeId, bill_id: &BillId) -> Result<bool>;
            async fn get_all_active_requests(&self) -> Result<Vec<MintRequest>>;
            async fn get_requests(
                &self,
                requester_node_id: &NodeId,
                bill_id: &BillId,
                mint_node_id: &NodeId,
            ) -> Result<Vec<MintRequest>>;
            async fn get_requests_for_bill(
                &self,
                requester_node_id: &NodeId,
                bill_id: &BillId,
            ) -> Result<Vec<MintRequest>>;
            async fn add_request(
                &self,
                requester_node_id: &NodeId,
                bill_id: &BillId,
                mint_node_id: &NodeId,
                mint_request_id: &str,
                timestamp: u64,
            ) -> Result<()>;
            async fn get_request(&self, mint_request_id: &str) -> Result<Option<MintRequest>>;
            async fn update_request(
                &self,
                mint_request_id: &str,
                new_status: &MintRequestStatus,
            ) -> Result<()>;
            async fn add_proofs_to_offer(&self, mint_request_id: &str, proofs: &str) -> Result<()>;
            async fn add_recovery_data_to_offer(
                &self,
                mint_request_id: &str,
                secrets: &[String],
                rs: &[String],
            ) -> Result<()>;
            async fn set_proofs_to_spent_for_offer(&self, mint_request_id: &str) -> Result<()>;
            async fn add_offer(
                &self,
                mint_request_id: &str,
                keyset_id: &str,
                expiration_timestamp: u64,
                discounted_sum: u64,
            ) -> Result<()>;
            async fn get_offer(&self, mint_request_id: &str) -> Result<Option<MintOffer>>;
        }
    }

    mockall::mock! {
        pub NostrContactStore {}

        impl ServiceTraitBounds for NostrContactStore {}

        #[async_trait]
        impl NostrContactStoreApi for NostrContactStore {
            async fn by_node_id(&self, node_id: &NodeId) -> Result<Option<NostrContact>>;
            async fn by_npub(&self, npub: &NostrPublicKey) -> Result<Option<NostrContact>>;
            async fn upsert(&self, data: &NostrContact) -> Result<()>;
            async fn delete(&self, node_id: &NodeId) -> Result<()>;
            async fn set_handshake_status(&self, node_id: &NodeId, status: HandshakeStatus) -> Result<()>;
            async fn set_trust_level(&self, node_id: &NodeId, trust_level: TrustLevel) -> Result<()>;
            async fn get_npubs(&self, levels: Vec<TrustLevel>) -> Result<Vec<NostrPublicKey>>;
            async fn search(&self, search_term: &str, levels: Vec<TrustLevel>) -> Result<Vec<NostrContact>>;
        }
    }

    mockall::mock! {
        pub BackupStoreApiMock {}

        impl ServiceTraitBounds for BackupStoreApiMock {}

        #[async_trait]
        impl BackupStoreApi for BackupStoreApiMock {
            async fn backup(&self) -> Result<Vec<u8>>;
            async fn restore(&self, file_path: &Path) -> Result<()>;
            async fn drop_db(&self, name: &str) -> Result<()>;
        }
    }

    mockall::mock! {
        pub BillStoreApiMock {}

        impl ServiceTraitBounds for BillStoreApiMock {}

        #[async_trait]
        impl BillStoreApi for BillStoreApiMock {
            async fn get_bills_from_cache(&self, ids: &[BillId], identity_node_id: &NodeId) -> Result<Vec<BitcreditBillResult>>;
            async fn get_bill_from_cache(&self, id: &BillId, identity_node_id: &NodeId) -> Result<Option<BitcreditBillResult>>;
            async fn save_bill_to_cache(&self, id: &BillId, identity_node_id: &NodeId, bill: &BitcreditBillResult) -> Result<()>;
            async fn invalidate_bill_in_cache(&self, id: &BillId) -> Result<()>;
            async fn clear_bill_cache(&self) -> Result<()>;
            async fn exists(&self, id: &BillId) -> Result<bool>;
            async fn get_ids(&self) -> Result<Vec<BillId>>;
            async fn save_keys(&self, id: &BillId, keys: &BillKeys) -> Result<()>;
            async fn get_keys(&self, id: &BillId) -> Result<BillKeys>;
            async fn is_paid(&self, id: &BillId) -> Result<bool>;
            async fn set_payment_state(&self, id: &BillId, payment_state: &PaymentState) -> Result<()>;
            async fn get_payment_state(&self, id: &BillId) -> Result<Option<PaymentState>>;
            async fn set_offer_to_sell_payment_state(
                &self,
                id: &BillId,
                block_id: u64,
                payment_state: &PaymentState,
            ) -> Result<()>;
            async fn get_offer_to_sell_payment_state(
                &self,
                id: &BillId,
                block_id: u64,
            ) -> Result<Option<PaymentState>>;
            async fn set_recourse_payment_state(
                &self,
                id: &BillId,
                block_id: u64,
                payment_state: &PaymentState,
            ) -> Result<()>;
            async fn get_recourse_payment_state(
                &self,
                id: &BillId,
                block_id: u64,
            ) -> Result<Option<PaymentState>>;
            async fn get_bill_ids_waiting_for_payment(&self) -> Result<Vec<BillId>>;
            async fn get_bill_ids_waiting_for_sell_payment(&self) -> Result<Vec<BillId>>;
            async fn get_bill_ids_waiting_for_recourse_payment(&self) -> Result<Vec<BillId>>;
            async fn get_bill_ids_with_op_codes_since(
                &self,
                op_code: HashSet<BillOpCode>,
                since: u64,
            ) -> Result<Vec<BillId>>;
        }
    }

    mockall::mock! {
        pub BillChainStoreApiMock {}

        impl ServiceTraitBounds for BillChainStoreApiMock {}

        #[async_trait]
        impl BillChainStoreApi for BillChainStoreApiMock {
            async fn get_latest_block(&self, id: &BillId) -> Result<BillBlock>;
            async fn add_block(&self, id: &BillId, block: &BillBlock) -> Result<()>;
            async fn get_chain(&self, id: &BillId) -> Result<BillBlockchain>;
        }
    }

    mockall::mock! {
        pub ChainKeyService {}

        impl ServiceTraitBounds for ChainKeyService {}

        #[async_trait]
        impl ChainKeyServiceApi for ChainKeyService {
            async fn get_chain_keys(&self, chain_id: &str, chain_type: BlockchainType) -> notification_service::Result<Option<BcrKeys>>;
        }
    }

    mockall::mock! {
        pub CompanyStoreApiMock {}

        impl ServiceTraitBounds for CompanyStoreApiMock {}

        #[async_trait]
        impl CompanyStoreApi for CompanyStoreApiMock {
            async fn search(&self, search_term: &str) -> Result<Vec<Company>>;
            async fn exists(&self, id: &NodeId) -> bool;
            async fn get(&self, id: &NodeId) -> Result<Company>;
            async fn get_all(&self) -> Result<HashMap<NodeId, (Company, CompanyKeys)>>;
            async fn insert(&self, data: &Company) -> Result<()>;
            async fn update(&self, id: &NodeId, data: &Company) -> Result<()>;
            async fn remove(&self, id: &NodeId) -> Result<()>;
            async fn save_key_pair(&self, id: &NodeId, key_pair: &CompanyKeys) -> Result<()>;
            async fn get_key_pair(&self, id: &NodeId) -> Result<CompanyKeys>;
        }
    }

    mockall::mock! {
        pub CompanyChainStoreApiMock {}

        impl ServiceTraitBounds for CompanyChainStoreApiMock {}

        #[async_trait]
        impl CompanyChainStoreApi for CompanyChainStoreApiMock {
            async fn get_latest_block(&self, id: &NodeId) -> Result<CompanyBlock>;
            async fn add_block(&self, id: &NodeId, block: &CompanyBlock) -> Result<()>;
            async fn remove(&self, id: &NodeId) -> Result<()>;
            async fn get_chain(&self, id: &NodeId) -> Result<CompanyBlockchain>;
        }
    }

    mockall::mock! {
        pub IdentityStoreApiMock {}

        impl ServiceTraitBounds for IdentityStoreApiMock {}

        #[async_trait]
        impl IdentityStoreApi for IdentityStoreApiMock {
            async fn exists(&self) -> bool;
            async fn save(&self, identity: &Identity) -> Result<()>;
            async fn get(&self) -> Result<Identity>;
            async fn get_full(&self) -> Result<IdentityWithAll>;
            async fn save_key_pair(&self, key_pair: &BcrKeys, seed: &str) -> Result<()>;
            async fn get_key_pair(&self) -> Result<BcrKeys>;
            async fn get_or_create_key_pair(&self) -> Result<BcrKeys>;
            async fn get_seedphrase(&self) -> Result<String>;
            async fn get_current_identity(&self) -> Result<ActiveIdentityState>;
            async fn set_current_identity(&self, identity_state: &ActiveIdentityState) -> Result<()>;
            async fn set_or_check_network(&self, configured_network: bitcoin::Network) -> Result<()>;
        }
    }

    mockall::mock! {
        pub IdentityChainStoreApiMock {}

        impl ServiceTraitBounds for IdentityChainStoreApiMock {}

        #[async_trait]
        impl IdentityChainStoreApi for IdentityChainStoreApiMock {
            async fn get_latest_block(&self) -> Result<IdentityBlock>;
            async fn add_block(&self, block: &IdentityBlock) -> Result<()>;
            async fn get_chain(&self) -> Result<IdentityBlockchain>;
        }
    }

    mockall::mock! {
        pub NostrEventOffsetStoreApiMock {}

        impl ServiceTraitBounds for NostrEventOffsetStoreApiMock {}

        #[async_trait]
        impl NostrEventOffsetStoreApi for NostrEventOffsetStoreApiMock {
            async fn current_offset(&self, node_id: &NodeId) -> Result<u64>;
            async fn is_processed(&self, event_id: &str) -> Result<bool>;
            async fn add_event(&self, data: NostrEventOffset) -> Result<()>;
        }
    }

    mockall::mock! {
        pub NostrQueuedMessageStore {}

        impl ServiceTraitBounds for NostrQueuedMessageStore {}

        #[async_trait]
        impl NostrQueuedMessageStoreApi for NostrQueuedMessageStore {
            async fn add_message(&self, message: NostrQueuedMessage, max_retries: i32) -> Result<()>;
            async fn get_retry_messages(&self, limit: u64) -> Result<Vec<NostrQueuedMessage>>;
            async fn fail_retry(&self, id: &str) -> Result<()>;
            async fn succeed_retry(&self, id: &str) -> Result<()>;
        }
    }

    mockall::mock! {
        pub NostrChainEventStore {}

        impl ServiceTraitBounds for NostrChainEventStore {}

        #[async_trait]
        impl NostrChainEventStoreApi for NostrChainEventStore {
            async fn find_chain_events(&self, chain_id: &str, chain_type: BlockchainType) -> Result<Vec<NostrChainEvent>>;
            async fn find_latest_block_events(&self, chain_id: &str, chain_type: BlockchainType) -> Result<Vec<NostrChainEvent>>;
            async fn find_root_event(&self,chain_id: &str, chain_type: BlockchainType) -> Result<Option<NostrChainEvent>>;
            async fn find_by_block_hash(&self, hash: &str) -> Result<Option<NostrChainEvent>>;
            async fn add_chain_event(&self, event: NostrChainEvent) -> Result<()>;
            async fn by_event_id(&self, event_id: &str) -> Result<Option<NostrChainEvent>>;
        }
    }

    mockall::mock! {
        pub IdentityProofStore {}

        impl ServiceTraitBounds for IdentityProofStore {}

        #[async_trait]
        impl IdentityProofStoreApi for IdentityProofStore {
            async fn list_by_node_id(&self, node_id: &NodeId) -> Result<Vec<IdentityProof>>;
            async fn add(&self, identity_proof: &IdentityProof) -> Result<()>;
            async fn archive(&self, id: &str) -> Result<()>;
            async fn archive_by_node_id(&self, node_id: &NodeId) -> Result<()>;
            async fn get_by_id(&self, id: &str) -> Result<Option<IdentityProof>>;
            async fn update_status_by_id(
                &self,
                id: &str,
                status: &IdentityProofStatus,
                status_last_checked_timestamp: u64,
            ) -> Result<()>;
            async fn get_with_status_last_checked_timestamp_before(
                &self,
                before_timestamp: u64,
            ) -> Result<Vec<IdentityProof>>;
        }
    }

    mockall::mock! {
        pub NotificationStoreApiMock {}

        impl ServiceTraitBounds for NotificationStoreApiMock {}

        #[async_trait]
        impl NotificationStoreApi for NotificationStoreApiMock {
            async fn get_active_status_for_node_ids(
                &self,
                node_ids: &[NodeId],
            ) -> Result<HashMap<NodeId, bool>>;
            async fn add(&self, notification: Notification) -> Result<Notification>;
            async fn list(&self, filter: NotificationFilter) -> Result<Vec<Notification>>;
            async fn get_latest_by_references(
                &self,
                reference: &[String],
                notification_type: NotificationType,
            ) -> Result<HashMap<String, Notification>>;
            async fn get_latest_by_reference(
                &self,
                reference: &str,
                notification_type: NotificationType,
            ) -> Result<Option<Notification>>;
            #[allow(unused)]
            async fn list_by_type(&self, notification_type: NotificationType) -> Result<Vec<Notification>>;
            async fn mark_as_done(&self, notification_id: &str) -> Result<()>;
            #[allow(unused)]
            async fn delete(&self, notification_id: &str) -> Result<()>;
            async fn set_bill_notification_sent(
                &self,
                bill_id: &BillId,
                block_height: i32,
                action_type: ActionType,
            ) -> Result<()>;
            async fn bill_notification_sent(
                &self,
                bill_id: &BillId,
                block_height: i32,
                action_type: ActionType,
            ) -> Result<bool>;
        }
    }

    mockall::mock! {
        pub EmailNotificationStoreApiMock {}

        impl ServiceTraitBounds for EmailNotificationStoreApiMock {}

        #[async_trait]
        impl EmailNotificationStoreApi for EmailNotificationStoreApiMock {
            async fn add_email_preferences_link_for_node_id(
                &self,
                email_preferences_link: &url::Url,
                node_id: &NodeId,
            ) -> Result<()>;
            async fn get_email_preferences_link_for_node_id(&self, node_id: &NodeId) -> Result<Option<url::Url>>;
        }
    }

    mockall::mock! {
        pub FileUploadStoreApiMock {}

        impl ServiceTraitBounds for FileUploadStoreApiMock {}

        #[async_trait]
        impl FileUploadStoreApi for FileUploadStoreApiMock {
            async fn create_temp_upload_folder(&self, file_upload_id: &str) -> Result<()>;
            async fn remove_temp_upload_folder(&self, file_upload_id: &str) -> Result<()>;
            async fn write_temp_upload_file(
                &self,
                file_upload_id: &str,
                file_name: &str,
                file_bytes: &[u8],
            ) -> Result<()>;
            async fn read_temp_upload_file(&self, file_upload_id: &str) -> Result<(String, Vec<u8>)>;
        }
    }

    #[allow(unused)]
    pub fn get_mock_db_ctx(nostr_contact_store: Option<MockNostrContactStore>) -> DbContext {
        DbContext {
            contact_store: Arc::new(MockContactStoreApiMock::new()),
            bill_store: Arc::new(MockBillStoreApiMock::new()),
            bill_blockchain_store: Arc::new(MockBillChainStoreApiMock::new()),
            identity_store: Arc::new(MockIdentityStoreApiMock::new()),
            identity_chain_store: Arc::new(MockIdentityChainStoreApiMock::new()),
            company_chain_store: Arc::new(MockCompanyChainStoreApiMock::new()),
            company_store: Arc::new(MockCompanyStoreApiMock::new()),
            file_upload_store: Arc::new(MockFileUploadStoreApiMock::new()),
            nostr_event_offset_store: Arc::new(MockNostrEventOffsetStoreApiMock::new()),
            notification_store: Arc::new(MockNotificationStoreApiMock::new()),
            email_notification_store: Arc::new(MockEmailNotificationStoreApiMock::new()),
            backup_store: Arc::new(MockBackupStoreApiMock::new()),
            queued_message_store: Arc::new(MockNostrQueuedMessageStore::new()),
            nostr_contact_store: Arc::new(nostr_contact_store.unwrap_or_default()),
            mint_store: Arc::new(MockMintStore::new()),
            nostr_chain_event_store: Arc::new(MockNostrChainEventStore::new()),
            identity_proof_store: Arc::new(MockIdentityProofStore::new()),
        }
    }

    pub fn init_test_cfg() {
        match CONFIG.get() {
            Some(_) => (),
            None => {
                let _ = crate::init(crate::Config {
                    app_url: url::Url::parse("https://bitcredit-dev.minibill.tech").unwrap(),
                    bitcoin_network: "testnet".to_string(),
                    esplora_base_url: "https://esplora.minibill.tech".to_string(),
                    db_config: SurrealDbConfig {
                        connection_string: "ws://localhost:8800".to_string(),
                        ..SurrealDbConfig::default()
                    },
                    data_dir: ".".to_string(),
                    nostr_config: NostrConfig {
                        only_known_contacts: false,
                        relays: vec!["ws://localhost:8080".to_string()],
                    },
                    mint_config: MintConfig {
                        default_mint_url: "http://localhost:4242/".into(),
                        default_mint_node_id: NodeId::from_str(
                            "bitcrt03f9f94d1fdc2090d46f3524807e3f58618c36988e69577d70d5d4d1e9e9645a4f",
                        ).unwrap(),
                    },
                    payment_config: PaymentConfig {
                        num_confirmations_for_payment: 6,
                    },
                    dev_mode_config: DevModeConfig {
                        on: false
                    },
                    court_config: CourtConfig {
                        default_url: url::Url::parse("https://court-dev.minibill.tech").unwrap()
                    }
                });
            }
        }
    }

    pub fn empty_address() -> PostalAddress {
        PostalAddress {
            country: "AT".to_string(),
            city: "Vienna".to_string(),
            zip: None,
            address: "Some Address 1".to_string(),
        }
    }

    pub fn filled_optional_address() -> OptionalPostalAddress {
        OptionalPostalAddress {
            country: Some("AT".to_string()),
            city: Some("Vienna".to_string()),
            zip: None,
            address: Some("Some Address 1".to_string()),
        }
    }

    pub fn empty_optional_address() -> OptionalPostalAddress {
        OptionalPostalAddress {
            country: None,
            city: None,
            zip: None,
            address: None,
        }
    }

    pub fn empty_identity() -> Identity {
        Identity {
            t: IdentityType::Ident,
            node_id: node_id_test(),
            name: "some name".to_string(),
            email: Some("some@example.com".to_string()),
            postal_address: empty_optional_address(),
            date_of_birth: None,
            country_of_birth: None,
            city_of_birth: None,
            identification_number: None,
            nostr_relays: vec![],
            profile_picture_file: None,
            identity_document_file: None,
        }
    }

    pub fn empty_bill_identified_participant() -> BillIdentParticipant {
        BillIdentParticipant {
            t: ContactType::Person,
            node_id: node_id_test(),
            name: "some@example.com".to_string(),
            postal_address: empty_address(),
            email: None,
            nostr_relays: vec![],
        }
    }

    pub fn bill_participant_only_node_id(node_id: NodeId) -> BillParticipant {
        BillParticipant::Ident(BillIdentParticipant {
            t: ContactType::Person,
            node_id,
            name: "some name".to_string(),
            postal_address: empty_address(),
            email: None,
            nostr_relays: vec![],
        })
    }

    pub fn empty_bitcredit_bill() -> BitcreditBill {
        BitcreditBill {
            id: bill_id_test(),
            country_of_issuing: "AT".to_string(),
            city_of_issuing: "Vienna".to_string(),
            drawee: empty_bill_identified_participant(),
            drawer: empty_bill_identified_participant(),
            payee: BillParticipant::Ident(empty_bill_identified_participant()),
            endorsee: None,
            currency: "sat".to_string(),
            sum: 5000,
            maturity_date: "2099-11-12".to_string(),
            issue_date: "2099-08-12".to_string(),
            city_of_payment: "Vienna".to_string(),
            country_of_payment: "AT".to_string(),
            language: "DE".to_string(),
            files: vec![],
        }
    }

    pub fn bill_identified_participant_only_node_id(node_id: NodeId) -> BillIdentParticipant {
        BillIdentParticipant {
            t: ContactType::Person,
            node_id,
            name: "some name".to_string(),
            postal_address: empty_address(),
            email: None,
            nostr_relays: vec![],
        }
    }

    pub fn node_id_test() -> NodeId {
        NodeId::from_str("bitcrt02295fb5f4eeb2f21e01eaf3a2d9a3be10f39db870d28f02146130317973a40ac0")
            .unwrap()
    }

    pub fn node_id_test_other() -> NodeId {
        NodeId::from_str("bitcrt03f9f94d1fdc2090d46f3524807e3f58618c36988e69577d70d5d4d1e9e9645a4f")
            .unwrap()
    }

    pub fn node_id_test_other2() -> NodeId {
        NodeId::from_str("bitcrt039180c169e5f6d7c579cf1cefa37bffd47a2b389c8125601f4068c87bea795943")
            .unwrap()
    }

    // bitcrt285psGq4Lz4fEQwfM3We5HPznJq8p1YvRaddszFaU5dY
    pub fn bill_id_test() -> BillId {
        BillId::new(
            PublicKey::from_str(
                "026423b7d36d05b8d50a89a1b4ef2a06c88bcd2c5e650f25e122fa682d3b39686c",
            )
            .unwrap(),
            bitcoin::Network::Testnet,
        )
    }

    // bitcrt76LWp9iFregj9Lv1awLSfQAmjtDDinBR4GSCbNrEtqEe
    pub fn bill_id_test_other() -> BillId {
        BillId::new(
            PublicKey::from_str(
                "027a233c85a8f98e276e949ab94bba8bbc07b21946e50e388da767bcc6c95603ce",
            )
            .unwrap(),
            bitcoin::Network::Testnet,
        )
    }

    // bitcrtJArd6A7fDhkiD3AU5UgBSQ66yjzQT1NP9tVoeQ1aZW1y
    pub fn bill_id_test_other2() -> BillId {
        BillId::new(
            PublicKey::from_str(
                "0364f8de530163a528b4de33405ebe434bbd974a26ac24708674de572efacbdfdd",
            )
            .unwrap(),
            bitcoin::Network::Testnet,
        )
    }

    pub fn private_key_test() -> SecretKey {
        SecretKey::from_str("d1ff7427912d3b81743d3b67ffa1e65df2156d3dab257316cbc8d0f35eeeabe9")
            .unwrap()
    }

    pub const NODE_ID_TEST_STR: &str =
        "bitcrt02295fb5f4eeb2f21e01eaf3a2d9a3be10f39db870d28f02146130317973a40ac0";

    pub const TEST_NODE_ID_SECP_AS_NPUB_HEX: &str =
        "205b8dec12bc9e879f5b517aa32192a2550e88adcee3e54ec2c7294802568fef";

    pub const VALID_PAYMENT_ADDRESS_TESTNET: &str = "tb1qteyk7pfvvql2r2zrsu4h4xpvju0nz7ykvguyk0";
}
