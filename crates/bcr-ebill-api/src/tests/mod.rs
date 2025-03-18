#[cfg(test)]
#[allow(clippy::module_inception)]
pub mod tests {
    use crate::{CONFIG, data::bill::BillKeys};
    use async_trait::async_trait;
    use bcr_ebill_core::{
        OptionalPostalAddress, PostalAddress, ServiceTraitBounds,
        bill::BitcreditBill,
        blockchain::{
            bill::{BillBlock, BillBlockchain, BillOpCode},
            company::{CompanyBlock, CompanyBlockchain},
            identity::IdentityBlock,
        },
        company::{Company, CompanyKeys},
        contact::{Contact, ContactType, IdentityPublicData},
        identity::{Identity, IdentityWithAll},
        notification::{ActionType, Notification, NotificationType},
        util::crypto::BcrKeys,
    };
    use bcr_ebill_persistence::{
        BackupStoreApi, ContactStoreApi, NostrEventOffset, NostrEventOffsetStoreApi,
        NotificationStoreApi, Result,
        bill::{BillChainStoreApi, BillStoreApi},
        company::{CompanyChainStoreApi, CompanyStoreApi},
        file_upload::FileUploadStoreApi,
        identity::{IdentityChainStoreApi, IdentityStoreApi},
        notification::NotificationFilter,
    };
    use bcr_ebill_transport::{BillChainEvent, NotificationServiceApi};
    use std::collections::{HashMap, HashSet};
    use std::path::Path;

    // Need to wrap mocks, because traits are in a different crate
    mockall::mock! {
        pub ContactStoreApiMock {}

        #[async_trait]
        impl ContactStoreApi for ContactStoreApiMock {
            async fn search(&self, search_term: &str) -> Result<Vec<Contact>>;
            async fn get_map(&self) -> Result<HashMap<String, Contact>>;
            async fn get(&self, node_id: &str) -> Result<Option<Contact>>;
            async fn insert(&self, node_id: &str, data: Contact) -> Result<()>;
            async fn delete(&self, node_id: &str) -> Result<()>;
            async fn update(&self, node_id: &str, data: Contact) -> Result<()>;
        }
    }

    mockall::mock! {
        pub BackupStoreApiMock {}

        #[async_trait]
        impl BackupStoreApi for BackupStoreApiMock {
            async fn backup(&self) -> Result<Vec<u8>>;
            async fn restore(&self, file_path: &Path) -> Result<()>;
            async fn drop_db(&self, name: &str) -> Result<()>;
        }
    }

    mockall::mock! {
        pub BillStoreApiMock {}

        #[async_trait]
        impl BillStoreApi for BillStoreApiMock {
            async fn exists(&self, id: &str) -> bool;
            async fn get_ids(&self) -> Result<Vec<String>>;
            async fn save_keys(&self, id: &str, keys: &BillKeys) -> Result<()>;
            async fn get_keys(&self, id: &str) -> Result<BillKeys>;
            async fn is_paid(&self, id: &str) -> Result<bool>;
            async fn set_to_paid(&self, id: &str, payment_address: &str) -> Result<()>;
            async fn get_bill_ids_waiting_for_payment(&self) -> Result<Vec<String>>;
            async fn get_bill_ids_waiting_for_sell_payment(&self) -> Result<Vec<String>>;
            async fn get_bill_ids_waiting_for_recourse_payment(&self) -> Result<Vec<String>>;
            async fn get_bill_ids_with_op_codes_since(
                &self,
                op_code: HashSet<BillOpCode>,
                since: u64,
            ) -> Result<Vec<String>>;
        }
    }

    mockall::mock! {
        pub BillChainStoreApiMock {}

        #[async_trait]
        impl BillChainStoreApi for BillChainStoreApiMock {
            async fn get_latest_block(&self, id: &str) -> Result<BillBlock>;
            async fn add_block(&self, id: &str, block: &BillBlock) -> Result<()>;
            async fn get_chain(&self, id: &str) -> Result<BillBlockchain>;
        }
    }

    mockall::mock! {
        pub CompanyStoreApiMock {}

        #[async_trait]
        impl CompanyStoreApi for CompanyStoreApiMock {
            async fn search(&self, search_term: &str) -> Result<Vec<Company>>;
            async fn exists(&self, id: &str) -> bool;
            async fn get(&self, id: &str) -> Result<Company>;
            async fn get_all(&self) -> Result<HashMap<String, (Company, CompanyKeys)>>;
            async fn insert(&self, data: &Company) -> Result<()>;
            async fn update(&self, id: &str, data: &Company) -> Result<()>;
            async fn remove(&self, id: &str) -> Result<()>;
            async fn save_key_pair(&self, id: &str, key_pair: &CompanyKeys) -> Result<()>;
            async fn get_key_pair(&self, id: &str) -> Result<CompanyKeys>;
        }
    }

    mockall::mock! {
        pub CompanyChainStoreApiMock {}

        #[async_trait]
        impl CompanyChainStoreApi for CompanyChainStoreApiMock {
            async fn get_latest_block(&self, id: &str) -> Result<CompanyBlock>;
            async fn add_block(&self, id: &str, block: &CompanyBlock) -> Result<()>;
            async fn remove(&self, id: &str) -> Result<()>;
            async fn get_chain(&self, id: &str) -> Result<CompanyBlockchain>;
        }
    }

    mockall::mock! {
        pub IdentityStoreApiMock {}

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
        }
    }

    mockall::mock! {
        pub IdentityChainStoreApiMock {}

        #[async_trait]
        impl IdentityChainStoreApi for IdentityChainStoreApiMock {
            async fn get_latest_block(&self) -> Result<IdentityBlock>;
            async fn add_block(&self, block: &IdentityBlock) -> Result<()>;
        }
    }

    mockall::mock! {
        pub NostrEventOffsetStoreApiMock {}

        #[async_trait]
        impl NostrEventOffsetStoreApi for NostrEventOffsetStoreApiMock {
            async fn current_offset(&self) -> Result<u64>;
            async fn is_processed(&self, event_id: &str) -> Result<bool>;
            async fn add_event(&self, data: NostrEventOffset) -> Result<()>;
        }
    }

    mockall::mock! {
        pub NotificationStoreApiMock {}

        #[async_trait]
        impl NotificationStoreApi for NotificationStoreApiMock {
            async fn add(&self, notification: Notification) -> Result<Notification>;
            async fn list(&self, filter: NotificationFilter) -> Result<Vec<Notification>>;
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
                bill_id: &str,
                block_height: i32,
                action_type: ActionType,
            ) -> Result<()>;
            async fn bill_notification_sent(
                &self,
                bill_id: &str,
                block_height: i32,
                action_type: ActionType,
            ) -> Result<bool>;
        }
    }

    mockall::mock! {
        pub FileUploadStoreApiMock {}

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
            async fn save_attached_file(
                &self,
                encrypted_bytes: &[u8],
                id: &str,
                file_name: &str,
            ) -> Result<()>;
            async fn open_attached_file(&self, id: &str, file_name: &str) -> Result<Vec<u8>>;
            async fn delete_attached_files(&self, id: &str) -> Result<()>;
        }
    }

    impl ServiceTraitBounds for MockNotificationService {}
    mockall::mock! {
        pub NotificationService {}

        #[async_trait]
        impl NotificationServiceApi for NotificationService {
            async fn send_bill_is_signed_event(&self, bill: &BillChainEvent) -> bcr_ebill_transport::Result<()>;
            async fn send_bill_is_accepted_event(&self, bill: &BitcreditBill) -> bcr_ebill_transport::Result<()>;
            async fn send_request_to_accept_event(&self, bill: &BitcreditBill) -> bcr_ebill_transport::Result<()>;
            async fn send_request_to_pay_event(&self, bill: &BitcreditBill) -> bcr_ebill_transport::Result<()>;
            async fn send_bill_is_paid_event(&self, bill: &BitcreditBill) -> bcr_ebill_transport::Result<()>;
            async fn send_bill_is_endorsed_event(&self, bill: &BitcreditBill) -> bcr_ebill_transport::Result<()>;
            async fn send_offer_to_sell_event(
                &self,
                bill_id: &str,
                sum: Option<u64>,
                buyer: &IdentityPublicData,
            ) -> bcr_ebill_transport::Result<()>;
            async fn send_bill_is_sold_event(
                &self,
                bill_id: &str,
                sum: Option<u64>,
                buyer: &IdentityPublicData,
            ) -> bcr_ebill_transport::Result<()>;
            async fn send_bill_recourse_paid_event(
                &self,
                bill_id: &str,
                sum: Option<u64>,
                recoursee: &IdentityPublicData,
            ) -> bcr_ebill_transport::Result<()>;
            async fn send_request_to_action_rejected_event(
                &self,
                bill_id: &str,
                sum: Option<u64>,
                rejected_action: ActionType,
                recipients: Vec<IdentityPublicData>,
            ) -> bcr_ebill_transport::Result<()>;
            async fn send_request_to_action_timed_out_event(
                &self,
                bill_id: &str,
                sum: Option<u64>,
                timed_out_action: ActionType,
                recipients: Vec<IdentityPublicData>,
            ) -> bcr_ebill_transport::Result<()>;
            async fn send_recourse_action_event(
                &self,
                bill_id: &str,
                sum: Option<u64>,
                action: ActionType,
                recipient: &IdentityPublicData,
            ) -> bcr_ebill_transport::Result<()>;
            async fn send_request_to_mint_event(&self, bill: &BitcreditBill) -> bcr_ebill_transport::Result<()>;
            async fn send_new_quote_event(&self, quote: &BitcreditBill) -> bcr_ebill_transport::Result<()>;
            async fn send_quote_is_approved_event(&self, quote: &BitcreditBill) -> bcr_ebill_transport::Result<()>;
            async fn get_client_notifications(
                &self,
                filter: NotificationFilter,
            ) -> bcr_ebill_transport::Result<Vec<Notification>>;
            async fn mark_notification_as_done(&self, notification_id: &str) -> bcr_ebill_transport::Result<()>;
            async fn get_active_bill_notification(&self, bill_id: &str) -> Option<Notification>;
            async fn check_bill_notification_sent(
                &self,
                bill_id: &str,
                block_height: i32,
                action: ActionType,
            ) -> bcr_ebill_transport::Result<bool>;
            async fn mark_bill_notification_sent(
                &self,
                bill_id: &str,
                block_height: i32,
                action: ActionType,
            ) -> bcr_ebill_transport::Result<()>;
        }
    }

    pub fn init_test_cfg() {
        match CONFIG.get() {
            Some(_) => (),
            None => {
                crate::init(crate::Config {
                    bitcoin_network: "mainnet".to_string(),
                    nostr_relay: "ws://localhost:8080".to_string(),
                    surreal_db_connection: "ws://localhost:8800".to_string(),
                    data_dir: ".".to_string(),
                })
                .unwrap();
            }
        }
    }

    pub fn empty_address() -> PostalAddress {
        PostalAddress {
            country: "".to_string(),
            city: "".to_string(),
            zip: None,
            address: "".to_string(),
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
            node_id: "".to_string(),
            name: "".to_string(),
            email: "".to_string(),
            postal_address: empty_optional_address(),
            date_of_birth: None,
            country_of_birth: None,
            city_of_birth: None,
            identification_number: None,
            nostr_relay: None,
            profile_picture_file: None,
            identity_document_file: None,
        }
    }

    pub fn empty_identity_public_data() -> IdentityPublicData {
        IdentityPublicData {
            t: ContactType::Person,
            node_id: "".to_string(),
            name: "".to_string(),
            postal_address: empty_address(),
            email: None,
            nostr_relay: None,
        }
    }

    pub fn identity_public_data_only_node_id(node_id: String) -> IdentityPublicData {
        IdentityPublicData {
            t: ContactType::Person,
            node_id,
            name: "".to_string(),
            postal_address: empty_address(),
            email: None,
            nostr_relay: None,
        }
    }

    pub fn empty_bitcredit_bill() -> BitcreditBill {
        BitcreditBill {
            id: "".to_string(),
            country_of_issuing: "".to_string(),
            city_of_issuing: "".to_string(),
            drawee: empty_identity_public_data(),
            drawer: empty_identity_public_data(),
            payee: empty_identity_public_data(),
            endorsee: None,
            currency: "".to_string(),
            sum: 0,
            maturity_date: "".to_string(),
            issue_date: "".to_string(),
            city_of_payment: "".to_string(),
            country_of_payment: "".to_string(),
            language: "".to_string(),
            files: vec![],
        }
    }

    pub const TEST_PUB_KEY_SECP: &str =
        "02295fb5f4eeb2f21e01eaf3a2d9a3be10f39db870d28f02146130317973a40ac0";

    pub const TEST_PRIVATE_KEY_SECP: &str =
        "d1ff7427912d3b81743d3b67ffa1e65df2156d3dab257316cbc8d0f35eeeabe9";

    pub const TEST_NODE_ID_SECP: &str =
        "03205b8dec12bc9e879f5b517aa32192a2550e88adcee3e54ec2c7294802568fef";

    pub const TEST_NODE_ID_SECP_AS_NPUB_HEX: &str =
        "205b8dec12bc9e879f5b517aa32192a2550e88adcee3e54ec2c7294802568fef";
}
