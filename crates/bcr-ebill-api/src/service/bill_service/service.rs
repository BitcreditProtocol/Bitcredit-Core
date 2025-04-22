use super::error::Error;
use super::{BillAction, BillServiceApi, Result};
use crate::blockchain::Blockchain;
use crate::blockchain::bill::block::BillIdentParticipantBlockData;
use crate::blockchain::bill::{BillBlockchain, BillOpCode};
use crate::data::{
    File,
    bill::{
        BillCombinedBitcoinKey, BillKeys, BillRole, BillsBalance, BillsBalanceOverview,
        BillsFilterRole, BitcreditBill, BitcreditBillResult, Endorsement, LightBitcreditBillResult,
        PastEndorsee,
    },
    contact::{BillIdentParticipant, ContactType},
    identity::Identity,
};
use crate::external::bitcoin::BitcoinClientApi;
use crate::get_config;
use crate::persistence::bill::BillChainStoreApi;
use crate::persistence::bill::BillStoreApi;
use crate::persistence::company::{CompanyChainStoreApi, CompanyStoreApi};
use crate::persistence::contact::ContactStoreApi;
use crate::persistence::file_upload::FileUploadStoreApi;
use crate::persistence::identity::{IdentityChainStoreApi, IdentityStoreApi};
use crate::util::BcrKeys;
use crate::{external, util};
use async_trait::async_trait;
use bcr_ebill_core::bill::validation::get_deadline_base_for_req_to_pay;
use bcr_ebill_core::bill::{
    BillIssueData, BillValidateActionData, PastPaymentDataPayment, PastPaymentDataRecourse,
    PastPaymentDataSell, PastPaymentResult, PastPaymentStatus,
};
use bcr_ebill_core::blockchain::bill::block::{BillParticipantBlockData, NodeId};
use bcr_ebill_core::constants::{
    ACCEPT_DEADLINE_SECONDS, PAYMENT_DEADLINE_SECONDS, RECOURSE_DEADLINE_SECONDS,
};
use bcr_ebill_core::contact::{BillAnonParticipant, BillParticipant, Contact};
use bcr_ebill_core::notification::ActionType;
use bcr_ebill_core::util::currency;
use bcr_ebill_core::{ServiceTraitBounds, Validate};
use bcr_ebill_transport::NotificationServiceApi;
use log::{debug, error, info};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// The bill service is responsible for all bill-related logic and for syncing them with the
/// network
#[derive(Clone)]
pub struct BillService {
    pub store: Arc<dyn BillStoreApi>,
    pub blockchain_store: Arc<dyn BillChainStoreApi>,
    pub identity_store: Arc<dyn IdentityStoreApi>,
    pub file_upload_store: Arc<dyn FileUploadStoreApi>,
    pub bitcoin_client: Arc<dyn BitcoinClientApi>,
    pub notification_service: Arc<dyn NotificationServiceApi>,
    pub identity_blockchain_store: Arc<dyn IdentityChainStoreApi>,
    pub company_blockchain_store: Arc<dyn CompanyChainStoreApi>,
    pub contact_store: Arc<dyn ContactStoreApi>,
    pub company_store: Arc<dyn CompanyStoreApi>,
}
impl ServiceTraitBounds for BillService {}

impl BillService {
    pub fn new(
        store: Arc<dyn BillStoreApi>,
        blockchain_store: Arc<dyn BillChainStoreApi>,
        identity_store: Arc<dyn IdentityStoreApi>,
        file_upload_store: Arc<dyn FileUploadStoreApi>,
        bitcoin_client: Arc<dyn BitcoinClientApi>,
        notification_service: Arc<dyn NotificationServiceApi>,
        identity_blockchain_store: Arc<dyn IdentityChainStoreApi>,
        company_blockchain_store: Arc<dyn CompanyChainStoreApi>,
        contact_store: Arc<dyn ContactStoreApi>,
        company_store: Arc<dyn CompanyStoreApi>,
    ) -> Self {
        Self {
            store,
            blockchain_store,
            identity_store,
            file_upload_store,
            bitcoin_client,
            notification_service,
            identity_blockchain_store,
            company_blockchain_store,
            contact_store,
            company_store,
        }
    }

    /// Recalculates the full bill and updates it in the cache
    pub(super) async fn recalculate_and_persist_bill(
        &self,
        bill_id: &str,
        chain: &BillBlockchain,
        bill_keys: &BillKeys,
        local_identity: &Identity,
        current_identity_node_id: &str,
        current_timestamp: u64,
    ) -> Result<()> {
        let calculated_bill = self
            .calculate_full_bill(
                chain,
                bill_keys,
                local_identity,
                current_identity_node_id,
                current_timestamp,
            )
            .await?;
        self.store
            .save_bill_to_cache(bill_id, &calculated_bill)
            .await?;
        Ok(())
    }

    pub(super) async fn extend_bill_chain_participant_data_from_contacts_or_identity(
        &self,
        chain_identity: BillParticipantBlockData,
        identity: &Identity,
        contacts: &HashMap<String, Contact>,
    ) -> BillParticipant {
        match chain_identity {
            BillParticipantBlockData::Ident(data) => BillParticipant::Ident(
                self.extend_bill_chain_identity_data_from_contacts_or_identity(
                    data, identity, contacts,
                )
                .await,
            ),
            BillParticipantBlockData::Anon(data) => {
                let (email, nostr_relay) = self
                    .get_email_and_nostr_relay(
                        &data.node_id,
                        // treat anon as person, since they can't be one of our companies
                        ContactType::Person,
                        identity,
                        contacts,
                    )
                    .await;
                BillParticipant::Anon(BillAnonParticipant {
                    node_id: data.node_id,
                    email,
                    nostr_relay,
                })
            }
        }
    }

    /// If it's our identity, we take the fields from there, otherwise we check contacts,
    /// companies, or leave them empty
    pub(super) async fn extend_bill_chain_identity_data_from_contacts_or_identity(
        &self,
        chain_identity: BillIdentParticipantBlockData,
        identity: &Identity,
        contacts: &HashMap<String, Contact>,
    ) -> BillIdentParticipant {
        let (email, nostr_relay) = self
            .get_email_and_nostr_relay(
                &chain_identity.node_id,
                chain_identity.t.clone(),
                identity,
                contacts,
            )
            .await;
        BillIdentParticipant {
            t: chain_identity.t,
            node_id: chain_identity.node_id,
            name: chain_identity.name,
            postal_address: chain_identity.postal_address,
            email,
            nostr_relay,
        }
    }

    async fn get_email_and_nostr_relay(
        &self,
        node_id: &str,
        t: ContactType,
        identity: &Identity,
        contacts: &HashMap<String, Contact>,
    ) -> (Option<String>, Option<String>) {
        match node_id {
            v if v == identity.node_id => {
                (Some(identity.email.clone()), identity.nostr_relay.clone())
            }
            other_node_id => {
                if let Some(contact) = contacts.get(other_node_id) {
                    (
                        Some(contact.email.clone()),
                        contact.nostr_relays.first().cloned(),
                    )
                } else if t == ContactType::Company {
                    if let Ok(company) = self.company_store.get(other_node_id).await {
                        (
                            Some(company.email.clone()),
                            identity.nostr_relay.clone(), // if it's a local company, we take our relay
                        )
                    } else {
                        (None, None)
                    }
                } else {
                    (None, None)
                }
            }
        }
    }

    async fn check_bill_timeouts(&self, bill_id: &str, now: u64) -> Result<()> {
        let chain = self.blockchain_store.get_chain(bill_id).await?;
        let bill_keys = self.store.get_keys(bill_id).await?;
        let latest_ts = chain.get_latest_block().timestamp;
        let contacts = self.contact_store.get_map().await?;

        if let Some(action) = match chain.get_latest_block().op_code {
            BillOpCode::RequestToPay | BillOpCode::OfferToSell
                if (latest_ts + PAYMENT_DEADLINE_SECONDS <= now) =>
            {
                Some(ActionType::PayBill)
            }
            BillOpCode::RequestToAccept if (latest_ts + ACCEPT_DEADLINE_SECONDS <= now) => {
                Some(ActionType::AcceptBill)
            }
            BillOpCode::RequestRecourse if (latest_ts + RECOURSE_DEADLINE_SECONDS <= now) => {
                Some(ActionType::RecourseBill)
            }
            _ => None,
        } {
            // did we already send the notification
            let sent = self
                .notification_service
                .check_bill_notification_sent(
                    bill_id,
                    chain.block_height() as i32,
                    action.to_owned(),
                )
                .await?;

            if !sent {
                let identity = self.identity_store.get().await?;
                let current_identity = BillIdentParticipant::new(identity.clone());
                let participants = chain.get_all_nodes_from_bill(&bill_keys)?;
                let mut recipient_options = vec![current_identity];
                let bill = self
                    .get_last_version_bill(&chain, &bill_keys, &identity, &contacts)
                    .await?;

                for node_id in participants {
                    let contact: Option<BillIdentParticipant> =
                        self.contact_store.get(&node_id).await?.map(|c| c.into());
                    recipient_options.push(contact);
                }

                let recipients = recipient_options
                    .into_iter()
                    .flatten()
                    .collect::<Vec<BillIdentParticipant>>();

                self.notification_service
                    .send_request_to_action_timed_out_event(
                        &identity.node_id,
                        bill_id,
                        Some(bill.sum),
                        action.to_owned(),
                        recipients,
                    )
                    .await?;

                // remember we have sent the notification
                self.notification_service
                    .mark_bill_notification_sent(bill_id, chain.block_height() as i32, action)
                    .await?;
            }
        }
        Ok(())
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl BillServiceApi for BillService {
    async fn get_bill_balances(
        &self,
        _currency: &str,
        current_identity_node_id: &str,
    ) -> Result<BillsBalanceOverview> {
        let bills = self.get_bills(current_identity_node_id).await?;

        let mut payer_sum = 0;
        let mut payee_sum = 0;
        let mut contingent_sum = 0;

        for bill in bills {
            if let Ok(sum) = currency::parse_sum(&bill.data.sum) {
                if let Some(bill_role) = bill.get_bill_role_for_node_id(current_identity_node_id) {
                    match bill_role {
                        BillRole::Payee => payee_sum += sum,
                        BillRole::Payer => payer_sum += sum,
                        BillRole::Contingent => contingent_sum += sum,
                    };
                }
            }
        }

        Ok(BillsBalanceOverview {
            payee: BillsBalance {
                sum: currency::sum_to_string(payee_sum),
            },
            payer: BillsBalance {
                sum: currency::sum_to_string(payer_sum),
            },
            contingent: BillsBalance {
                sum: currency::sum_to_string(contingent_sum),
            },
        })
    }

    async fn search_bills(
        &self,
        _currency: &str,
        search_term: &Option<String>,
        date_range_from: Option<u64>,
        date_range_to: Option<u64>,
        role: &BillsFilterRole,
        current_identity_node_id: &str,
    ) -> Result<Vec<LightBitcreditBillResult>> {
        debug!(
            "searching bills with {search_term:?} from {date_range_from:?} to {date_range_to:?} and {role:?}"
        );
        let bills = self.get_bills(current_identity_node_id).await?;
        let mut result = vec![];

        // for now we do the search here - with the quick-fetch table, we can search in surrealDB
        // directly
        for bill in bills {
            // if the bill wasn't issued between from and to, we kick them out
            if let Ok(issue_date_ts) =
                util::date::date_string_to_timestamp(&bill.data.issue_date, None)
            {
                if let Some(from) = date_range_from {
                    if from > issue_date_ts {
                        continue;
                    }
                }
                if let Some(to) = date_range_to {
                    if to < issue_date_ts {
                        continue;
                    }
                }
            }

            let bill_role = match bill.get_bill_role_for_node_id(current_identity_node_id) {
                Some(bill_role) => bill_role,
                None => continue, // node is not in bill - don't add
            };

            match role {
                BillsFilterRole::All => (), // we take all
                BillsFilterRole::Payer => {
                    if bill_role != BillRole::Payer {
                        // payer selected, but node not payer
                        continue;
                    }
                }
                BillsFilterRole::Payee => {
                    if bill_role != BillRole::Payee {
                        // payee selected, but node not payee
                        continue;
                    }
                }
                BillsFilterRole::Contingent => {
                    if bill_role != BillRole::Contingent {
                        // contingent selected, but node not
                        // contingent
                        continue;
                    }
                }
            };

            if let Some(st) = search_term {
                if !bill.search_bill_for_search_term(st) {
                    continue;
                }
            }

            result.push(bill.into());
        }

        Ok(result)
    }

    async fn get_bills(&self, current_identity_node_id: &str) -> Result<Vec<BitcreditBillResult>> {
        let bill_ids = self.store.get_ids().await?;
        let identity = self.identity_store.get().await?;
        let current_timestamp = util::date::now().timestamp() as u64;

        // fetch contacts to get current contact data for participants
        let contacts = self.contact_store.get_map().await?;

        let mut bills = self.store.get_bills_from_cache(&bill_ids).await?;
        // extend identities for cached bills
        for bill in bills.iter_mut() {
            self.extend_bill_identities_from_contacts_or_identity(bill, &identity, &contacts)
                .await;

            // check requests for being expired - if an active req to
            // accept/pay/recourse/sell is expired, we need to recalculate the bill
            if self.check_requests_for_expiration(bill, current_timestamp)? {
                debug!(
                    "Bill cache hit, but needs to recalculate because of request deadline {} - recalculating",
                    &bill.id
                );
                *bill = self
                    .recalculate_and_cache_bill(
                        &bill.id,
                        &identity,
                        current_identity_node_id,
                        current_timestamp,
                    )
                    .await?;
            }
        }

        for bill_id in bill_ids.iter() {
            // if bill was not in cache - recalculate and cache it
            if !bills.iter().any(|bill| *bill_id == bill.id) {
                debug!("Bill {bill_id} was not in the cache - recalculate");
                let calculated_bill = self
                    .recalculate_and_cache_bill(
                        bill_id,
                        &identity,
                        current_identity_node_id,
                        current_timestamp,
                    )
                    .await?;
                bills.push(calculated_bill);
            }
        }

        // fetch active notifications for bills
        let active_notifications = self
            .notification_service
            .get_active_bill_notifications(&bill_ids)
            .await;
        for bill in bills.iter_mut() {
            bill.data.active_notification = active_notifications.get(&bill.id).cloned();
        }

        // only return bills where the current node id is a participant
        Ok(bills
            .into_iter()
            .filter(|b| {
                b.participants
                    .all_participant_node_ids
                    .iter()
                    .any(|p| p == current_identity_node_id)
            })
            .collect())
    }

    async fn get_combined_bitcoin_key_for_bill(
        &self,
        bill_id: &str,
        caller_public_data: &BillIdentParticipant,
        caller_keys: &BcrKeys,
    ) -> Result<BillCombinedBitcoinKey> {
        let chain = self.blockchain_store.get_chain(bill_id).await?;
        let bill_keys = self.store.get_keys(bill_id).await?;

        // if caller is not part of the bill, they can't access it
        if !chain
            .get_all_nodes_from_bill(&bill_keys)?
            .iter()
            .any(|p| p == &caller_public_data.node_id)
        {
            debug!("caller is not a participant of bill {bill_id}");
            return Err(Error::NotFound);
        }

        // The first key is always the bill key
        let private_key = self.bitcoin_client.get_combined_private_key(
            &BcrKeys::from_private_key(&bill_keys.private_key)?
                .get_bitcoin_private_key(get_config().bitcoin_network()),
            &caller_keys.get_bitcoin_private_key(get_config().bitcoin_network()),
        )?;
        return Ok(BillCombinedBitcoinKey { private_key });
    }

    async fn get_detail(
        &self,
        bill_id: &str,
        identity: &Identity,
        current_identity_node_id: &str,
        current_timestamp: u64,
    ) -> Result<BitcreditBillResult> {
        let res = self
            .get_full_bill(
                bill_id,
                identity,
                current_identity_node_id,
                current_timestamp,
            )
            .await?;
        // if currently active identity is not part of the bill, we can't access it
        if !res
            .participants
            .all_participant_node_ids
            .iter()
            .any(|p| p == current_identity_node_id)
        {
            return Err(Error::NotFound);
        }
        Ok(res)
    }

    async fn get_bill_keys(&self, bill_id: &str) -> Result<BillKeys> {
        if !self.store.exists(bill_id).await {
            return Err(Error::NotFound);
        }
        let keys = self.store.get_keys(bill_id).await?;
        Ok(keys)
    }

    async fn open_and_decrypt_attached_file(
        &self,
        bill_id: &str,
        file_name: &str,
        bill_private_key: &str,
    ) -> Result<Vec<u8>> {
        debug!("getting file {file_name} for bill with id: {bill_id}");
        let read_file = self
            .file_upload_store
            .open_attached_file(bill_id, file_name)
            .await?;
        let decrypted = util::crypto::decrypt_ecies(&read_file, bill_private_key)?;
        Ok(decrypted)
    }

    async fn encrypt_and_save_uploaded_file(
        &self,
        file_name: &str,
        file_bytes: &[u8],
        bill_id: &str,
        bill_public_key: &str,
    ) -> Result<File> {
        let file_hash = util::sha256_hash(file_bytes);
        let encrypted = util::crypto::encrypt_ecies(file_bytes, bill_public_key)?;
        self.file_upload_store
            .save_attached_file(&encrypted, bill_id, file_name)
            .await?;
        info!("Saved file {file_name} with hash {file_hash} for bill {bill_id}");
        Ok(File {
            name: file_name.to_owned(),
            hash: file_hash,
        })
    }

    async fn issue_new_bill(&self, data: BillIssueData) -> Result<BitcreditBill> {
        self.issue_bill(data).await
    }

    async fn execute_bill_action(
        &self,
        bill_id: &str,
        bill_action: BillAction,
        signer_public_data: &BillIdentParticipant,
        signer_keys: &BcrKeys,
        timestamp: u64,
    ) -> Result<BillBlockchain> {
        debug!(
            "Executing bill action {:?} for bill {bill_id}",
            &bill_action
        );
        // fetch data
        let identity = self.identity_store.get_full().await?;
        let contacts = self.contact_store.get_map().await?;
        let mut blockchain = self.blockchain_store.get_chain(bill_id).await?;
        let bill_keys = self.store.get_keys(bill_id).await?;
        let bill = self
            .get_last_version_bill(&blockchain, &bill_keys, &identity.identity, &contacts)
            .await?;
        let is_paid = self.store.is_paid(bill_id).await?;

        // validate
        BillValidateActionData {
            blockchain: blockchain.clone(),
            drawee_node_id: bill.drawee.node_id.clone(),
            payee_node_id: bill.payee.node_id().clone(),
            endorsee_node_id: bill.endorsee.clone().map(|e| e.node_id()),
            maturity_date: bill.maturity_date.clone(),
            bill_keys: bill_keys.clone(),
            timestamp,
            signer_node_id: signer_public_data.node_id.clone(),
            bill_action: bill_action.clone(),
            is_paid,
        }
        .validate()?;

        // create and sign blocks
        self.create_blocks_for_bill_action(
            &bill,
            &mut blockchain,
            &bill_keys,
            &bill_action,
            &BillParticipant::Ident(signer_public_data.clone()), // TODO: support anon
            signer_keys,
            &identity,
            timestamp,
        )
        .await?;

        // Calculate bill and persist it to cache
        self.recalculate_and_persist_bill(
            bill_id,
            &blockchain,
            &bill_keys,
            &identity.identity,
            &signer_public_data.node_id,
            timestamp,
        )
        .await?;

        // notify and propagate blocks
        self.notify_for_block_action(
            &blockchain,
            &bill_keys,
            &bill_action,
            &identity.identity,
            &contacts,
        )
        .await?;

        debug!("Executed bill action {:?} for bill {bill_id}", &bill_action);

        Ok(blockchain)
    }

    async fn check_bills_payment(&self) -> Result<()> {
        let identity = self.identity_store.get().await?;
        let bill_ids_waiting_for_payment = self.store.get_bill_ids_waiting_for_payment().await?;

        for bill_id in bill_ids_waiting_for_payment {
            if let Err(e) = self.check_bill_payment(&bill_id, &identity).await {
                error!("Checking bill payment for {bill_id} failed: {e}");
            }
        }
        Ok(())
    }

    async fn check_bills_offer_to_sell_payment(&self) -> Result<()> {
        let identity = self.identity_store.get_full().await?;
        let bill_ids_waiting_for_offer_to_sell_payment =
            self.store.get_bill_ids_waiting_for_sell_payment().await?;
        let now = external::time::TimeApi::get_atomic_time().await.timestamp;

        for bill_id in bill_ids_waiting_for_offer_to_sell_payment {
            if let Err(e) = self
                .check_bill_offer_to_sell_payment(&bill_id, &identity, now)
                .await
            {
                error!("Checking offer to sell payment for {bill_id} failed: {e}");
            }
        }
        Ok(())
    }

    async fn check_bills_in_recourse_payment(&self) -> Result<()> {
        let identity = self.identity_store.get_full().await?;
        let bill_ids_waiting_for_recourse_payment = self
            .store
            .get_bill_ids_waiting_for_recourse_payment()
            .await?;
        let now = external::time::TimeApi::get_atomic_time().await.timestamp;

        for bill_id in bill_ids_waiting_for_recourse_payment {
            if let Err(e) = self
                .check_bill_in_recourse_payment(&bill_id, &identity, now)
                .await
            {
                error!("Checking recourse payment for {bill_id} failed: {e}");
            }
        }
        Ok(())
    }

    async fn check_bills_timeouts(&self, now: u64) -> Result<()> {
        let op_codes = HashSet::from([
            BillOpCode::RequestToPay,
            BillOpCode::OfferToSell,
            BillOpCode::RequestToAccept,
            BillOpCode::RequestRecourse,
        ]);

        let bill_ids_to_check = self
            .store
            .get_bill_ids_with_op_codes_since(op_codes, 0)
            .await?;

        for bill_id in bill_ids_to_check {
            if let Err(e) = self.check_bill_timeouts(&bill_id, now).await {
                error!("Checking bill timeouts for {bill_id} failed: {e}");
            }
        }

        Ok(())
    }

    async fn get_past_endorsees(
        &self,
        bill_id: &str,
        current_identity_node_id: &str,
    ) -> Result<Vec<PastEndorsee>> {
        if !self.store.exists(bill_id).await {
            return Err(Error::NotFound);
        }

        let chain = self.blockchain_store.get_chain(bill_id).await?;
        let bill_keys = self.store.get_keys(bill_id).await?;

        let bill_participants = chain.get_all_nodes_from_bill(&bill_keys)?;
        // active identity is not part of the bill
        if !bill_participants
            .iter()
            .any(|p| p == current_identity_node_id)
        {
            debug!("caller is not a participant of bill {bill_id}");
            return Err(Error::NotFound);
        }

        let res = chain.get_past_endorsees_for_bill(&bill_keys, current_identity_node_id)?;
        Ok(res)
    }

    async fn get_past_payments(
        &self,
        bill_id: &str,
        caller_public_data: &BillIdentParticipant,
        caller_keys: &BcrKeys,
        timestamp: u64,
    ) -> Result<Vec<PastPaymentResult>> {
        if !self.store.exists(bill_id).await {
            return Err(Error::NotFound);
        }

        let mut result = vec![];

        let chain = self.blockchain_store.get_chain(bill_id).await?;
        let bill_keys = self.store.get_keys(bill_id).await?;
        let is_paid = self.store.is_paid(bill_id).await?;
        let bill = chain.get_first_version_bill(&bill_keys)?;
        let bill_parties = chain.get_bill_parties(&bill_keys, &bill)?;

        let holder = match bill_parties.endorsee {
            None => &bill_parties.payee,
            Some(ref endorsee) => endorsee,
        };

        let private_key_to_spend = self.bitcoin_client.get_combined_private_key(
            &BcrKeys::from_private_key(&bill_keys.private_key)?
                .get_bitcoin_private_key(get_config().bitcoin_network()),
            &caller_keys.get_bitcoin_private_key(get_config().bitcoin_network()),
        )?;

        // Request to Pay
        if holder.node_id() == caller_public_data.node_id {
            if let Some(req_to_pay) =
                chain.get_last_version_block_with_op_code(BillOpCode::RequestToPay)
            {
                let address_to_pay = self
                    .bitcoin_client
                    .get_address_to_pay(&bill_keys.public_key, &holder.node_id())?;
                let link_to_pay = self.bitcoin_client.generate_link_to_pay(
                    &address_to_pay,
                    bill.sum,
                    &format!("Payment in relation to a bill {}", bill.id.clone()),
                );
                let mempool_link_for_address_to_pay = self
                    .bitcoin_client
                    .get_mempool_link_for_address(&address_to_pay);

                let deadline_base =
                    get_deadline_base_for_req_to_pay(req_to_pay.timestamp, &bill.maturity_date)?;
                let is_expired = util::date::check_if_deadline_has_passed(
                    deadline_base,
                    timestamp,
                    PAYMENT_DEADLINE_SECONDS,
                );
                let is_rejected = chain.block_with_operation_code_exists(BillOpCode::RejectToPay);

                if is_paid || is_rejected || is_expired {
                    result.push(PastPaymentResult::Payment(PastPaymentDataPayment {
                        time_of_request: req_to_pay.timestamp,
                        payer: bill_parties.drawee.clone().into(),
                        payee: holder.clone().into(),
                        currency: bill.currency.clone(),
                        sum: currency::sum_to_string(bill.sum),
                        link_to_pay,
                        address_to_pay,
                        private_key_to_spend: private_key_to_spend.clone(),
                        mempool_link_for_address_to_pay,
                        status: if is_paid {
                            PastPaymentStatus::Paid(req_to_pay.timestamp)
                        } else if is_rejected {
                            let ts = if let Some(reject_to_pay_block) =
                                chain.get_last_version_block_with_op_code(BillOpCode::RejectToPay)
                            {
                                reject_to_pay_block.timestamp
                            } else {
                                req_to_pay.timestamp
                            };
                            PastPaymentStatus::Rejected(ts)
                        } else {
                            PastPaymentStatus::Expired(
                                req_to_pay.timestamp + PAYMENT_DEADLINE_SECONDS,
                            )
                        },
                    }));
                }
            }
        }

        // OfferToSell
        let past_sell_payments = chain.get_past_sell_payments_for_node_id(
            &bill_keys,
            &caller_public_data.node_id,
            timestamp,
        )?;
        for past_sell_payment in past_sell_payments {
            let address_to_pay = past_sell_payment.0.payment_address;
            let link_to_pay = self.bitcoin_client.generate_link_to_pay(
                &address_to_pay,
                past_sell_payment.0.sum,
                &format!("Payment in relation to a bill {}", &bill.id),
            );
            let mempool_link_for_address_to_pay = self
                .bitcoin_client
                .get_mempool_link_for_address(&address_to_pay);

            result.push(PastPaymentResult::Sell(PastPaymentDataSell {
                time_of_request: past_sell_payment.2,
                buyer: past_sell_payment.0.buyer,
                seller: past_sell_payment.0.seller,
                currency: past_sell_payment.0.currency,
                sum: currency::sum_to_string(past_sell_payment.0.sum),
                link_to_pay,
                address_to_pay,
                private_key_to_spend: private_key_to_spend.clone(),
                mempool_link_for_address_to_pay,
                status: past_sell_payment.1,
            }));
        }

        // Recourse
        let past_recourse_payments = chain.get_past_recourse_payments_for_node_id(
            &bill_keys,
            &caller_public_data.node_id,
            timestamp,
        )?;
        for past_sell_payment in past_recourse_payments {
            let address_to_pay = self.bitcoin_client.get_address_to_pay(
                &bill_keys.public_key,
                &past_sell_payment.0.recourser.node_id,
            )?;
            let link_to_pay = self.bitcoin_client.generate_link_to_pay(
                &address_to_pay,
                past_sell_payment.0.sum,
                &format!("Payment in relation to a bill {}", &bill.id),
            );
            let mempool_link_for_address_to_pay = self
                .bitcoin_client
                .get_mempool_link_for_address(&address_to_pay);

            result.push(PastPaymentResult::Recourse(PastPaymentDataRecourse {
                time_of_request: past_sell_payment.2,
                recoursee: past_sell_payment.0.recoursee.into(),
                recourser: past_sell_payment.0.recourser.into(),
                currency: past_sell_payment.0.currency,
                sum: currency::sum_to_string(past_sell_payment.0.sum),
                link_to_pay,
                address_to_pay,
                private_key_to_spend: private_key_to_spend.clone(),
                mempool_link_for_address_to_pay,
                status: past_sell_payment.1,
            }));
        }

        Ok(result)
    }

    async fn get_endorsements(
        &self,
        bill_id: &str,
        current_identity_node_id: &str,
    ) -> Result<Vec<Endorsement>> {
        if !self.store.exists(bill_id).await {
            return Err(Error::NotFound);
        }

        let chain = self.blockchain_store.get_chain(bill_id).await?;
        let bill_keys = self.store.get_keys(bill_id).await?;

        let bill_participants = chain.get_all_nodes_from_bill(&bill_keys)?;
        // active identity is not part of the bill
        if !bill_participants
            .iter()
            .any(|p| p == current_identity_node_id)
        {
            debug!("caller is not a participant of bill {bill_id}");
            return Err(Error::NotFound);
        }

        let result = chain.get_endorsements_for_bill(&bill_keys);
        Ok(result)
    }

    async fn clear_bill_cache(&self) -> Result<()> {
        self.store.clear_bill_cache().await?;
        Ok(())
    }
}
