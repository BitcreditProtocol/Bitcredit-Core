use super::error::Error;
use super::{BillAction, BillServiceApi, Result};
use crate::blockchain::Blockchain;
use crate::blockchain::bill::block::BillIdentParticipantBlockData;
use crate::blockchain::bill::{BillBlockchain, BillOpCode};
use crate::constants::CURRENCY_SAT;
use crate::data::{
    NodeId, SecretKey,
    bill::{
        BillCombinedBitcoinKey, BillId, BillKeys, BillRole, BillsBalance, BillsBalanceOverview,
        BillsFilterRole, BitcreditBill, BitcreditBillResult, Endorsement, LightBitcreditBillResult,
        PastEndorsee,
    },
    contact::{BillIdentParticipant, ContactType},
    identity::Identity,
};
use crate::data::{validate_bill_id_network, validate_node_id_network};
use crate::external::bitcoin::BitcoinClientApi;
use crate::external::court::CourtClientApi;
use crate::external::file_storage::{self, FileStorageClientApi};
use crate::external::mint::{MintClientApi, QuoteStatusReply, ResolveMintOffer};
use crate::get_config;
use crate::persistence::bill::BillChainStoreApi;
use crate::persistence::bill::BillStoreApi;
use crate::persistence::company::{CompanyChainStoreApi, CompanyStoreApi};
use crate::persistence::contact::ContactStoreApi;
use crate::persistence::file_upload::FileUploadStoreApi;
use crate::persistence::identity::{IdentityChainStoreApi, IdentityStoreApi};
use crate::service::notification_service::NotificationServiceApi;
use crate::util::BcrKeys;
use crate::util::file::UploadFileType;
use crate::{external, util};
use async_trait::async_trait;
use bcr_ebill_core::bill::{
    BillIssueData, BillValidateActionData, PastPaymentDataPayment, PastPaymentDataRecourse,
    PastPaymentDataSell, PastPaymentResult, PastPaymentStatus, PaymentState,
};
use bcr_ebill_core::blockchain::bill::block::{
    BillParticipantBlockData, BillRequestRecourseBlockData,
};
use bcr_ebill_core::blockchain::bill::chain::BillBlockPlaintextWrapper;
use bcr_ebill_core::blockchain::bill::create_bill_to_share_with_external_party;
use bcr_ebill_core::company::{Company, CompanyKeys};
use bcr_ebill_core::contact::{
    BillAnonParticipant, BillParticipant, Contact, LightBillParticipant,
};
use bcr_ebill_core::email::Email;
use bcr_ebill_core::identity::{IdentityType, IdentityWithAll};
use bcr_ebill_core::mint::{MintRequest, MintRequestState, MintRequestStatus};
use bcr_ebill_core::notification::ActionType;
use bcr_ebill_core::util::currency;
use bcr_ebill_core::{File, ServiceTraitBounds, Validate, ValidationError};
use bcr_ebill_persistence::mint::MintStoreApi;
use bcr_ebill_persistence::nostr::NostrContactStoreApi;
use log::{debug, error, info, warn};
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
    pub file_upload_client: Arc<dyn FileStorageClientApi>,
    pub bitcoin_client: Arc<dyn BitcoinClientApi>,
    pub notification_service: Arc<dyn NotificationServiceApi>,
    pub identity_blockchain_store: Arc<dyn IdentityChainStoreApi>,
    pub company_blockchain_store: Arc<dyn CompanyChainStoreApi>,
    pub contact_store: Arc<dyn ContactStoreApi>,
    pub company_store: Arc<dyn CompanyStoreApi>,
    pub mint_store: Arc<dyn MintStoreApi>,
    pub mint_client: Arc<dyn MintClientApi>,
    pub court_client: Arc<dyn CourtClientApi>,
    pub nostr_contact_store: Arc<dyn NostrContactStoreApi>,
}
impl ServiceTraitBounds for BillService {}

impl BillService {
    pub fn new(
        store: Arc<dyn BillStoreApi>,
        blockchain_store: Arc<dyn BillChainStoreApi>,
        identity_store: Arc<dyn IdentityStoreApi>,
        file_upload_store: Arc<dyn FileUploadStoreApi>,
        file_upload_client: Arc<dyn FileStorageClientApi>,
        bitcoin_client: Arc<dyn BitcoinClientApi>,
        notification_service: Arc<dyn NotificationServiceApi>,
        identity_blockchain_store: Arc<dyn IdentityChainStoreApi>,
        company_blockchain_store: Arc<dyn CompanyChainStoreApi>,
        contact_store: Arc<dyn ContactStoreApi>,
        company_store: Arc<dyn CompanyStoreApi>,
        mint_store: Arc<dyn MintStoreApi>,
        mint_client: Arc<dyn MintClientApi>,
        court_client: Arc<dyn CourtClientApi>,
        nostr_contact_store: Arc<dyn NostrContactStoreApi>,
    ) -> Self {
        Self {
            store,
            blockchain_store,
            identity_store,
            file_upload_store,
            file_upload_client,
            bitcoin_client,
            notification_service,
            identity_blockchain_store,
            company_blockchain_store,
            contact_store,
            company_store,
            mint_store,
            mint_client,
            court_client,
            nostr_contact_store,
        }
    }

    /// Recalculates the full bill and updates it in the cache
    pub(super) async fn recalculate_and_persist_bill(
        &self,
        bill_id: &BillId,
        chain: &BillBlockchain,
        bill_keys: &BillKeys,
        local_identity: &Identity,
        current_identity_node_id: &NodeId,
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
            .save_bill_to_cache(bill_id, current_identity_node_id, &calculated_bill)
            .await?;
        Ok(())
    }

    pub(super) async fn extend_bill_chain_participant_data_from_contacts_or_identity(
        &self,
        chain_identity: BillParticipantBlockData,
        identity: &Identity,
        contacts: &HashMap<NodeId, Contact>,
    ) -> BillParticipant {
        match chain_identity {
            BillParticipantBlockData::Ident(data) => BillParticipant::Ident(
                self.extend_bill_chain_identity_data_from_contacts_or_identity(
                    data, identity, contacts,
                )
                .await,
            ),
            BillParticipantBlockData::Anon(data) => {
                let (email, nostr_relays) = self
                    .get_email_and_nostr_relay(&data.node_id, ContactType::Anon, identity, contacts)
                    .await;
                BillParticipant::Anon(BillAnonParticipant {
                    node_id: data.node_id,
                    email,
                    nostr_relays,
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
        contacts: &HashMap<NodeId, Contact>,
    ) -> BillIdentParticipant {
        let (email, nostr_relays) = self
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
            nostr_relays,
        }
    }

    async fn get_email_and_nostr_relay(
        &self,
        node_id: &NodeId,
        t: ContactType,
        identity: &Identity,
        contacts: &HashMap<NodeId, Contact>,
    ) -> (Option<Email>, Vec<url::Url>) {
        match node_id {
            v if *v == identity.node_id => (identity.email.clone(), identity.nostr_relays.clone()),
            other_node_id => {
                if let Some(contact) = contacts.get(other_node_id) {
                    (contact.email.clone(), contact.nostr_relays.clone())
                } else if t == ContactType::Company {
                    if let Ok(company) = self.company_store.get(other_node_id).await {
                        (
                            Some(company.email.clone()),
                            identity.nostr_relays.clone(), // if it's a local company, we take our relay
                        )
                    } else {
                        (None, vec![])
                    }
                } else if let Ok(Some(nostr_contact)) =
                    self.nostr_contact_store.by_node_id(node_id).await
                {
                    (None, nostr_contact.relays)
                } else {
                    (None, vec![])
                }
            }
        }
    }

    async fn check_bill_timeouts(&self, bill_id: &BillId, now: u64) -> Result<()> {
        let chain = self.blockchain_store.get_chain(bill_id).await?;
        let bill_keys = self.store.get_keys(bill_id).await?;
        let contacts = self.contact_store.get_map().await?;
        let mut recoursee = None;
        let bill_data = chain.get_first_version_bill(&bill_keys)?;

        let latest_block = chain.get_latest_block();
        if let Some(action) = match latest_block.op_code {
            BillOpCode::RequestToPay
                if chain
                    .is_req_to_pay_block_payment_expired(
                        latest_block,
                        &bill_keys,
                        now,
                        Some(&bill_data.maturity_date),
                    )?
                    .0 =>
            {
                Some(ActionType::PayBill)
            }
            BillOpCode::OfferToSell
                if chain
                    .is_offer_to_sell_block_payment_expired(latest_block, &bill_keys, now)?
                    .0 =>
            {
                Some(ActionType::PayBill)
            }

            BillOpCode::RequestToAccept
                if chain
                    .is_req_to_accept_block_payment_expired(latest_block, &bill_keys, now)?
                    .0 =>
            {
                Some(ActionType::AcceptBill)
            }
            BillOpCode::RequestRecourse
                if chain
                    .is_req_to_recourse_block_payment_expired(latest_block, &bill_keys, now)?
                    .0 =>
            {
                if let Ok(recourse_block) =
                    latest_block.get_decrypted_block::<BillRequestRecourseBlockData>(&bill_keys)
                {
                    recoursee = Some(recourse_block.recoursee.node_id());
                }
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
                let current_identity = match identity.t {
                    IdentityType::Ident => BillIdentParticipant::new(identity.clone())
                        .map(BillParticipant::Ident)
                        .ok(),
                    IdentityType::Anon => Some(BillParticipant::Anon(BillAnonParticipant::new(
                        identity.clone(),
                    ))),
                };
                let participants = chain.get_all_nodes_from_bill(&bill_keys)?;
                let mut recipient_options: Vec<Option<BillParticipant>> = vec![current_identity];
                let bill = self
                    .get_last_version_bill(&chain, &bill_keys, &identity, &contacts)
                    .await?;

                let holder = bill.endorsee.as_ref().unwrap_or(&bill.payee).node_id();
                let drawee = &bill.drawee.node_id;

                for node_id in participants {
                    if let Some(contact) = self.contact_store.get(&node_id).await? {
                        recipient_options.push(Some(contact.try_into()?));
                    }
                }

                let recipients = recipient_options
                    .into_iter()
                    .flatten()
                    .collect::<Vec<BillParticipant>>();

                self.notification_service
                    .send_request_to_action_timed_out_event(
                        &identity.node_id, // TODO(company-notifications): how to handle jobs as company participant?
                        bill_id,
                        Some(bill.sum),
                        action.to_owned(),
                        recipients,
                        &holder,
                        drawee,
                        &recoursee,
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

    /// Checks a given mint quote and updates the bill mint state, if there was a change
    pub(super) async fn check_mint_quote_and_update_bill_mint_state(
        &self,
        mint_request: &MintRequest,
    ) -> Result<()> {
        debug!(
            "Checking mint request for quote {}",
            &mint_request.mint_request_id
        );
        let mint_cfg = &get_config().mint_config;
        // for now, we only support the default mint
        if mint_request.mint_node_id != mint_cfg.default_mint_node_id {
            return Ok(());
        }

        match mint_request.status {
            // If it's accepted, get the offer and, if it's not finished (i.e. has no proofs), attempt to get keyset and mint
            MintRequestStatus::Accepted => {
                if let Ok(Some(offer)) = self
                    .mint_store
                    .get_offer(&mint_request.mint_request_id)
                    .await
                {
                    // only if there are no proofs yet and proofs are not spent
                    if offer.proofs.is_none() && !offer.proofs_spent {
                        debug!(
                            "Checking for keyset info for {}",
                            &mint_request.mint_request_id
                        );
                        // not finished - check keyset and try to mint and create tokens and persist
                        match self
                            .mint_client
                            .get_keyset_info(&mint_cfg.default_mint_url, &offer.keyset_id)
                            .await
                        {
                            // keyset info is available
                            Ok(keyset_info) => {
                                // fetch private key for requester
                                let private_key = match self.identity_store.get_full().await {
                                    Ok(identity) => {
                                        // check if requester is identity
                                        if identity.identity.node_id
                                            == mint_request.requester_node_id
                                        {
                                            identity.key_pair.get_private_key()
                                        } else {
                                            // check if requester is a company
                                            let local_companies: HashMap<
                                                NodeId,
                                                (Company, CompanyKeys),
                                            > = self.company_store.get_all().await?;
                                            if let Some(requester_company) =
                                                local_companies.get(&mint_request.requester_node_id)
                                            {
                                                requester_company.1.private_key
                                            } else {
                                                // requester is neither identity, nor company
                                                log::warn!(
                                                    "Requester for {} is not a local identity, or company",
                                                    &mint_request.mint_request_id
                                                );
                                                return Ok(());
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        return Err(e.into());
                                    }
                                };
                                debug!(
                                    "Keyset found and minting for {}",
                                    &mint_request.mint_request_id
                                );
                                // generate blinds
                                let (blinded_messages, secrets, rs) =
                                    external::mint::generate_blinds(
                                        keyset_info.id,
                                        offer.discounted_sum,
                                    )?;
                                // persist recovery data in case something goes wrong after minting
                                // getting here a second time for this offer will fail, which is OK
                                // since it means that either minting, or proof creation failed and we can't
                                // detect which one reliably
                                // with the secrets and rs, we can re-create the blinded messages and get
                                // blinded signatures from the mint using the mint, OR the recovery endpoint
                                self.mint_store
                                    .add_recovery_data_to_offer(
                                        &mint_request.mint_request_id,
                                        &secrets
                                            .iter()
                                            .map(|s| s.to_string())
                                            .collect::<Vec<String>>(),
                                        &rs.iter().map(|r| r.to_string()).collect::<Vec<String>>(),
                                    )
                                    .await?;
                                // mint and generate proofs
                                let proofs = self
                                    .mint_client
                                    .mint(
                                        &mint_cfg.default_mint_url,
                                        keyset_info,
                                        &mint_request.mint_request_id,
                                        &private_key,
                                        blinded_messages,
                                        secrets,
                                        rs,
                                    )
                                    .await?;
                                // store proofs on the offer
                                self.mint_store
                                    .add_proofs_to_offer(&mint_request.mint_request_id, &proofs)
                                    .await?;
                            }
                            Err(_) => {
                                info!("No keyset available for {}", mint_request.mint_request_id);
                            }
                        };
                    } else if offer.proofs.is_some() && !offer.proofs_spent {
                        debug!(
                            "Checking if proofs for {} are spent",
                            &mint_request.mint_request_id
                        );
                        if let Some(proofs) = offer.proofs {
                            match self
                                .mint_client
                                .check_if_proofs_are_spent(
                                    &mint_cfg.default_mint_url,
                                    &proofs,
                                    &offer.keyset_id,
                                )
                                .await
                            {
                                Ok(spent) => {
                                    if spent {
                                        debug!(
                                            "Proofs for {} are spent - updating",
                                            &mint_request.mint_request_id
                                        );
                                        self.mint_store
                                            .set_proofs_to_spent_for_offer(
                                                &mint_request.mint_request_id,
                                            )
                                            .await?;
                                    }
                                }
                                Err(e) => {
                                    error!(
                                        "Could not check if proofs are spent for {}: {e}",
                                        &mint_request.mint_request_id
                                    );
                                }
                            }
                        }
                    } else {
                        // proofs spent - nothing to do
                    }
                }
            }
            MintRequestStatus::Pending | MintRequestStatus::Offered => {
                let updated_status = self
                    .mint_client
                    .lookup_quote_for_mint(
                        &mint_cfg.default_mint_url,
                        &mint_request.mint_request_id,
                    )
                    .await?;
                // only update, if changed
                match updated_status {
                    QuoteStatusReply::Pending => {
                        // it's already pending, or offered and can't go from Offered to Pending - nothing to do
                    }
                    QuoteStatusReply::Offered {
                        keyset_id,
                        expiration_date,
                        discounted,
                    } => {
                        // if it's not already offered, set to offered
                        if !matches!(mint_request.status, MintRequestStatus::Offered) {
                            // Update the request
                            self.mint_store
                                .update_request(
                                    &mint_request.mint_request_id,
                                    &MintRequestStatus::Offered,
                                )
                                .await?;
                            // Store the offer
                            self.mint_store
                                .add_offer(
                                    &mint_request.mint_request_id,
                                    &keyset_id.to_string(),
                                    expiration_date.timestamp() as u64,
                                    discounted.to_sat(),
                                )
                                .await?;
                        }
                    }
                    QuoteStatusReply::Denied { tstamp } => {
                        // checked below, that it's not denied
                        self.mint_store
                            .update_request(
                                &mint_request.mint_request_id,
                                &MintRequestStatus::Denied {
                                    timestamp: tstamp.timestamp() as u64,
                                },
                            )
                            .await?;
                    }
                    QuoteStatusReply::Expired { tstamp } => {
                        // checked below, that it's not expired
                        self.mint_store
                            .update_request(
                                &mint_request.mint_request_id,
                                &MintRequestStatus::Expired {
                                    timestamp: tstamp.timestamp() as u64,
                                },
                            )
                            .await?;
                    }
                    QuoteStatusReply::Cancelled { tstamp } => {
                        // checked below, that it's not cancelled
                        self.mint_store
                            .update_request(
                                &mint_request.mint_request_id,
                                &MintRequestStatus::Cancelled {
                                    timestamp: tstamp.timestamp() as u64,
                                },
                            )
                            .await?;
                    }
                    QuoteStatusReply::Rejected { tstamp } => {
                        // checked below, that it's not rejected
                        self.mint_store
                            .update_request(
                                &mint_request.mint_request_id,
                                &MintRequestStatus::Rejected {
                                    timestamp: tstamp.timestamp() as u64,
                                },
                            )
                            .await?;
                    }
                    QuoteStatusReply::Accepted { .. } => {
                        // checked above, that it's not accepted
                        self.mint_store
                            .update_request(
                                &mint_request.mint_request_id,
                                &MintRequestStatus::Accepted,
                            )
                            .await?;
                    }
                };
            }
            // Cancelled, Rejected, Expired, Denied
            _ => {
                // Req to mint is finished - nothing to do
            }
        };
        Ok(())
    }

    async fn get_req_to_mint_for_node_id(
        &self,
        mint_request_id: &str,
        current_identity_node_id: &NodeId,
    ) -> Result<MintRequest> {
        match self.mint_store.get_request(mint_request_id).await {
            Ok(Some(req)) => {
                // only if we're the requester
                if req.requester_node_id == *current_identity_node_id {
                    let mint_cfg = &get_config().mint_config;
                    // only for the default mint for now
                    if req.mint_node_id == mint_cfg.default_mint_node_id {
                        Ok(req.to_owned())
                    } else {
                        Err(Error::NotFound)
                    }
                } else {
                    Err(Error::NotFound)
                }
            }
            Ok(None) => Err(Error::NotFound),
            Err(e) => Err(e.into()),
        }
    }

    async fn reject_mint_offers_except_accepted_one_for_bill(
        &self,
        accepted_mint_request_id: &str,
        bill_id: &BillId,
        current_identity_node_id: &NodeId,
    ) -> Result<()> {
        let requests = self
            .mint_store
            .get_requests_for_bill(current_identity_node_id, bill_id)
            .await?;
        for req in requests {
            // don't reject the accepted one and only reject offered ones
            if req.mint_request_id != accepted_mint_request_id
                && matches!(req.status, MintRequestStatus::Offered)
                && let Err(e) = self
                    .mint_client
                    .resolve_quote_for_mint(
                        &get_config().mint_config.default_mint_url,
                        &req.mint_request_id,
                        ResolveMintOffer::Reject,
                    )
                    .await
            {
                error!(
                    "Could not reject quote for mint {}: {e}",
                    req.mint_request_id
                )
            }
        }
        Ok(())
    }

    async fn get_participant_for_mint(
        &self,
        mint_node_id: &NodeId,
        identity: &Identity,
    ) -> BillParticipant {
        let relays = match self
            .notification_service
            .resolve_contact(mint_node_id)
            .await
        {
            Ok(Some(nostr_contact_data)) => nostr_contact_data
                .relays
                .iter()
                .map(|url| url.to_owned().into())
                .collect::<Vec<url::Url>>(),
            _ => {
                // fallback to own relays
                identity.nostr_relays.clone()
            }
        };
        BillParticipant::Anon(BillAnonParticipant {
            node_id: mint_node_id.to_owned(),
            email: None,
            nostr_relays: relays,
        })
    }

    /// Download the files, decrypt them, encrypt and upload them for the given node id
    /// and relay url and return a list of urls to the uploaded files
    async fn upload_bill_files_for_node_id(
        &self,
        bill_id: &BillId,
        bill_private_key: &SecretKey,
        node_id: &NodeId,
        relay_url: &url::Url,
        files: &[File],
    ) -> Result<Vec<url::Url>> {
        if files.is_empty() {
            return Ok(vec![]);
        }
        let mut result = Vec::with_capacity(files.len());
        for file in files {
            let decrypted_file = self
                .open_and_decrypt_attached_file(bill_id, file, bill_private_key)
                .await?;
            let uploaded_file = self
                .encrypt_and_save_uploaded_file(
                    &file.name,
                    &decrypted_file,
                    bill_id,
                    &node_id.pub_key(),
                    relay_url,
                    UploadFileType::Document,
                )
                .await?;
            result.push(file_storage::to_url(relay_url, &uploaded_file.nostr_hash)?);
        }
        Ok(result)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl BillServiceApi for BillService {
    async fn get_bill_balances(
        &self,
        _currency: &str,
        current_identity_node_id: &NodeId,
    ) -> Result<BillsBalanceOverview> {
        validate_node_id_network(current_identity_node_id)?;
        let bills = self.get_bills(current_identity_node_id).await?;

        let mut payer_sum = 0;
        let mut payee_sum = 0;
        let mut contingent_sum = 0;

        for bill in bills {
            if let Ok(sum) = currency::parse_sum(&bill.data.sum)
                && let Some(bill_role) = bill.get_bill_role_for_node_id(current_identity_node_id)
            {
                match bill_role {
                    BillRole::Payee => payee_sum += sum,
                    BillRole::Payer => payer_sum += sum,
                    BillRole::Contingent => {
                        // if we're in the guarantee chain, but only anonymously, we don't count it
                        let endorsements = bill.participants.endorsements;
                        let mut in_guarantee_chain_as_non_anon = false;
                        for endorsement in endorsements.iter() {
                            let holder = &endorsement.pay_to_the_order_of;
                            // we're in the chain as non-anon
                            if &holder.node_id() == current_identity_node_id
                                && matches!(holder, LightBillParticipant::Ident(_))
                            {
                                in_guarantee_chain_as_non_anon = true;
                                break;
                            }
                        }
                        if in_guarantee_chain_as_non_anon
                            || &bill.participants.drawer.node_id == current_identity_node_id
                        {
                            contingent_sum += sum
                        }
                    }
                };
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
        current_identity_node_id: &NodeId,
    ) -> Result<Vec<LightBitcreditBillResult>> {
        debug!(
            "searching bills with {search_term:?} from {date_range_from:?} to {date_range_to:?} and {role:?}"
        );
        validate_node_id_network(current_identity_node_id)?;
        let bills = self.get_bills(current_identity_node_id).await?;
        let mut result = vec![];

        // for now we do the search here - with the quick-fetch table, we can search in surrealDB
        // directly
        for bill in bills {
            // if the bill wasn't issued between from and to, we kick them out
            let issue_date_ts = bill.data.issue_date.to_timestamp();
            if let Some(from) = date_range_from
                && from > issue_date_ts
            {
                continue;
            }
            if let Some(to) = date_range_to
                && to < issue_date_ts
            {
                continue;
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

            if let Some(st) = search_term
                && !bill.search_bill_for_search_term(st)
            {
                continue;
            }

            result.push(bill.into());
        }

        Ok(result)
    }

    async fn get_bills(
        &self,
        current_identity_node_id: &NodeId,
    ) -> Result<Vec<BitcreditBillResult>> {
        validate_node_id_network(current_identity_node_id)?;
        let bill_ids = self.store.get_ids().await?;
        let identity = self.identity_store.get().await?;
        let current_timestamp = util::date::now().timestamp() as u64;

        // fetch contacts to get current contact data for participants
        let contacts = self.contact_store.get_map().await?;

        let mut bills = self
            .store
            .get_bills_from_cache(&bill_ids, current_identity_node_id)
            .await?;
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
        bill_id: &BillId,
        caller_public_data: &BillParticipant,
        caller_keys: &BcrKeys,
    ) -> Result<BillCombinedBitcoinKey> {
        validate_bill_id_network(bill_id)?;
        validate_node_id_network(&caller_public_data.node_id())?;
        let chain = self.blockchain_store.get_chain(bill_id).await?;
        let bill_keys = self.store.get_keys(bill_id).await?;

        // if caller is not part of the bill, they can't access it
        if !chain
            .get_all_nodes_from_bill(&bill_keys)?
            .iter()
            .any(|p| p == &caller_public_data.node_id())
        {
            debug!("caller is not a participant of bill {bill_id}");
            return Err(Error::NotFound);
        }

        // The first key is always the bill key
        let private_descriptor = self.bitcoin_client.get_combined_private_descriptor(
            &BcrKeys::from_private_key(&bill_keys.private_key)?
                .get_bitcoin_private_key(get_config().bitcoin_network()),
            &caller_keys.get_bitcoin_private_key(get_config().bitcoin_network()),
        )?;
        return Ok(BillCombinedBitcoinKey { private_descriptor });
    }

    async fn get_detail(
        &self,
        bill_id: &BillId,
        identity: &Identity,
        current_identity_node_id: &NodeId,
        current_timestamp: u64,
    ) -> Result<BitcreditBillResult> {
        validate_bill_id_network(bill_id)?;
        validate_node_id_network(current_identity_node_id)?;
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

    async fn get_bill_keys(&self, bill_id: &BillId) -> Result<BillKeys> {
        validate_bill_id_network(bill_id)?;
        match self.store.exists(bill_id).await {
            Ok(true) => (),
            _ => {
                return Err(Error::NotFound);
            }
        };
        let keys = self.store.get_keys(bill_id).await?;
        Ok(keys)
    }

    async fn open_and_decrypt_attached_file(
        &self,
        bill_id: &BillId,
        file: &File,
        bill_private_key: &SecretKey,
    ) -> Result<Vec<u8>> {
        debug!("getting file {} for bill with id: {bill_id}", file.name);
        validate_bill_id_network(bill_id)?;
        let nostr_relays = get_config().nostr_config.relays.clone();
        // TODO(multi-relay): don't default to first
        if let Some(nostr_relay) = nostr_relays.first() {
            let file_bytes = self
                .file_upload_client
                .download(nostr_relay, &file.nostr_hash)
                .await?;
            let decrypted = util::crypto::decrypt_ecies(&file_bytes, bill_private_key)?;
            let file_hash = util::sha256_hash(&decrypted);
            if file_hash != file.hash {
                error!(
                    "Hash for bill file {} did not match uploaded file",
                    file.name
                );
                return Err(super::Error::NotFound);
            }
            Ok(decrypted)
        } else {
            return Err(super::Error::NotFound);
        }
    }

    async fn issue_new_bill(&self, data: BillIssueData) -> Result<BitcreditBill> {
        self.issue_bill(data).await
    }

    async fn execute_bill_action(
        &self,
        bill_id: &BillId,
        bill_action: BillAction,
        signer_public_data: &BillParticipant,
        signer_keys: &BcrKeys,
        timestamp: u64,
    ) -> Result<BillBlockchain> {
        debug!(
            "Executing bill action {:?} for bill {bill_id}",
            &bill_action
        );
        validate_bill_id_network(bill_id)?;
        validate_node_id_network(&signer_public_data.node_id())?;
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
            signer_node_id: signer_public_data.node_id().clone(),
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
            &signer_public_data.clone(),
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
            &signer_public_data.node_id(),
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
            &signer_public_data.node_id(),
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

    async fn check_payment_for_bill(&self, bill_id: &BillId, identity: &Identity) -> Result<()> {
        validate_bill_id_network(bill_id)?;
        let bill_ids_waiting_for_payment = self.store.get_bill_ids_waiting_for_payment().await?;

        if bill_ids_waiting_for_payment.iter().any(|id| id == bill_id) {
            if let Err(e) = self.check_bill_payment(bill_id, identity).await {
                error!("Checking bill payment for {bill_id} failed: {e}");
            }
        } else {
            info!("Bill with id {bill_id} is not waiting for payment - not checking payment");
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

    async fn check_offer_to_sell_payment_for_bill(
        &self,
        bill_id: &BillId,
        identity: &IdentityWithAll,
    ) -> Result<()> {
        validate_bill_id_network(bill_id)?;
        let bill_ids_waiting_for_offer_to_sell_payment =
            self.store.get_bill_ids_waiting_for_sell_payment().await?;
        let now = external::time::TimeApi::get_atomic_time().await.timestamp;

        if bill_ids_waiting_for_offer_to_sell_payment
            .iter()
            .any(|id| id == bill_id)
        {
            if let Err(e) = self
                .check_bill_offer_to_sell_payment(bill_id, identity, now)
                .await
            {
                error!("Checking offer to sell payment for {bill_id} failed: {e}");
            }
        } else {
            info!(
                "Bill with id {bill_id} is not waiting for offer to sell payment - not checking payment"
            );
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

    async fn check_recourse_payment_for_bill(
        &self,
        bill_id: &BillId,
        identity: &IdentityWithAll,
    ) -> Result<()> {
        validate_bill_id_network(bill_id)?;
        let bill_ids_waiting_for_recourse_payment = self
            .store
            .get_bill_ids_waiting_for_recourse_payment()
            .await?;
        let now = external::time::TimeApi::get_atomic_time().await.timestamp;

        if bill_ids_waiting_for_recourse_payment
            .iter()
            .any(|id| id == bill_id)
        {
            if let Err(e) = self
                .check_bill_in_recourse_payment(bill_id, identity, now)
                .await
            {
                error!("Checking recourse payment for {bill_id} failed: {e}");
            }
        } else {
            info!(
                "Bill with id {bill_id} is not waiting for recourse payment - not checking payment"
            );
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
        bill_id: &BillId,
        current_identity_node_id: &NodeId,
    ) -> Result<Vec<PastEndorsee>> {
        validate_bill_id_network(bill_id)?;
        validate_node_id_network(current_identity_node_id)?;
        match self.store.exists(bill_id).await {
            Ok(true) => (),
            _ => {
                return Err(Error::NotFound);
            }
        };

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
        bill_id: &BillId,
        caller_public_data: &BillParticipant,
        caller_keys: &BcrKeys,
        timestamp: u64,
    ) -> Result<Vec<PastPaymentResult>> {
        validate_bill_id_network(bill_id)?;
        validate_node_id_network(&caller_public_data.node_id())?;
        match self.store.exists(bill_id).await {
            Ok(true) => (),
            _ => {
                return Err(Error::NotFound);
            }
        };

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

        let descriptor_to_spend = self.bitcoin_client.get_combined_private_descriptor(
            &BcrKeys::from_private_key(&bill_keys.private_key)?
                .get_bitcoin_private_key(get_config().bitcoin_network()),
            &caller_keys.get_bitcoin_private_key(get_config().bitcoin_network()),
        )?;

        // Request to Pay
        if holder.node_id() == caller_public_data.node_id()
            && let Some(req_to_pay) =
                chain.get_last_version_block_with_op_code(BillOpCode::RequestToPay)
        {
            let address_to_pay = self
                .bitcoin_client
                .get_address_to_pay(&bill_keys.public_key, &holder.node_id().pub_key())?;
            let link_to_pay = self.bitcoin_client.generate_link_to_pay(
                &address_to_pay,
                bill.sum,
                &format!("Payment in relation to a bill {}", bill.id.clone()),
            );
            let mempool_link_for_address_to_pay = self
                .bitcoin_client
                .get_mempool_link_for_address(&address_to_pay);

            // we check for the payment expiration, not the request expiration
            // if the request expired, but the payment deadline hasn't, it's not a past payment
            let (is_expired, payment_deadline) = chain.is_req_to_pay_block_payment_expired(
                req_to_pay,
                &bill_keys,
                timestamp,
                Some(&bill.maturity_date),
            )?;

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
                    private_descriptor_to_spend: descriptor_to_spend.clone(),
                    mempool_link_for_address_to_pay,
                    status: if is_paid {
                        if let Ok(Some(PaymentState::PaidConfirmed(paid_date))) =
                            self.store.get_payment_state(bill_id).await
                        {
                            PastPaymentStatus::Paid(paid_date.block_time)
                        } else {
                            // fall back to req to pay time, if we don't have the paid ts
                            PastPaymentStatus::Paid(req_to_pay.timestamp)
                        }
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
                        PastPaymentStatus::Expired(payment_deadline)
                    },
                    payment_deadline,
                }));
            }
        }

        // OfferToSell
        let past_sell_payments = chain.get_past_sell_payments_for_node_id(
            &bill_keys,
            &caller_public_data.node_id(),
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
                private_descriptor_to_spend: descriptor_to_spend.clone(),
                mempool_link_for_address_to_pay,
                status: past_sell_payment.1,
                payment_deadline: past_sell_payment.0.buying_deadline_timestamp,
            }));
        }

        // Recourse
        let past_recourse_payments = chain.get_past_recourse_payments_for_node_id(
            &bill_keys,
            &caller_public_data.node_id(),
            timestamp,
        )?;
        for past_sell_payment in past_recourse_payments {
            let address_to_pay = self.bitcoin_client.get_address_to_pay(
                &bill_keys.public_key,
                &past_sell_payment.0.recourser.node_id().pub_key(),
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
                private_descriptor_to_spend: descriptor_to_spend.clone(),
                mempool_link_for_address_to_pay,
                status: past_sell_payment.1,
                payment_deadline: past_sell_payment.0.recourse_deadline_timestamp,
            }));
        }

        Ok(result)
    }

    async fn get_endorsements(
        &self,
        bill_id: &BillId,
        identity: &Identity,
        current_identity_node_id: &NodeId,
        current_timestamp: u64,
    ) -> Result<Vec<Endorsement>> {
        validate_bill_id_network(bill_id)?;
        validate_node_id_network(current_identity_node_id)?;
        let bill = self
            .get_detail(
                bill_id,
                identity,
                current_identity_node_id,
                current_timestamp,
            )
            .await?;
        let result = bill.participants.endorsements;
        Ok(result)
    }

    async fn clear_bill_cache(&self) -> Result<()> {
        self.store.clear_bill_cache().await?;
        Ok(())
    }

    async fn request_to_mint(
        &self,
        bill_id: &BillId,
        mint_node_id: &NodeId,
        signer_public_data: &BillParticipant,
        signer_keys: &BcrKeys,
        timestamp: u64,
    ) -> Result<()> {
        validate_bill_id_network(bill_id)?;
        validate_node_id_network(&signer_public_data.node_id())?;
        validate_node_id_network(mint_node_id)?;
        debug!("Executing request to mint with mint {mint_node_id} for bill {bill_id}");
        let mint_cfg = &get_config().mint_config;
        // make sure the mint is a valid one - currently just checks it against the default mint
        if mint_cfg.default_mint_node_id != *mint_node_id {
            return Err(Error::Validation(ValidationError::InvalidMint(
                mint_node_id.to_string(),
            )));
        }
        // fetch data
        let identity = self.identity_store.get().await?;
        let contacts = self.contact_store.get_map().await?;
        let blockchain = self.blockchain_store.get_chain(bill_id).await?;
        let bill_keys = self.store.get_keys(bill_id).await?;
        let bill = self
            .get_last_version_bill(&blockchain, &bill_keys, &identity, &contacts)
            .await?;
        let is_paid = self.store.is_paid(bill_id).await?;

        let mint_anon_participant = self.get_participant_for_mint(mint_node_id, &identity).await;
        // validate using mint bill action - no point doing a mint request, if it can't be minted
        BillValidateActionData {
            blockchain: blockchain.clone(),
            drawee_node_id: bill.drawee.node_id.clone(),
            payee_node_id: bill.payee.node_id().clone(),
            endorsee_node_id: bill.endorsee.clone().map(|e| e.node_id()),
            maturity_date: bill.maturity_date.clone(),
            bill_keys: bill_keys.clone(),
            timestamp,
            signer_node_id: signer_public_data.node_id().clone(),
            bill_action: BillAction::Mint(
                mint_anon_participant.clone(),
                bill.sum,
                bill.currency.clone(),
            ),
            is_paid,
        }
        .validate()?;

        let requests_to_mint_for_bill_and_mint = self
            .mint_store
            .get_requests(&signer_public_data.node_id(), bill_id, mint_node_id)
            .await?;
        // If there are any active, or accepted (i.e. pending, accepted or offered) requests, we can't make another one
        if requests_to_mint_for_bill_and_mint.iter().any(|rtm| {
            matches!(
                rtm.status,
                MintRequestStatus::Pending
                    | MintRequestStatus::Offered
                    | MintRequestStatus::Accepted
            )
        }) {
            return Err(Error::Validation(
                ValidationError::RequestToMintForBillAndMintAlreadyActive,
            ));
        }

        // Upload existing files for the mint
        // TODO(multi-relay): don't default to first, but to file upload relay of receiver
        let file_urls_for_mint = match mint_anon_participant.nostr_relays().first() {
            Some(relay_url) => {
                self.upload_bill_files_for_node_id(
                    bill_id,
                    &bill_keys.private_key,
                    &mint_anon_participant.node_id(),
                    relay_url,
                    &bill.files,
                )
                .await?
            }
            None => {
                warn!(
                    "mint {} does not have a nostr relay",
                    &mint_anon_participant.node_id()
                );
                vec![]
            }
        };

        // Send request to mint to mint
        let bill_to_share = create_bill_to_share_with_external_party(
            bill_id,
            &blockchain,
            &bill_keys,
            &mint_anon_participant.node_id().pub_key(),
            signer_keys,
            &file_urls_for_mint,
        )?;
        let mint_request_id = self
            .mint_client
            .enquire_mint_quote(&mint_cfg.default_mint_url, bill_to_share, signer_keys)
            .await?;

        // Store request to mint
        self.mint_store
            .add_request(
                &signer_public_data.node_id(),
                bill_id,
                mint_node_id,
                &mint_request_id,
                timestamp,
            )
            .await?;

        // Calculate bill and persist it to cache
        self.recalculate_and_persist_bill(
            bill_id,
            &blockchain,
            &bill_keys,
            &identity,
            &signer_public_data.node_id(),
            timestamp,
        )
        .await?;

        // Send notifications
        if let Err(e) = self
            .notification_service
            .send_request_to_mint_event(
                &signer_public_data.node_id(),
                &mint_anon_participant,
                &bill,
            )
            .await
        {
            error!("Couldn't send notifications for request to mint: {e}");
        }

        debug!("Executed request to mint with mint {mint_node_id} for bill {bill_id}");

        Ok(())
    }

    async fn get_mint_state(
        &self,
        bill_id: &BillId,
        current_identity_node_id: &NodeId,
    ) -> Result<Vec<MintRequestState>> {
        validate_bill_id_network(bill_id)?;
        validate_node_id_network(current_identity_node_id)?;
        let requests = self
            .mint_store
            .get_requests_for_bill(current_identity_node_id, bill_id)
            .await?;

        let mut req_states: Vec<MintRequestState> = requests
            .into_iter()
            .map(|req| MintRequestState {
                request: req,
                offer: None,
            })
            .collect();

        for req in req_states.iter_mut() {
            // if it's offered, or accepted, we also fetch the offer
            if matches!(
                req.request.status,
                MintRequestStatus::Offered | MintRequestStatus::Accepted
            ) {
                let offer = self
                    .mint_store
                    .get_offer(&req.request.mint_request_id)
                    .await?;
                req.offer = offer;
            }
        }

        Ok(req_states)
    }

    async fn cancel_request_to_mint(
        &self,
        mint_request_id: &str,
        current_identity_node_id: &NodeId,
    ) -> Result<()> {
        debug!("trying to cancel request to mint {mint_request_id}");
        validate_node_id_network(current_identity_node_id)?;
        let req = self
            .get_req_to_mint_for_node_id(mint_request_id, current_identity_node_id)
            .await?;
        // only if it's pending
        if matches!(req.status, MintRequestStatus::Pending) {
            self.mint_client
                .cancel_quote_for_mint(
                    &get_config().mint_config.default_mint_url,
                    &req.mint_request_id,
                )
                .await?;
            self.mint_store
                .update_request(
                    mint_request_id,
                    &MintRequestStatus::Cancelled {
                        timestamp: util::date::now().timestamp() as u64,
                    },
                )
                .await?;
            Ok(())
        } else {
            Err(Error::CancelMintRequestNotPending)
        }
    }

    async fn check_mint_state(
        &self,
        bill_id: &BillId,
        current_identity_node_id: &NodeId,
    ) -> Result<()> {
        debug!("checking mint requests for bill {bill_id}");
        validate_bill_id_network(bill_id)?;
        validate_node_id_network(current_identity_node_id)?;
        let requests = self
            .mint_store
            .get_requests_for_bill(current_identity_node_id, bill_id)
            .await?;
        for req in requests {
            if let Err(e) = self.check_mint_quote_and_update_bill_mint_state(&req).await {
                error!(
                    "Could not check mint state for {}: {e}",
                    &req.mint_request_id
                );
            }
        }
        Ok(())
    }

    async fn check_mint_state_for_all_bills(&self) -> Result<()> {
        debug!("checking all not-finished mint requests");
        // get all not-finished (offered, pending, accepted) requests
        let requests = self.mint_store.get_all_active_requests().await?;
        debug!(
            "checking all not-finished mint requests ({})",
            requests.len()
        );
        for req in requests {
            if let Err(e) = self.check_mint_quote_and_update_bill_mint_state(&req).await {
                error!(
                    "Could not check mint state for {}: {e}",
                    &req.mint_request_id
                );
            }
        }
        Ok(())
    }

    async fn accept_mint_offer(
        &self,
        mint_request_id: &str,
        signer_public_data: &BillParticipant,
        signer_keys: &BcrKeys,
        timestamp: u64,
    ) -> Result<()> {
        let currency = CURRENCY_SAT.to_string(); // default to sat for now
        let identity = self.identity_store.get().await?;
        debug!("trying to accept offer from request to mint {mint_request_id}");
        validate_node_id_network(&signer_public_data.node_id())?;
        let req = self
            .get_req_to_mint_for_node_id(mint_request_id, &signer_public_data.node_id())
            .await?;
        // only if it's offered
        if matches!(req.status, MintRequestStatus::Offered) {
            // and not expired
            if let Ok(Some(offer)) = self.mint_store.get_offer(&req.mint_request_id).await {
                if offer.expiration_timestamp < timestamp {
                    return Err(Error::AcceptMintOfferExpired);
                }
                // accept the offer
                self.mint_client
                    .resolve_quote_for_mint(
                        &get_config().mint_config.default_mint_url,
                        &req.mint_request_id,
                        ResolveMintOffer::Accept,
                    )
                    .await?;

                // endorse the bill to the mint
                let mint_anon_participant = self
                    .get_participant_for_mint(&req.mint_node_id, &identity)
                    .await;
                self.execute_bill_action(
                    &req.bill_id,
                    BillAction::Mint(mint_anon_participant, offer.discounted_sum, currency),
                    signer_public_data,
                    signer_keys,
                    timestamp,
                )
                .await?;

                // update the state
                self.mint_store
                    .update_request(mint_request_id, &MintRequestStatus::Accepted)
                    .await?;

                // reject all other offers - but don't fail on errors
                if let Err(e) = self
                    .reject_mint_offers_except_accepted_one_for_bill(
                        &req.mint_request_id,
                        &req.bill_id,
                        &signer_public_data.node_id(),
                    )
                    .await
                {
                    error!(
                        "Error rejecting other mint offers for bill {}: {e}",
                        req.bill_id
                    );
                }
                Ok(())
            } else {
                Err(Error::NotFound)
            }
        } else {
            Err(Error::AcceptMintRequestNotOffered)
        }
    }

    async fn reject_mint_offer(
        &self,
        mint_request_id: &str,
        current_identity_node_id: &NodeId,
    ) -> Result<()> {
        debug!("trying to reject offer from request to mint {mint_request_id}");
        validate_node_id_network(current_identity_node_id)?;
        let req = self
            .get_req_to_mint_for_node_id(mint_request_id, current_identity_node_id)
            .await?;
        // only if it's offered
        if matches!(req.status, MintRequestStatus::Offered) {
            self.mint_client
                .resolve_quote_for_mint(
                    &get_config().mint_config.default_mint_url,
                    &req.mint_request_id,
                    ResolveMintOffer::Reject,
                )
                .await?;
            self.mint_store
                .update_request(
                    mint_request_id,
                    &MintRequestStatus::Rejected {
                        timestamp: util::date::now().timestamp() as u64,
                    },
                )
                .await?;
            Ok(())
        } else {
            Err(Error::RejectMintRequestNotOffered)
        }
    }

    async fn dev_mode_get_full_bill_chain(
        &self,
        bill_id: &BillId,
        current_identity_node_id: &NodeId,
    ) -> Result<Vec<BillBlockPlaintextWrapper>> {
        // if dev mode is off - we return an error
        if !get_config().dev_mode_config.on {
            error!("Called dev mode operation with dev mode disabled - please enable!");
            return Err(Error::InvalidOperation);
        }

        validate_bill_id_network(bill_id)?;
        validate_node_id_network(current_identity_node_id)?;

        // if there is no such bill, we return an error
        match self.store.exists(bill_id).await {
            Ok(true) => (),
            _ => {
                return Err(Error::NotFound);
            }
        };

        let chain = self.blockchain_store.get_chain(bill_id).await?;
        let bill_keys = self.store.get_keys(bill_id).await?;
        let bill_participant_node_ids = chain.get_all_nodes_from_bill(&bill_keys)?;

        // if currently active identity is not part of the bill, we can't access it
        if !bill_participant_node_ids
            .iter()
            .any(|p| p == current_identity_node_id)
        {
            return Err(Error::NotFound);
        }

        let plaintext_chain = chain.get_chain_with_plaintext_block_data(&bill_keys)?;

        Ok(plaintext_chain)
    }

    async fn share_bill_with_court(
        &self,
        bill_id: &BillId,
        signer_public_data: &BillParticipant,
        signer_keys: &BcrKeys,
        court_node_id: &NodeId,
    ) -> Result<()> {
        validate_bill_id_network(bill_id)?;
        validate_node_id_network(&signer_public_data.node_id())?;
        let court_url = get_config().court_config.default_url.clone();
        debug!(
            "Executing share with court {court_node_id} with court {} for bill {bill_id}",
            court_url
        );
        let blockchain = self.blockchain_store.get_chain(bill_id).await?;
        let bill_keys = self.store.get_keys(bill_id).await?;
        let participants = blockchain.get_all_nodes_from_bill(&bill_keys)?;
        // Can only share bills we are part of
        if !participants.contains(&signer_public_data.node_id()) {
            return Err(Error::NotFound);
        }

        let identity = self.identity_store.get().await?;
        let contacts = self.contact_store.get_map().await?;
        let bill = self
            .get_last_version_bill(&blockchain, &bill_keys, &identity, &contacts)
            .await?;

        // Upload existing files for the court to our relay
        // TODO(multi-relay): don't default to first, but to file upload relay of receiver
        let file_urls_for_court = match signer_public_data.nostr_relays().first() {
            Some(relay_url) => {
                self.upload_bill_files_for_node_id(
                    bill_id,
                    &bill_keys.private_key,
                    court_node_id,
                    relay_url,
                    &bill.files,
                )
                .await?
            }
            None => {
                warn!("caller does not have a nostr relay",);
                return Err(Error::Validation(ValidationError::InvalidRelayUrl));
            }
        };

        // Send request to share with court
        let bill_to_share = create_bill_to_share_with_external_party(
            bill_id,
            &blockchain,
            &bill_keys,
            &court_node_id.pub_key(),
            signer_keys,
            &file_urls_for_court,
        )?;

        self.court_client
            .share_with_court(&court_url, bill_to_share, signer_keys)
            .await?;

        debug!(
            "Executed share with court {court_node_id} with court {} for bill {bill_id}",
            court_url
        );
        Ok(())
    }
}
