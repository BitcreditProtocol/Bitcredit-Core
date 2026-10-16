use super::{BillAction, Result, error::Error, service::BillService};
use crate::service::bill_service::blocks::PreparedSignerBlocks;
use crate::service::file_reference_helper::{bill_file_context, encrypt_upload_and_track_file};
use crate::{
    constants::MAX_BILL_ATTACHMENTS,
    service::{
        file_server_service::configured_blossom_servers, file_upload_service::UploadFileType,
    },
    util::validate_node_id_network,
};
use bcr_common::core::{BillId, NodeId};
use bcr_ebill_core::protocol::blockchain::bill::{
    BillBlock, BillValidateActionData, BillValidationActionMode, ContactType,
};
use bcr_ebill_core::protocol::{
    File, Name, PublicKey, Validate,
    blockchain::{
        Blockchain,
        bill::{
            BillBlockchain, BillIssueData, BitcreditBill,
            block::BillIssueBlockData,
            participant::{BillAnonParticipant, BillIdentParticipant, BillParticipant},
            validation::validate_bill_issue,
        },
    },
    crypto::BcrKeys,
    event::BillChainEvent,
};
use bcr_ebill_core::{
    application::{ValidationError, bill::BillType},
    protocol::ProtocolValidationError,
};
use log::{debug, error};

impl BillService {
    pub(super) async fn encrypt_and_save_uploaded_file(
        &self,
        file_name: &Name,
        file_bytes: &[u8],
        bill_id: &BillId,
        public_key: &PublicKey,
        signer: &BcrKeys,
        upload_file_type: UploadFileType,
    ) -> Result<File> {
        // validate file size for upload file type
        if !upload_file_type.check_file_size(file_bytes.len()) {
            return Err(Error::Validation(
                ProtocolValidationError::FileIsTooBig(upload_file_type.max_file_size()).into(),
            ));
        }
        let node_id = NodeId::new(signer.pub_key(), self.config.bitcoin_network());
        encrypt_upload_and_track_file(
            &self.file_reference_store,
            &self.file_upload_client,
            &self.transport_service,
            &configured_blossom_servers(&self.config.nostr_config),
            file_name,
            file_bytes,
            public_key,
            signer,
            &node_id,
            bill_file_context(&bill_id.to_string(), "files"),
            None,
            "bill",
        )
        .await
        .map_err(Error::from)
    }

    pub(super) async fn issue_bill(&self, data: BillIssueData) -> Result<BitcreditBill> {
        debug!(
            "issuing bill with type {}, blank: {}",
            data.t, data.blank_issue
        );
        validate_node_id_network(&data.drawee, self.config.bitcoin_network())?;
        validate_node_id_network(&data.payee, self.config.bitcoin_network())?;
        validate_node_id_network(
            &data.drawer_public_data.node_id(),
            self.config.bitcoin_network(),
        )?;
        let bill_type = match data.t {
            0 => BillType::PromissoryNote,
            1 => BillType::SelfDrafted,
            2 => BillType::ThreeParties,
            _ => return Err(Error::Validation(ValidationError::InvalidBillType)),
        };
        validate_bill_issue(&data)?;

        let drawer = match data.drawer_public_data {
            BillParticipant::Ident(ref drawer_data) => drawer_data,
            BillParticipant::Anon(_) => {
                return Err(Error::Validation(
                    ProtocolValidationError::SignerCantBeAnon.into(),
                ));
            }
        };

        let (public_data_drawee, public_data_payee): (BillIdentParticipant, BillParticipant) =
            match bill_type {
                // Drawer is payee
                BillType::SelfDrafted => {
                    let public_data_drawee = match self.contact_store.get(&data.drawee).await {
                        Ok(Some(drawee)) => drawee.try_into()?,
                        Ok(None) | Err(_) => {
                            return Err(Error::Validation(ValidationError::DraweeNotInContacts));
                        }
                    };

                    if data.blank_issue {
                        return Err(Error::Validation(
                            ProtocolValidationError::SelfDraftedBillCantBeBlank.into(),
                        ));
                    }

                    let public_data_payee = BillParticipant::Ident(drawer.clone());

                    (public_data_drawee, public_data_payee)
                }
                // Drawer is drawee
                BillType::PromissoryNote => {
                    let public_data_drawee = drawer.clone();

                    let mut public_data_payee = match self.contact_store.get(&data.payee).await {
                        Ok(Some(payee)) => payee.try_into()?,
                        Ok(None) | Err(_) => {
                            return Err(Error::Validation(ValidationError::PayeeNotInContacts));
                        }
                    };

                    // if it's a blank issue, convert the payee to anon
                    if data.blank_issue {
                        match public_data_payee {
                            BillParticipant::Anon(_) => (),
                            BillParticipant::Ident(identified) => {
                                let anon: BillAnonParticipant = identified.into();
                                public_data_payee = BillParticipant::Anon(anon);
                            }
                        };
                    }

                    (public_data_drawee, public_data_payee)
                }
                // Drawer is neither drawee nor payee
                BillType::ThreeParties => {
                    let public_data_drawee = match self.contact_store.get(&data.drawee).await {
                        Ok(Some(drawee)) => drawee.try_into()?,
                        Ok(None) | Err(_) => {
                            return Err(Error::Validation(ValidationError::DraweeNotInContacts));
                        }
                    };

                    let mut public_data_payee = match self.contact_store.get(&data.payee).await {
                        Ok(Some(payee)) => payee.try_into()?,
                        Ok(None) | Err(_) => {
                            return Err(Error::Validation(ValidationError::PayeeNotInContacts));
                        }
                    };

                    // if it's a blank issue, convert the payee to anon
                    if data.blank_issue {
                        match public_data_payee {
                            BillParticipant::Anon(_) => (),
                            BillParticipant::Ident(identified) => {
                                let anon: BillAnonParticipant = identified.into();
                                public_data_payee = BillParticipant::Anon(anon);
                            }
                        };
                    }
                    (public_data_drawee, public_data_payee)
                }
            };
        debug!("issuing bill with drawee {public_data_drawee:?} and payee {public_data_payee:?}");

        let identity = self.identity_store.get_full().await?;
        let bill_keys = BcrKeys::new();
        let public_key = bill_keys.pub_key();

        let bill_id = BillId::new(public_key, self.config.bitcoin_network());

        if data.file_upload_ids.len() > MAX_BILL_ATTACHMENTS {
            return Err(Error::Validation(
                ProtocolValidationError::TooManyFiles.into(),
            ));
        }

        let mut bill_files: Vec<File> = vec![];
        for file_upload_id in data.file_upload_ids.iter() {
            let (file_name, file_bytes) = &self
                .file_upload_store
                .read_temp_upload_file(file_upload_id)
                .await
                .map_err(|_| Error::Validation(ValidationError::NoFileForFileUploadId))?;
            bill_files.push(
                self.encrypt_and_save_uploaded_file(
                    file_name,
                    file_bytes,
                    &bill_id,
                    &public_key,
                    &identity.key_pair,
                    UploadFileType::Document,
                )
                .await?,
            );
        }

        let bill = BitcreditBill {
            id: bill_id.clone(),
            country_of_issuing: data.country_of_issuing,
            city_of_issuing: data.city_of_issuing,
            sum: data.sum,
            maturity_date: data.maturity_date,
            issue_date: data.issue_date,
            country_of_payment: data.country_of_payment,
            city_of_payment: data.city_of_payment,
            drawee: public_data_drawee,
            drawer: drawer.clone(),
            payee: public_data_payee,
            endorsee: None,
            files: bill_files,
        };

        let signing_keys = self.get_bill_signing_keys(
            &data.drawer_public_data, // drawer has to be identified
            &data.drawer_keys,
            &identity,
        )?;
        let Some(identity_proof) = self
            .get_signer_identity_proof(
                &data.drawer_public_data,
                &identity,
                &self.config.mint_config.default_mint_node_id,
            )
            .await?
        else {
            return Err(Error::Protocol(
                ProtocolValidationError::NoSignerIdentityProof.into(),
            ));
        };
        let block_data = BillIssueBlockData::from(
            bill.clone(),
            signing_keys.signatory_identity,
            data.timestamp,
            identity_proof,
        );
        block_data.validate()?;

        // prepare
        let mut chain = BillBlockchain::new(
            &block_data,
            signing_keys.signatory_keys,
            signing_keys.company_keys,
            bill_keys.clone(),
            data.timestamp,
        )
        .map_err(|e| Error::Protocol(e.into()))?;

        let issue_block = chain.get_first_block().clone();
        let chain_after_issue = chain.clone();

        let mut identity_chain = self.identity_blockchain_store.get_chain().await?;
        let mut company_chain = match &data.drawer_public_data {
            BillParticipant::Ident(drawer) if drawer.t == ContactType::Company => Some(
                self.company_blockchain_store
                    .get_chain(&drawer.node_id)
                    .await?,
            ),
            _ => None,
        };

        let issue_signer_blocks = self.prepare_signer_blocks(
            &data.drawer_public_data,
            &bill_id,
            &issue_block,
            &identity,
            &data.drawer_keys,
            &mut identity_chain,
            company_chain.as_mut(),
            data.timestamp,
            Some(bill_keys.clone()),
        )?;

        // handle auto-accepting the bill with timestamp increased by 1 sec if we're the drawee
        let mut auto_accept: Option<(BillBlock, PreparedSignerBlocks)> = None;
        let final_timestamp = if bill.drawer.node_id == bill.drawee.node_id {
            debug!("we are drawer and drawee of bill: {bill_id} - immediately accepting");
            let accept_timestamp = data.timestamp + 1;
            let accept_action = BillAction::Accept;
            BillValidateActionData {
                blockchain: chain.clone(),
                drawee_node_id: bill.drawee.node_id.clone(),
                payee_node_id: bill.payee.node_id(),
                endorsee_node_id: None,
                maturity_date: bill.maturity_date.clone(),
                bill_keys: bill_keys.clone(),
                timestamp: accept_timestamp,
                signer_node_id: data.drawer_public_data.node_id(),
                is_paid: false,
                mode: BillValidationActionMode::Deep(accept_action.clone()),
            }
            .validate()?;
            let accept_block = self
                .prepare_bill_action_block(
                    &bill,
                    &mut chain,
                    &bill_keys,
                    &accept_action,
                    &data.drawer_public_data,
                    &data.drawer_keys,
                    &identity,
                    accept_timestamp,
                )
                .await?;
            let accept_signer_blocks = self.prepare_signer_blocks(
                &data.drawer_public_data,
                &bill_id,
                &accept_block,
                &identity,
                &data.drawer_keys,
                &mut identity_chain,
                company_chain.as_mut(),
                accept_timestamp,
                None,
            )?;
            auto_accept = Some((accept_block, accept_signer_blocks));
            accept_timestamp
        } else {
            data.timestamp
        };

        // Calculate bill for caching
        let calculated_bill = self
            .calculate_full_bill(
                &chain,
                &bill_keys,
                &identity.identity,
                &data.drawer_public_data,
                &data.drawer_keys,
                final_timestamp,
            )
            .await?;

        // persist - TODO (tx): make transactional

        self.store.save_keys(&bill_id, &bill_keys).await?;

        // bill block
        self.blockchain_store
            .add_block(&bill_id, &issue_block)
            .await?;

        // company block
        if let Some(company) = &issue_signer_blocks.company_block {
            self.company_blockchain_store
                .add_block(&company.company_id, &company.block)
                .await?;
        }

        // identity block
        self.identity_blockchain_store
            .add_block(&issue_signer_blocks.identity_block)
            .await?;

        // automatic accept
        if let Some((accept_block, accept_signer_blocks)) = &auto_accept {
            self.blockchain_store
                .add_block(&bill_id, accept_block)
                .await?;
            if let Some(company) = &accept_signer_blocks.company_block {
                self.company_blockchain_store
                    .add_block(&company.company_id, &company.block)
                    .await?;
            }
            self.identity_blockchain_store
                .add_block(&accept_signer_blocks.identity_block)
                .await?;
        }

        self.store
            .save_bill_to_cache(
                &bill_id,
                &data.drawer_public_data.node_id(),
                &calculated_bill,
            )
            .await?;

        // effects & propagation

        self.propagate_prepared_signer_blocks(&issue_signer_blocks, &identity)
            .await?;

        // send notification to all required recipients
        if let Err(e) = self
            .transport_service
            .send_bill_is_signed_event(&BillChainEvent::new(
                &bill,
                &chain_after_issue, // after issue, in case we auto-accept
                &bill_keys,
                true,
                &identity.identity.node_id,
            )?)
            .await
        {
            error!("Error propagating bill via Nostr {e}");
        }

        // propagate auto-accept blocks and notifications
        if let Some((_accept_block, accept_signer_blocks)) = &auto_accept {
            self.propagate_prepared_signer_blocks(accept_signer_blocks, &identity)
                .await?;
            let contacts = self.contact_store.get_map().await?;
            self.notify_for_block_action(
                &chain,
                &bill_keys,
                &BillAction::Accept,
                &identity.identity,
                &contacts,
                &data.drawer_public_data.node_id(),
            )
            .await?;
        }

        debug!("issued bill with id {bill_id}");

        // cleanup

        // clean up temporary file uploads, if there are any, logging any errors
        for file_upload_id in data.file_upload_ids.iter() {
            if let Err(e) = self
                .file_upload_store
                .remove_temp_upload_folder(file_upload_id)
                .await
            {
                error!(
                    "Error while cleaning up temporary file uploads for {}: {e}",
                    file_upload_id
                );
            }
        }

        Ok(bill)
    }
}
