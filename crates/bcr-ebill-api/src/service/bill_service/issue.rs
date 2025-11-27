use super::{BillAction, BillServiceApi, Result, error::Error, service::BillService};
use crate::{
    constants::MAX_BILL_ATTACHMENTS, get_config, service::file_upload_service::UploadFileType,
    util::validate_node_id_network,
};
use bcr_common::core::BillId;
use bcr_ebill_core::protocol::{
    File, Name, PublicKey, Sha256Hash, Validate,
    blockchain::{
        Blockchain,
        bill::{
            BillBlockchain, BillIssueData, BitcreditBill,
            block::BillIssueBlockData,
            participant::{BillAnonParticipant, BillIdentParticipant, BillParticipant},
            validation::validate_bill_issue,
        },
    },
    crypto::{self, BcrKeys},
    event::BillChainEvent,
};
use bcr_ebill_core::{
    application::{ValidationError, bill::BillType},
    protocol::ProtocolValidationError,
};
use log::{debug, error, info};

impl BillService {
    pub(super) async fn encrypt_and_save_uploaded_file(
        &self,
        file_name: &Name,
        file_bytes: &[u8],
        bill_id: &BillId,
        public_key: &PublicKey,
        relay_url: &url::Url,
        upload_file_type: UploadFileType,
    ) -> Result<File> {
        // validate file size for upload file type
        if !upload_file_type.check_file_size(file_bytes.len()) {
            return Err(Error::Validation(
                ProtocolValidationError::FileIsTooBig(upload_file_type.max_file_size()).into(),
            ));
        }
        let file_hash = Sha256Hash::from_bytes(file_bytes);
        let encrypted = crypto::encrypt_ecies(file_bytes, public_key)?;
        let nostr_hash = self.file_upload_client.upload(relay_url, encrypted).await?;
        info!("Saved file {file_name} with hash {file_hash} for bill {bill_id}");
        Ok(File {
            name: file_name.to_owned(),
            hash: file_hash,
            nostr_hash,
        })
    }

    pub(super) async fn issue_bill(&self, data: BillIssueData) -> Result<BitcreditBill> {
        debug!(
            "issuing bill with type {}, blank: {}",
            &data.t, &data.blank_issue
        );
        validate_node_id_network(&data.drawee)?;
        validate_node_id_network(&data.payee)?;
        validate_node_id_network(&data.drawer_public_data.node_id())?;
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
        let nostr_relays = identity.identity.nostr_relays.clone();
        let bill_keys = BcrKeys::new();
        let public_key = bill_keys.pub_key();

        let bill_id = BillId::new(public_key, get_config().bitcoin_network());

        if data.file_upload_ids.len() > MAX_BILL_ATTACHMENTS {
            return Err(Error::Validation(
                ProtocolValidationError::TooManyFiles.into(),
            ));
        }

        let mut bill_files: Vec<File> = vec![];
        // TODO(multi-relay): don't default to first
        if let Some(nostr_relay) = nostr_relays.first() {
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
                        nostr_relay,
                        UploadFileType::Document,
                    )
                    .await?,
                );
            }
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
                &get_config().mint_config.default_mint_node_id,
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

        self.store.save_keys(&bill_id, &bill_keys).await?;
        let chain = BillBlockchain::new(
            &block_data,
            signing_keys.signatory_keys,
            signing_keys.company_keys,
            bill_keys.clone(),
            data.timestamp,
        )
        .map_err(|e| Error::Protocol(e.into()))?;

        let block = chain.get_first_block();
        self.blockchain_store.add_block(&bill.id, block).await?;

        self.add_identity_and_company_chain_blocks_for_signed_bill_action(
            &data.drawer_public_data.clone(), // drawer is identified
            &bill_id,
            block,
            &identity,
            &data.drawer_keys,
            data.timestamp,
            Some(bill_keys.clone()),
        )
        .await?;

        // Calculate bill and persist it to cache
        self.recalculate_and_persist_bill(
            &bill_id,
            &chain,
            &bill_keys,
            &identity.identity,
            &data.drawer_public_data.node_id(),
            data.timestamp,
        )
        .await?;

        // clean up temporary file uploads, if there are any, logging any errors
        for file_upload_id in data.file_upload_ids.iter() {
            if let Err(e) = self
                .file_upload_store
                .remove_temp_upload_folder(file_upload_id)
                .await
            {
                error!(
                    "Error while cleaning up temporary file uploads for {}: {e}",
                    &file_upload_id
                );
            }
        }

        // send notification and blocks to all required recipients
        if let Err(e) = self
            .transport_service
            .send_bill_is_signed_event(&BillChainEvent::new(
                &bill,
                &chain,
                &bill_keys,
                true,
                &identity.identity.node_id,
            )?)
            .await
        {
            error!("Error propagating bill via Nostr {e}");
        }

        debug!("issued bill with id {bill_id}");

        // If we're the drawee, we immediately accept the bill with timestamp increased by 1 sec
        if bill.drawer.node_id == bill.drawee.node_id {
            debug!("we are drawer and drawee of bill: {bill_id} - immediately accepting");
            self.execute_bill_action(
                &bill_id,
                BillAction::Accept,
                &data.drawer_public_data,
                &data.drawer_keys,
                data.timestamp + 1,
            )
            .await?;
        }

        Ok(bill)
    }
}
