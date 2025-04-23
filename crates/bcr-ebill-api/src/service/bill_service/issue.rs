use super::{BillAction, BillServiceApi, Result, error::Error, service::BillService};
use crate::util;
use bcr_ebill_core::{
    File, Validate, ValidationError,
    bill::{BillIssueData, BillKeys, BillType, BitcreditBill, validation::validate_bill_issue},
    blockchain::{
        Blockchain,
        bill::{
            BillBlockchain,
            block::{BillIssueBlockData, NodeId},
        },
    },
    contact::{BillIdentParticipant, BillParticipant},
    util::BcrKeys,
};
use bcr_ebill_transport::BillChainEvent;
use log::{debug, error};

impl BillService {
    pub(super) async fn issue_bill(&self, data: BillIssueData) -> Result<BitcreditBill> {
        debug!("issuing bill with type {}", &data.t);
        let (sum, bill_type) = validate_bill_issue(&data)?;

        let drawer = match data.drawer_public_data {
            BillParticipant::Ident(ref drawer_data) => drawer_data,
            BillParticipant::Anon(_) => {
                return Err(Error::Validation(ValidationError::DrawerIsNotBillIssuer));
            }
        };

        let (public_data_drawee, public_data_payee): (BillIdentParticipant, BillParticipant) =
            match bill_type {
                // Drawer is payee
                BillType::SelfDrafted => {
                    let public_data_drawee = match self.contact_store.get(&data.drawee).await {
                        Ok(Some(drawee)) => drawee.try_into()?,
                        Ok(None) | Err(_) => {
                            return Err(Error::DraweeNotInContacts);
                        }
                    };

                    let public_data_payee = BillParticipant::Ident(drawer.clone());

                    (public_data_drawee, public_data_payee)
                }
                // Drawer is drawee
                BillType::PromissoryNote => {
                    let public_data_drawee = drawer.clone();

                    let public_data_payee = match self.contact_store.get(&data.payee).await {
                        Ok(Some(payee)) => payee.try_into()?,
                        Ok(None) | Err(_) => {
                            return Err(Error::PayeeNotInContacts);
                        }
                    };

                    (public_data_drawee, public_data_payee)
                }
                // Drawer is neither drawee nor payee
                BillType::ThreeParties => {
                    let public_data_drawee = match self.contact_store.get(&data.drawee).await {
                        Ok(Some(drawee)) => drawee.try_into()?,
                        Ok(None) | Err(_) => {
                            return Err(Error::DraweeNotInContacts);
                        }
                    };

                    let public_data_payee = match self.contact_store.get(&data.payee).await {
                        Ok(Some(payee)) => payee.try_into()?,
                        Ok(None) | Err(_) => {
                            return Err(Error::PayeeNotInContacts);
                        }
                    };

                    (public_data_drawee, public_data_payee)
                }
            };
        debug!("issuing bill with drawee {public_data_drawee:?} and payee {public_data_payee:?}");

        let identity = self.identity_store.get_full().await?;
        let keys = BcrKeys::new();
        let public_key = keys.get_public_key();

        let bill_id = util::sha256_hash(public_key.as_bytes());
        let bill_keys = BillKeys {
            private_key: keys.get_private_key_string(),
            public_key: keys.get_public_key(),
        };

        let mut bill_files: Vec<File> = vec![];
        for file_upload_id in data.file_upload_ids.iter() {
            let (file_name, file_bytes) = &self
                .file_upload_store
                .read_temp_upload_file(file_upload_id)
                .await
                .map_err(|_| Error::NoFileForFileUploadId)?;
            bill_files.push(
                self.encrypt_and_save_uploaded_file(file_name, file_bytes, &bill_id, &public_key)
                    .await?,
            );
        }

        let bill = BitcreditBill {
            id: bill_id.clone(),
            country_of_issuing: data.country_of_issuing,
            city_of_issuing: data.city_of_issuing,
            currency: data.currency,
            sum,
            maturity_date: data.maturity_date,
            issue_date: data.issue_date,
            country_of_payment: data.country_of_payment,
            city_of_payment: data.city_of_payment,
            language: data.language,
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
        let block_data = BillIssueBlockData::from(
            bill.clone(),
            signing_keys.signatory_identity,
            data.timestamp,
        );
        block_data.validate()?;

        self.store.save_keys(&bill_id, &bill_keys).await?;
        let chain = BillBlockchain::new(
            &block_data,
            signing_keys.signatory_keys,
            signing_keys.company_keys,
            keys.clone(),
            data.timestamp,
        )?;

        let block = chain.get_first_block();
        self.blockchain_store.add_block(&bill.id, block).await?;

        self.add_identity_and_company_chain_blocks_for_signed_bill_action(
            &data.drawer_public_data.clone(), // drawer is identified
            &bill_id,
            block,
            &identity.key_pair,
            &data.drawer_keys,
            data.timestamp,
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
            .notification_service
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
        if bill.drawer == bill.drawee {
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
