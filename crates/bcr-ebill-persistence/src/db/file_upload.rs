use super::{
    super::{Error, Result, file_upload::FileUploadStoreApi},
    surreal::{Bindings, SurrealWrapper},
};
use crate::constants::{DB_FILE_UPLOAD_ID, DB_TABLE};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bcr_ebill_core::{ServiceTraitBounds, name::Name};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub struct FileUploadStore {
    db: SurrealWrapper,
}

impl FileUploadStore {
    const TEMP_FILES_TABLE: &'static str = "temp_files";

    pub fn new(db: SurrealWrapper) -> Self {
        Self { db }
    }

    pub async fn cleanup_temp_uploads(&self) -> Result<()> {
        log::info!("cleaning up temp uploads");
        let _: Vec<FileDb> = self.db.delete_all(Self::TEMP_FILES_TABLE).await?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileDb {
    pub file_upload_id: Uuid,
    pub file_name: Name,
    pub file_bytes: String,
}

impl ServiceTraitBounds for FileUploadStore {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl FileUploadStoreApi for FileUploadStore {
    async fn remove_temp_upload_folder(&self, file_upload_id: &Uuid) -> Result<()> {
        let mut bindings = Bindings::default();
        bindings.add(DB_TABLE, Self::TEMP_FILES_TABLE)?;
        bindings.add(DB_FILE_UPLOAD_ID, file_upload_id.to_string())?;
        let _: Vec<FileDb> = self
            .db
            .query(
                "DELETE from type::table($table) WHERE file_upload_id = $file_upload_id",
                bindings,
            )
            .await?;
        Ok(())
    }

    async fn write_temp_upload_file(
        &self,
        file_upload_id: &Uuid,
        file_name: &Name,
        file_bytes: &[u8],
    ) -> Result<()> {
        let entity = FileDb {
            file_upload_id: file_upload_id.to_owned(),
            file_name: file_name.to_owned(),
            file_bytes: STANDARD.encode(file_bytes),
        };
        let _: Option<FileDb> = self
            .db
            .create(
                Self::TEMP_FILES_TABLE,
                Some(file_upload_id.to_string()),
                entity,
            )
            .await?;
        Ok(())
    }

    async fn read_temp_upload_file(&self, file_upload_id: &Uuid) -> Result<(Name, Vec<u8>)> {
        let result: Option<FileDb> = self
            .db
            .select_one(Self::TEMP_FILES_TABLE, file_upload_id.to_string())
            .await?;
        match result {
            None => Err(Error::NoSuchEntity(
                "file".to_string(),
                file_upload_id.to_string(),
            )),
            Some(f) => Ok((
                f.file_name,
                STANDARD
                    .decode(&f.file_bytes)
                    .map_err(|_| Error::EncodingError)?,
            )),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use bcr_ebill_core::util::get_uuid_v4;

    use super::*;
    use crate::db::get_memory_db;

    #[tokio::test]
    async fn test_temp_file() {
        let temp_store = get_temp_store().await;
        let some_id = get_uuid_v4();
        temp_store
            .write_temp_upload_file(&some_id, &Name::new("file_name.jpg").unwrap(), &[])
            .await
            .unwrap();
        let temp_file = temp_store
            .read_temp_upload_file(&some_id)
            .await
            .unwrap()
            .clone();
        assert_eq!(temp_file.0, Name::new("file_name.jpg").unwrap());
    }

    async fn get_temp_store() -> FileUploadStore {
        let mem_db = get_memory_db("test", "temp_files")
            .await
            .expect("could not create get_memory_db");
        FileUploadStore::new(SurrealWrapper {
            db: mem_db,
            files: true,
        })
    }
}
