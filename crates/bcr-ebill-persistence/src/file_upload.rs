use super::Result;
use async_trait::async_trait;
use bcr_ebill_core::{ServiceTraitBounds, name::Name};
use uuid::Uuid;

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait FileUploadStoreApi: ServiceTraitBounds {
    /// Deletes temporary upload folder with the given name
    async fn remove_temp_upload_folder(&self, file_upload_id: &Uuid) -> Result<()>;

    /// Writes the temporary upload file with the given file name and bytes for the given file_upload_id
    async fn write_temp_upload_file(
        &self,
        file_upload_id: &Uuid,
        file_name: &Name,
        file_bytes: &[u8],
    ) -> Result<()>;

    /// Reads the temporary files from the given file_upload_id and returns their file name and
    /// bytes
    async fn read_temp_upload_file(&self, file_upload_id: &Uuid) -> Result<(Name, Vec<u8>)>;
}
