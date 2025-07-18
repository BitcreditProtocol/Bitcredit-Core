#[cfg(not(target_arch = "wasm32"))]
use crate::Error;

use super::Result;
use async_trait::async_trait;
use bcr_ebill_core::ServiceTraitBounds;
#[cfg(not(target_arch = "wasm32"))]
use std::path::{Path, PathBuf};

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait FileUploadStoreApi: ServiceTraitBounds {
    /// Creates temporary upload folder with the given name
    async fn create_temp_upload_folder(&self, file_upload_id: &str) -> Result<()>;

    /// Deletes temporary upload folder with the given name
    async fn remove_temp_upload_folder(&self, file_upload_id: &str) -> Result<()>;

    /// Writes the temporary upload file with the given file name and bytes for the given file_upload_id
    async fn write_temp_upload_file(
        &self,
        file_upload_id: &str,
        file_name: &str,
        file_bytes: &[u8],
    ) -> Result<()>;

    /// Reads the temporary files from the given file_upload_id and returns their file name and
    /// bytes
    async fn read_temp_upload_file(&self, file_upload_id: &str) -> Result<(String, Vec<u8>)>;
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone)]
pub struct FileUploadStore {
    temp_upload_folder: String,
    files_folder: String,
}

/// Given a base path and a directory path, ensures that the directory
/// exists and returns the full path.
#[cfg(not(target_arch = "wasm32"))]
pub async fn file_storage_path(data_dir: &str, path: &str) -> Result<String> {
    let directory = format!("{data_dir}/{path}");
    if !Path::new(&directory).exists() {
        tokio::fs::create_dir_all(&directory).await?;
    }
    Ok(directory)
}

#[cfg(not(target_arch = "wasm32"))]
impl FileUploadStore {
    pub async fn new(data_dir: &str, files_path: &str, temp_upload_path: &str) -> Result<Self> {
        let files_folder = file_storage_path(data_dir, files_path).await?;
        let temp_upload_folder =
            file_storage_path(&format!("{data_dir}/{files_path}"), temp_upload_path).await?;
        Ok(Self {
            temp_upload_folder,
            files_folder,
        })
    }

    pub fn get_path_for_files(&self, id: &str) -> PathBuf {
        PathBuf::from(self.files_folder.as_str()).join(id)
    }

    pub async fn cleanup_temp_uploads(&self) -> Result<()> {
        log::info!("cleaning up temp upload folder");
        let path = Path::new(&self.temp_upload_folder);
        let mut dir = tokio::fs::read_dir(path).await?;
        while let Some(entry) = dir.next_entry().await? {
            let path = entry.path();
            if path.is_dir() {
                log::info!("deleting temp upload folder at {path:?}");
                tokio::fs::remove_dir_all(path).await?;
            }
        }
        Ok(())
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl ServiceTraitBounds for FileUploadStore {}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg(not(target_arch = "wasm32"))]
impl FileUploadStoreApi for FileUploadStore {
    async fn create_temp_upload_folder(&self, file_upload_id: &str) -> Result<()> {
        let dest_dir = Path::new(&self.temp_upload_folder).join(file_upload_id);
        if !dest_dir.exists() {
            tokio::fs::create_dir_all(&dest_dir).await?;
        }
        Ok(())
    }

    async fn remove_temp_upload_folder(&self, file_upload_id: &str) -> Result<()> {
        let dest_dir = Path::new(&self.temp_upload_folder).join(file_upload_id);
        if dest_dir.exists() {
            log::info!("deleting temp upload folder for bill at {dest_dir:?}");
            tokio::fs::remove_dir_all(dest_dir).await?;
        }
        Ok(())
    }

    async fn write_temp_upload_file(
        &self,
        file_upload_id: &str,
        file_name: &str,
        file_bytes: &[u8],
    ) -> Result<()> {
        let dest = Path::new(&self.temp_upload_folder)
            .join(file_upload_id)
            .join(file_name);
        tokio::fs::write(dest, file_bytes).await?;
        Ok(())
    }

    async fn read_temp_upload_file(&self, file_upload_id: &str) -> Result<(String, Vec<u8>)> {
        let mut files = Vec::new();
        let folder = Path::new(&self.temp_upload_folder).join(file_upload_id);
        let mut dir = tokio::fs::read_dir(&folder).await?;
        while let Some(entry) = dir.next_entry().await? {
            let file_path = entry.path();
            if let Some(file_name) = file_path.file_name()
                && let Some(file_name_str) = file_name.to_str()
            {
                let file_bytes = tokio::fs::read(&file_path).await?;
                files.push((file_name_str.to_owned(), file_bytes));
            }
        }
        if files.is_empty() {
            return Err(Error::NoSuchEntity(
                "file".to_string(),
                file_upload_id.to_owned(),
            ));
        }
        Ok(files[0].clone())
    }
}
