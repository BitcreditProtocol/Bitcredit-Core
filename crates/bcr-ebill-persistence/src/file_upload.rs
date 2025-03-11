use super::Result;
use async_trait::async_trait;
use log::info;
use std::path::{Path, PathBuf};

#[async_trait]
pub trait FileUploadStoreApi: Send + Sync {
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
    async fn read_temp_upload_files(&self, file_upload_id: &str) -> Result<Vec<(String, Vec<u8>)>>;

    /// Writes the given encrypted bytes of an attached file to disk, in a folder named id within
    /// the files folder
    async fn save_attached_file(
        &self,
        encrypted_bytes: &[u8],
        id: &str,
        file_name: &str,
    ) -> Result<()>;

    /// Opens the given attached file from disk
    async fn open_attached_file(&self, id: &str, file_name: &str) -> Result<Vec<u8>>;

    /// Deletes the attached files for the given id
    async fn delete_attached_files(&self, id: &str) -> Result<()>;
}

#[derive(Clone)]
pub struct FileUploadStore {
    #[allow(dead_code)]
    temp_upload_folder: String,
    files_folder: String,
}

/// Given a base path and a directory path, ensures that the directory
/// exists and returns the full path.
pub async fn file_storage_path(data_dir: &str, path: &str) -> Result<String> {
    let directory = format!("{}/{}", data_dir, path);
    if !Path::new(&directory).exists() {
        info!("TODO: file upload: create directory");
        // TODO: create directory
        // tokio::fs::create_dir_all(&directory).await?;
    }
    Ok(directory)
}

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
        // TODO: read directory and remove
        // let path = Path::new(&self.temp_upload_folder);
        // let mut dir = tokio::fs::read_dir(path).await?;
        // while let Some(entry) = dir.next_entry().await? {
        //     let path = entry.path();
        //     if path.is_dir() {
        //         log::info!("deleting temp upload folder at {path:?}");
        // TODO: remove directory
        // tokio::fs::remove_dir_all(path).await?;
        // }
        // }
        Ok(())
    }
}

#[async_trait]
impl FileUploadStoreApi for FileUploadStore {
    async fn create_temp_upload_folder(&self, _file_upload_id: &str) -> Result<()> {
        // TODO: create temp directory
        // let dest_dir = Path::new(&self.temp_upload_folder).join(file_upload_id);
        // if !dest_dir.exists() {
        //     tokio::fs::create_dir_all(&dest_dir).await?;
        // }
        Ok(())
    }

    async fn remove_temp_upload_folder(&self, _file_upload_id: &str) -> Result<()> {
        // TODO: remove temp directory
        // let dest_dir = Path::new(&self.temp_upload_folder).join(file_upload_id);
        // if dest_dir.exists() {
        //     log::info!("deleting temp upload folder for bill at {dest_dir:?}");
        //     tokio::fs::remove_dir_all(dest_dir).await?;
        // }
        Ok(())
    }

    async fn write_temp_upload_file(
        &self,
        _file_upload_id: &str,
        _file_name: &str,
        _file_bytes: &[u8],
    ) -> Result<()> {
        // TODO: write file to disk
        // let dest = Path::new(&self.temp_upload_folder)
        //     .join(file_upload_id)
        //     .join(file_name);
        // tokio::fs::write(dest, file_bytes).await?;
        Ok(())
    }

    async fn read_temp_upload_files(
        &self,
        _file_upload_id: &str,
    ) -> Result<Vec<(String, Vec<u8>)>> {
        // TODO: read dir and files in dir
        let files = Vec::new();
        // let folder = Path::new(&self.temp_upload_folder).join(file_upload_id);
        // let mut dir = tokio::fs::read_dir(&folder).await?;
        // while let Some(entry) = dir.next_entry().await? {
        //     let file_path = entry.path();
        //     if let Some(file_name) = file_path.file_name() {
        //         if let Some(file_name_str) = file_name.to_str() {
        //             let file_bytes = tokio::fs::read(&file_path).await?;
        //             files.push((file_name_str.to_owned(), file_bytes));
        //         }
        //     }
        // }
        Ok(files)
    }

    async fn save_attached_file(
        &self,
        _encrypted_bytes: &[u8],
        _id: &str,
        _file_name: &str,
    ) -> Result<()> {
        // TODO: save file to disk
        // let dest_dir = self.get_path_for_files(id);
        // if !dest_dir.exists() {
        //     tokio::fs::create_dir_all(&dest_dir).await?;
        // }
        // let dest_file = dest_dir.join(file_name);
        // tokio::fs::write(dest_file, encrypted_bytes).await?;
        Ok(())
    }

    async fn open_attached_file(&self, _id: &str, _file_name: &str) -> Result<Vec<u8>> {
        // TODO: open file
        // let path = self.get_path_for_files(id).join(file_name);

        // let mut file = tokio::fs::File::open(&path).await?;
        // let mut buf = Vec::new();

        // file.read_to_end(&mut buf).await?;
        // Ok(buf)
        Ok(vec![])
    }

    async fn delete_attached_files(&self, _id: &str) -> Result<()> {
        // TODO: delete dir and files within
        // let path = self.get_path_for_files(id);

        // if path.is_dir() {
        //     log::info!("deleting attached files at {path:?}");
        //     tokio::fs::remove_dir_all(path).await?;
        // }
        Ok(())
    }
}
