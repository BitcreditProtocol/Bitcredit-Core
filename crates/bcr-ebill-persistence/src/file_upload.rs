use super::{Error, Result, traits::file_upload::FileUploadStoreApi};
use async_trait::async_trait;
use bcr_ebill_core::{application::ServiceTraitBounds, protocol::Name};
use serde::{Deserialize, Serialize};
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use tokio::fs;
use uuid::Uuid;

pub struct FileUploadStore {
    root: PathBuf,
}

impl FileUploadStore {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub async fn cleanup_temp_uploads(&self) -> Result<()> {
        log::info!("cleaning up temp uploads");
        clear_dir(&self.root).await?;
        Ok(())
    }

    fn upload_dir(&self, id: &Uuid) -> PathBuf {
        self.root.join(id.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileDb {
    pub file_upload_id: Uuid,
    pub file_name: Name,
    pub file_bytes: String,
}

impl ServiceTraitBounds for FileUploadStore {}

#[async_trait]
impl FileUploadStoreApi for FileUploadStore {
    async fn remove_temp_upload_folder(&self, file_upload_id: &Uuid) -> Result<()> {
        let path = self.upload_dir(file_upload_id);

        match fs::remove_dir_all(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    async fn write_temp_upload_file(
        &self,
        file_upload_id: &Uuid,
        file_name: &Name,
        file_bytes: &[u8],
    ) -> Result<()> {
        let upload_dir = self.upload_dir(file_upload_id);

        match fs::remove_dir_all(&upload_dir).await {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }

        fs::create_dir_all(&upload_dir).await?;
        let file_path = upload_dir.join(file_name.to_string());
        fs::write(file_path, file_bytes).await?;

        Ok(())
    }

    async fn read_temp_upload_file(&self, file_upload_id: &Uuid) -> Result<(Name, Vec<u8>)> {
        match read_first_file(self.upload_dir(file_upload_id)).await? {
            None => Err(Error::NoSuchEntity(
                "file".to_string(),
                file_upload_id.to_string(),
            )),
            Some((name, bytes)) => Ok((
                Name::from_str(&name)
                    .map_err(|e| Error::InvalidData(format!("invalid file name: {name}, {e}")))?,
                bytes,
            )),
        }
    }
}

fn is_sidecar(name: &str) -> bool {
    matches!(
        name,
        ".DS_Store" | "Thumbs.db" | "ehthumbs.db" | "desktop.ini" | ".directory"
    ) || name.starts_with("._")
}

async fn read_first_file(dir: impl AsRef<Path>) -> io::Result<Option<(String, Vec<u8>)>> {
    let mut entries = fs::read_dir(dir).await?;

    while let Some(entry) = entries.next_entry().await? {
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();

        if is_sidecar(&name) {
            continue;
        }

        if entry.file_type().await?.is_file() {
            let bytes = fs::read(entry.path()).await?;
            return Ok(Some((name.into_owned(), bytes)));
        }
    }

    Ok(None)
}

async fn clear_dir(path: impl AsRef<Path>) -> Result<()> {
    let mut entries = fs::read_dir(path).await?;

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();

        if entry.file_type().await?.is_dir() {
            fs::remove_dir_all(path).await?;
        } else {
            fs::remove_file(path).await?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn file_name(name: &str) -> Name {
        Name::from_str(name).expect("valid file name")
    }

    #[tokio::test]
    async fn write_temp_upload_file_creates_directory_and_file() {
        let temp = tempdir().unwrap();
        let store = FileUploadStore::new(temp.path().to_path_buf());
        let upload_id = Uuid::new_v4();
        let name = file_name("test.txt");
        let bytes = b"hello world";
        store
            .write_temp_upload_file(&upload_id, &name, bytes)
            .await
            .unwrap();
        let upload_dir = temp.path().join(upload_id.to_string());
        let file_path = upload_dir.join("test.txt");
        assert!(upload_dir.is_dir());
        assert!(file_path.is_file());
        let stored_bytes = fs::read(file_path).await.unwrap();
        assert_eq!(stored_bytes, bytes);
    }

    #[tokio::test]
    async fn read_temp_upload_file_returns_file_name_and_bytes() {
        let temp = tempdir().unwrap();
        let store = FileUploadStore::new(temp.path().to_path_buf());
        let upload_id = Uuid::new_v4();
        let name = file_name("invoice.pdf");
        let bytes = b"some file contents";
        store
            .write_temp_upload_file(&upload_id, &name, bytes)
            .await
            .unwrap();
        let (read_name, read_bytes) = store.read_temp_upload_file(&upload_id).await.unwrap();
        assert_eq!(read_name.to_string(), "invoice.pdf");
        assert_eq!(read_bytes, bytes);
    }

    #[tokio::test]
    async fn read_temp_upload_file_ignores_sidecar_files() {
        let temp = tempdir().unwrap();
        let store = FileUploadStore::new(temp.path().to_path_buf());
        let upload_id = Uuid::new_v4();
        let upload_dir = store.upload_dir(&upload_id);
        fs::create_dir_all(&upload_dir).await.unwrap();
        fs::write(upload_dir.join(".DS_Store"), b"hidden")
            .await
            .unwrap();
        fs::write(upload_dir.join(".directory"), b"also hidden")
            .await
            .unwrap();
        fs::write(upload_dir.join("visible.txt"), b"visible contents")
            .await
            .unwrap();
        let (name, bytes) = store.read_temp_upload_file(&upload_id).await.unwrap();
        assert_eq!(name.to_string(), "visible.txt");
        assert_eq!(bytes, b"visible contents");
    }

    #[tokio::test]
    async fn read_temp_upload_file_ignores_hidden_directories() {
        let temp = tempdir().unwrap();
        let store = FileUploadStore::new(temp.path().to_path_buf());
        let upload_id = Uuid::new_v4();
        let upload_dir = store.upload_dir(&upload_id);
        fs::create_dir_all(upload_dir.join(".hidden-dir"))
            .await
            .unwrap();
        fs::write(upload_dir.join(".hidden-dir").join("hidden.txt"), b"hidden")
            .await
            .unwrap();
        fs::write(upload_dir.join("visible.txt"), b"visible")
            .await
            .unwrap();
        let (name, bytes) = store.read_temp_upload_file(&upload_id).await.unwrap();
        assert_eq!(name.to_string(), "visible.txt");
        assert_eq!(bytes, b"visible");
    }

    #[tokio::test]
    async fn read_temp_upload_file_returns_no_such_entity_when_no_visible_file_exists() {
        let temp = tempdir().unwrap();
        let store = FileUploadStore::new(temp.path().to_path_buf());
        let upload_id = Uuid::new_v4();
        let upload_dir = store.upload_dir(&upload_id);
        fs::create_dir_all(&upload_dir).await.unwrap();
        fs::write(upload_dir.join(".DS_Store"), b"hidden")
            .await
            .unwrap();
        let result = store.read_temp_upload_file(&upload_id).await;
        match result {
            Err(Error::NoSuchEntity(entity, id)) => {
                assert_eq!(entity, "file");
                assert_eq!(id, upload_id.to_string());
            }
            other => panic!("expected NoSuchEntity, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn read_temp_upload_file_returns_error_when_upload_directory_does_not_exist() {
        let temp = tempdir().unwrap();
        let store = FileUploadStore::new(temp.path().to_path_buf());
        let upload_id = Uuid::new_v4();
        let result = store.read_temp_upload_file(&upload_id).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn cleanup_temp_uploads_removes_all_contents_but_keeps_root() {
        let temp = tempdir().unwrap();
        let store = FileUploadStore::new(temp.path().to_path_buf());
        let upload_id_1 = Uuid::new_v4();
        let upload_id_2 = Uuid::new_v4();
        let dir_1 = store.upload_dir(&upload_id_1);
        let dir_2 = store.upload_dir(&upload_id_2);
        fs::create_dir_all(&dir_1).await.unwrap();
        fs::create_dir_all(dir_2.join("nested")).await.unwrap();
        fs::write(dir_1.join("file.txt"), b"one").await.unwrap();
        fs::write(dir_2.join("nested").join("file.txt"), b"two")
            .await
            .unwrap();
        fs::write(temp.path().join("root-file.txt"), b"root")
            .await
            .unwrap();
        store.cleanup_temp_uploads().await.unwrap();
        assert!(temp.path().is_dir());
        let mut entries = fs::read_dir(temp.path()).await.unwrap();
        assert!(entries.next_entry().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn remove_temp_upload_folder_removes_empty_upload_directory() {
        let temp = tempdir().unwrap();
        let store = FileUploadStore::new(temp.path().to_path_buf());
        let upload_id = Uuid::new_v4();
        let upload_dir = store.upload_dir(&upload_id);
        fs::create_dir_all(&upload_dir).await.unwrap();
        assert!(upload_dir.exists());
        store.remove_temp_upload_folder(&upload_id).await.unwrap();
        assert!(!upload_dir.exists());
    }

    #[tokio::test]
    async fn multiple_uploads_are_isolated_by_upload_id() {
        let temp = tempdir().unwrap();
        let store = FileUploadStore::new(temp.path().to_path_buf());
        let upload_id_1 = Uuid::new_v4();
        let upload_id_2 = Uuid::new_v4();
        let name_1 = file_name("first.txt");
        let name_2 = file_name("second.txt");
        store
            .write_temp_upload_file(&upload_id_1, &name_1, b"first")
            .await
            .unwrap();
        store
            .write_temp_upload_file(&upload_id_2, &name_2, b"second")
            .await
            .unwrap();
        let (read_name_1, bytes_1) = store.read_temp_upload_file(&upload_id_1).await.unwrap();
        let (read_name_2, bytes_2) = store.read_temp_upload_file(&upload_id_2).await.unwrap();
        assert_eq!(read_name_1.to_string(), "first.txt");
        assert_eq!(bytes_1, b"first");
        assert_eq!(read_name_2.to_string(), "second.txt");
        assert_eq!(bytes_2, b"second");
    }

    #[tokio::test]
    async fn writing_same_file_again_overwrites_existing_contents() {
        let temp = tempdir().unwrap();
        let store = FileUploadStore::new(temp.path().to_path_buf());
        let upload_id = Uuid::new_v4();
        let name = file_name("test.txt");
        store
            .write_temp_upload_file(&upload_id, &name, b"old")
            .await
            .unwrap();
        store
            .write_temp_upload_file(&upload_id, &name, b"new contents")
            .await
            .unwrap();
        let (_, bytes) = store.read_temp_upload_file(&upload_id).await.unwrap();
        assert_eq!(bytes, b"new contents");
    }
}
