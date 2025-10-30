use super::{Error, Result};
use crate::constants::{
    MAX_DOCUMENT_FILE_SIZE_BYTES, MAX_FILE_NAME_CHARACTERS, VALID_FILE_MIME_TYPES,
};
use crate::data::UploadFileResult;
use crate::persistence::file_upload::FileUploadStoreApi;
use crate::{persistence, util};
use async_trait::async_trait;
use bcr_ebill_core::name::Name;
use bcr_ebill_core::{ServiceTraitBounds, ValidationError};
use log::{debug, error};
use std::sync::Arc;
use uuid::Uuid;

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait FileUploadServiceApi: ServiceTraitBounds {
    /// validates the given uploaded file
    async fn validate_attached_file(&self, file: &dyn util::file::UploadFileHandler) -> Result<()>;

    /// uploads files
    async fn upload_file(
        &self,
        file: &dyn util::file::UploadFileHandler,
    ) -> Result<UploadFileResult>;

    /// returns a temp upload file
    async fn get_temp_file(&self, file_upload_id: &Uuid) -> Result<Option<(Name, Vec<u8>)>>;
}

#[derive(Clone)]
pub struct FileUploadService {
    file_upload_store: Arc<dyn FileUploadStoreApi>,
}

impl FileUploadService {
    pub fn new(file_upload_store: Arc<dyn FileUploadStoreApi>) -> Self {
        Self { file_upload_store }
    }
}

impl ServiceTraitBounds for FileUploadService {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl FileUploadServiceApi for FileUploadService {
    async fn validate_attached_file(&self, file: &dyn util::file::UploadFileHandler) -> Result<()> {
        if file.is_empty() {
            return Err(Error::Validation(ValidationError::FileIsEmpty));
        }

        if file.len() > MAX_DOCUMENT_FILE_SIZE_BYTES {
            return Err(Error::Validation(ValidationError::FileIsTooBig(
                MAX_DOCUMENT_FILE_SIZE_BYTES,
            )));
        }

        let name = match file.name() {
            Some(n) => n,
            None => {
                return Err(Error::Validation(ValidationError::InvalidFileName(
                    MAX_FILE_NAME_CHARACTERS,
                )));
            }
        };

        if name.is_empty() || name.len() > MAX_FILE_NAME_CHARACTERS {
            return Err(Error::Validation(ValidationError::InvalidFileName(
                MAX_FILE_NAME_CHARACTERS,
            )));
        }

        let detected_type = match file.detect_content_type().await.map_err(|e| {
            error!("Could not detect content type for file {name}: {e}");
            Error::Validation(ValidationError::InvalidContentType)
        })? {
            Some(t) => t,
            None => {
                return Err(Error::Validation(ValidationError::InvalidContentType));
            }
        };

        if !VALID_FILE_MIME_TYPES.contains(&detected_type.as_str()) {
            return Err(Error::Validation(ValidationError::InvalidContentType));
        }
        Ok(())
    }

    async fn upload_file(
        &self,
        file: &dyn util::file::UploadFileHandler,
    ) -> Result<UploadFileResult> {
        // create a new random id
        let file_upload_id = util::get_uuid_v4();
        // create a folder to store the files
        self.file_upload_store
            .create_temp_upload_folder(&file_upload_id)
            .await?;
        // sanitize and randomize file name and write file into the temporary folder
        let file_name = Name::new(util::file::generate_unique_filename(
            &util::file::sanitize_filename(&file.name().ok_or(Error::Validation(
                ValidationError::InvalidFileName(MAX_FILE_NAME_CHARACTERS),
            ))?),
            file.extension(),
        ))?;
        let read_file = file.get_contents().await.map_err(persistence::Error::Io)?;
        self.file_upload_store
            .write_temp_upload_file(&file_upload_id, &file_name, &read_file)
            .await?;
        Ok(UploadFileResult { file_upload_id })
    }

    async fn get_temp_file(&self, file_upload_id: &Uuid) -> Result<Option<(Name, Vec<u8>)>> {
        debug!("getting temp file for file_upload_id: {file_upload_id}",);
        let file = self
            .file_upload_store
            .read_temp_upload_file(file_upload_id)
            .await
            .map_err(|_| crate::service::Error::NoFileForFileUploadId)?;
        let (file_name, file_bytes) = file;
        return Ok(Some((file_name, file_bytes)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{tests::tests::MockFileUploadStoreApiMock, util::get_uuid_v4};
    use std::sync::Arc;
    use util::file::MockUploadFileHandler;

    fn get_service(mock_storage: MockFileUploadStoreApiMock) -> FileUploadService {
        FileUploadService::new(Arc::new(mock_storage))
    }

    #[tokio::test]
    async fn upload_file_baseline() {
        let file_bytes = String::from("hello world").as_bytes().to_vec();
        let mut storage = MockFileUploadStoreApiMock::new();
        storage
            .expect_write_temp_upload_file()
            .returning(|_, _, _| Ok(()));
        storage
            .expect_create_temp_upload_folder()
            .returning(|_| Ok(()));
        let mut file = MockUploadFileHandler::new();
        file.expect_name()
            .returning(|| Some(String::from("invoice")));
        file.expect_extension()
            .returning(|| Some(String::from("pdf")));
        file.expect_get_contents()
            .returning(move || Ok(file_bytes.clone()));
        let service = get_service(storage);

        let res = service.upload_file(&file).await;
        assert!(res.is_ok());
        assert_eq!(res.unwrap().file_upload_id, get_uuid_v4(),);
    }

    #[tokio::test]
    async fn upload_file_baseline_fails_on_folder_creation() {
        let file_bytes = String::from("hello world").as_bytes().to_vec();
        let mut storage = MockFileUploadStoreApiMock::new();
        storage
            .expect_create_temp_upload_folder()
            .returning(|_| Err(persistence::Error::Io(std::io::Error::other("test error"))));
        let mut file = MockUploadFileHandler::new();
        file.expect_name()
            .returning(|| Some(String::from("invoice")));
        file.expect_extension()
            .returning(|| Some(String::from("pdf")));
        file.expect_get_contents()
            .returning(move || Ok(file_bytes.clone()));
        let service = get_service(storage);

        let res = service.upload_file(&file).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn upload_file_baseline_fails_on_file_creation() {
        let mut storage = MockFileUploadStoreApiMock::new();
        storage
            .expect_create_temp_upload_folder()
            .returning(|_| Ok(()));
        let mut file = MockUploadFileHandler::new();
        file.expect_name()
            .returning(|| Some(String::from("invoice")));
        file.expect_extension()
            .returning(|| Some(String::from("pdf")));
        file.expect_get_contents()
            .returning(|| Err(std::io::Error::other("test error")));
        let service = get_service(storage);

        let res = service.upload_file(&file).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn upload_file_baseline_fails_on_file_name_errors() {
        let mut storage = MockFileUploadStoreApiMock::new();
        storage
            .expect_create_temp_upload_folder()
            .returning(|_| Ok(()));
        let mut file = MockUploadFileHandler::new();
        file.expect_name().returning(|| None);
        let service = get_service(storage);

        let res = service.upload_file(&file).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn upload_file_baseline_fails_on_file_read_errors() {
        let file_bytes = String::from("hello world").as_bytes().to_vec();
        let mut storage = MockFileUploadStoreApiMock::new();
        storage
            .expect_write_temp_upload_file()
            .returning(|_, _, _| Err(persistence::Error::Io(std::io::Error::other("test error"))));
        storage
            .expect_create_temp_upload_folder()
            .returning(|_| Ok(()));
        let mut file = MockUploadFileHandler::new();
        file.expect_name()
            .returning(|| Some(String::from("invoice")));
        file.expect_extension()
            .returning(|| Some(String::from("pdf")));
        file.expect_get_contents()
            .returning(move || Ok(file_bytes.clone()));
        let service = get_service(storage);

        let res = service.upload_file(&file).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn validate_attached_file_checks_file_size() {
        let mut file = MockUploadFileHandler::new();
        file.expect_len()
            .returning(move || MAX_DOCUMENT_FILE_SIZE_BYTES * 2);
        file.expect_is_empty().returning(move || false);

        let service = get_service(MockFileUploadStoreApiMock::new());
        let res = service.validate_attached_file(&file).await;

        assert!(res.is_err());
    }

    #[tokio::test]
    async fn validate_attached_file_checks_file_name() {
        let mut file = MockUploadFileHandler::new();
        file.expect_len().returning(move || 100);
        file.expect_is_empty().returning(move || false);
        file.expect_name().returning(move || None);

        let service = get_service(MockFileUploadStoreApiMock::new());
        let res = service.validate_attached_file(&file).await;

        assert!(res.is_err());
    }

    #[tokio::test]
    async fn validate_attached_file_checks_file_name_empty() {
        let mut file = MockUploadFileHandler::new();
        file.expect_len().returning(move || 100);
        file.expect_is_empty().returning(move || false);
        file.expect_name().returning(move || Some(String::from("")));

        let service = get_service(MockFileUploadStoreApiMock::new());
        let res = service.validate_attached_file(&file).await;

        assert!(res.is_err());
    }

    #[tokio::test]
    async fn validate_attached_file_checks_file_name_length() {
        let mut file = MockUploadFileHandler::new();
        file.expect_len().returning(move || 100);
        file.expect_name()
            .returning(move || Some("abc".repeat(100)));
        file.expect_is_empty().returning(move || false);

        let service = get_service(MockFileUploadStoreApiMock::new());
        let res = service.validate_attached_file(&file).await;

        assert!(res.is_err());
    }

    #[tokio::test]
    async fn validate_attached_file_checks_file_type_error() {
        let mut file = MockUploadFileHandler::new();
        file.expect_len().returning(move || 100);
        file.expect_name()
            .returning(move || Some(String::from("goodname")));
        file.expect_is_empty().returning(move || false);
        file.expect_detect_content_type()
            .returning(move || Err(std::io::Error::other("test error")));

        let service = get_service(MockFileUploadStoreApiMock::new());
        let res = service.validate_attached_file(&file).await;

        assert!(res.is_err());
    }

    #[tokio::test]
    async fn validate_attached_file_checks_file_type_invalid() {
        let mut file = MockUploadFileHandler::new();
        file.expect_len().returning(move || 100);
        file.expect_name()
            .returning(move || Some(String::from("goodname")));
        file.expect_is_empty().returning(move || false);
        file.expect_detect_content_type()
            .returning(move || Ok(None));

        let service = get_service(MockFileUploadStoreApiMock::new());
        let res = service.validate_attached_file(&file).await;

        assert!(res.is_err());
    }

    #[tokio::test]
    async fn validate_attached_file_checks_file_empty() {
        let mut file = MockUploadFileHandler::new();
        file.expect_is_empty().returning(move || true);

        let service = get_service(MockFileUploadStoreApiMock::new());
        let res = service.validate_attached_file(&file).await;

        assert!(res.is_err());
    }

    #[tokio::test]
    async fn validate_attached_file_checks_file_type_not_in_list() {
        let mut file = MockUploadFileHandler::new();
        file.expect_len().returning(move || 100);
        file.expect_name()
            .returning(move || Some(String::from("goodname")));
        file.expect_is_empty().returning(move || false);
        file.expect_detect_content_type()
            .returning(move || Ok(Some(String::from("invalidfile"))));

        let service = get_service(MockFileUploadStoreApiMock::new());
        let res = service.validate_attached_file(&file).await;

        assert!(res.is_err());
    }

    #[tokio::test]
    async fn validate_attached_file_checks_valid() {
        let mut file = MockUploadFileHandler::new();
        file.expect_len().returning(move || 100);
        file.expect_is_empty().returning(move || false);
        file.expect_name()
            .returning(move || Some(String::from("goodname")));
        file.expect_detect_content_type()
            .returning(move || Ok(Some(String::from("application/pdf"))));

        let service = get_service(MockFileUploadStoreApiMock::new());
        let res = service.validate_attached_file(&file).await;

        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn get_temp_file_baseline() {
        let mut storage = MockFileUploadStoreApiMock::new();
        storage.expect_read_temp_upload_file().returning(|_| {
            Ok((
                Name::new("some_file").unwrap(),
                "hello_world".as_bytes().to_vec(),
            ))
        });
        let service = get_service(storage);

        let res = service.get_temp_file(&get_uuid_v4()).await;
        assert!(res.is_ok());
        assert_eq!(
            res.unwrap(),
            Some((
                Name::new("some_file").unwrap(),
                "hello_world".as_bytes().to_vec()
            ))
        );
    }

    #[tokio::test]
    async fn get_temp_file_err() {
        let mut storage = MockFileUploadStoreApiMock::new();
        storage
            .expect_read_temp_upload_file()
            .returning(|_| Err(persistence::Error::Io(std::io::Error::other("test error"))));
        let service = get_service(storage);

        let res = service.get_temp_file(&get_uuid_v4()).await;
        assert!(res.is_err());
    }
}
