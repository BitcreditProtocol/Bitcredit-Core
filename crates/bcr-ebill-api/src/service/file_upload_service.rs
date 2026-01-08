use super::{Error, Result};
use crate::constants::{
    MAX_DOCUMENT_FILE_SIZE_BYTES, MAX_FILE_NAME_CHARACTERS, MAX_PICTURE_FILE_SIZE_BYTES,
    VALID_FILE_MIME_TYPES,
};
use crate::util::get_uuid_v4;
use async_trait::async_trait;
use bcr_ebill_core::application::{ServiceTraitBounds, UploadFileResult, ValidationError};
use bcr_ebill_core::protocol::{Name, ProtocolValidationError};
use bcr_ebill_persistence::file_upload::FileUploadStoreApi;
use log::{debug, error};
use std::sync::Arc;
use std::{ffi::OsStr, path::Path};
use uuid::Uuid;

#[cfg(test)]
use mockall::automock;

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait FileUploadServiceApi: ServiceTraitBounds {
    /// validates the given uploaded file
    async fn validate_attached_file(&self, file: &dyn UploadFileHandler) -> Result<()>;

    /// uploads files
    async fn upload_file(&self, file: &dyn UploadFileHandler) -> Result<UploadFileResult>;

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
    async fn validate_attached_file(&self, file: &dyn UploadFileHandler) -> Result<()> {
        if file.is_empty() {
            return Err(Error::Validation(
                ProtocolValidationError::FileIsEmpty.into(),
            ));
        }

        if file.len() > MAX_DOCUMENT_FILE_SIZE_BYTES {
            return Err(Error::Validation(
                ProtocolValidationError::FileIsTooBig(MAX_DOCUMENT_FILE_SIZE_BYTES).into(),
            ));
        }

        let name = match file.name() {
            Some(n) => n,
            None => {
                return Err(Error::Validation(
                    ProtocolValidationError::InvalidFileName(MAX_FILE_NAME_CHARACTERS).into(),
                ));
            }
        };

        if name.trim().is_empty() || name.trim().chars().count() > MAX_FILE_NAME_CHARACTERS {
            return Err(Error::Validation(
                ProtocolValidationError::InvalidFileName(MAX_FILE_NAME_CHARACTERS).into(),
            ));
        }

        let detected_type = match file.detect_content_type().await.map_err(|e| {
            error!("Could not detect content type for file {name}: {e}");
            Error::Validation(ProtocolValidationError::InvalidContentType.into())
        })? {
            Some(t) => t,
            None => {
                return Err(Error::Validation(
                    ProtocolValidationError::InvalidContentType.into(),
                ));
            }
        };

        if !VALID_FILE_MIME_TYPES.contains(&detected_type.as_str()) {
            return Err(Error::Validation(
                ProtocolValidationError::InvalidContentType.into(),
            ));
        }
        Ok(())
    }

    async fn upload_file(&self, file: &dyn UploadFileHandler) -> Result<UploadFileResult> {
        // create a new random id
        let file_upload_id = get_uuid_v4();
        // sanitize and randomize file name and write file into the temporary folder
        let file_name = Name::new(generate_unique_filename(
            &sanitize_filename(&file.name().ok_or(Error::Validation(
                ProtocolValidationError::InvalidFileName(MAX_FILE_NAME_CHARACTERS).into(),
            ))?),
            file.extension(),
        ))?;
        let read_file = file
            .get_contents()
            .await
            .map_err(bcr_ebill_persistence::Error::Io)?;
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
            .map_err(|_| {
                crate::service::Error::Validation(ValidationError::NoFileForFileUploadId)
            })?;
        let (file_name, file_bytes) = file;
        return Ok(Some((file_name, file_bytes)));
    }
}

#[cfg_attr(test, automock)]
#[async_trait]
pub trait UploadFileHandler: Send + Sync {
    /// Read the attached uploaded file
    async fn get_contents(&self) -> std::io::Result<Vec<u8>>;
    /// Returns the extension for an uploaded file
    fn extension(&self) -> Option<String>;
    /// Returns the name for an uploaded file
    fn name(&self) -> Option<String>;
    /// Returns the file length for an uploaded file
    fn len(&self) -> usize;
    /// Returns whether it's empty
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// detects the content type of the file by checking the first bytes
    async fn detect_content_type(&self) -> std::io::Result<Option<String>>;
}

/// The different types of files we have in the system
pub enum UploadFileType {
    Document,
    Picture,
}

impl UploadFileType {
    pub fn check_file_size(&self, bytes_len: usize) -> bool {
        match self {
            UploadFileType::Document => bytes_len <= MAX_DOCUMENT_FILE_SIZE_BYTES,
            UploadFileType::Picture => bytes_len <= MAX_PICTURE_FILE_SIZE_BYTES,
        }
    }

    pub fn max_file_size(&self) -> usize {
        match self {
            UploadFileType::Document => MAX_DOCUMENT_FILE_SIZE_BYTES,
            UploadFileType::Picture => MAX_PICTURE_FILE_SIZE_BYTES,
        }
    }
}

/// Function to sanitize the filename by removing unwanted characters.
pub fn sanitize_filename(filename: &str) -> String {
    filename
        .to_lowercase()
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '.' || *c == '-' || *c == '_')
        .collect()
}

pub fn detect_content_type_for_bytes(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 256 {
        return None; // can't decide with so few bytes
    }
    infer::get(&bytes[..256]).map(|t| t.mime_type().to_owned())
}

/// Function to generate a unique filename using UUID while preserving the file extension.
pub fn generate_unique_filename(original_filename: &str, extension: Option<String>) -> String {
    let path = Path::new(original_filename);
    let stem = path.file_stem().and_then(OsStr::to_str).unwrap_or("");
    let extension = extension.unwrap_or_default();
    let optional_dot = if extension.is_empty() { "" } else { "." };
    format!("{}_{}{}{}", stem, get_uuid_v4(), optional_dot, extension)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{tests::tests::MockFileUploadStoreApiMock, util::get_uuid_v4};
    use MockUploadFileHandler;
    use std::sync::Arc;

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
    async fn upload_file_baseline_fails_on_file_creation() {
        let storage = MockFileUploadStoreApiMock::new();
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
        let storage = MockFileUploadStoreApiMock::new();
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
            .returning(|_, _, _| Err(bcr_ebill_persistence::Error::EncodingError));
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
        storage.expect_read_temp_upload_file().returning(|_| {
            Err(bcr_ebill_persistence::Error::Io(std::io::Error::other(
                "test error",
            )))
        });
        let service = get_service(storage);

        let res = service.get_temp_file(&get_uuid_v4()).await;
        assert!(res.is_err());
    }

    #[test]
    fn sanitize_filename_basic() {
        assert_eq!(
            sanitize_filename("FI$$LE()()NAME.PD@@@F"),
            String::from("filename.pdf")
        );
    }

    #[test]
    fn sanitize_filename_empty() {
        assert_eq!(sanitize_filename(""), String::from(""));
    }

    #[test]
    fn sanitize_filename_sane() {
        assert_eq!(
            sanitize_filename("invoice-october_2024.pdf"),
            String::from("invoice-october_2024.pdf")
        );
    }

    #[test]
    fn generate_unique_filename_basic() {
        assert_eq!(
            generate_unique_filename("file_name.pdf", Some(String::from("pdf"))),
            String::from("file_name_00000000-0000-0000-0000-000000000000.pdf")
        );
    }

    #[test]
    fn generate_unique_filename_no_ext() {
        assert_eq!(
            generate_unique_filename("file_name", None),
            String::from("file_name_00000000-0000-0000-0000-000000000000")
        );
    }

    #[test]
    fn generate_unique_filename_multi_ext() {
        assert_eq!(
            generate_unique_filename("file_name", Some(String::from("tar.gz"))),
            String::from("file_name_00000000-0000-0000-0000-000000000000.tar.gz")
        );
    }
}
