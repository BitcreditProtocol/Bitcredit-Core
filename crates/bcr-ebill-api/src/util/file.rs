use async_trait::async_trait;
use std::{ffi::OsStr, path::Path};

#[cfg(test)]
use mockall::automock;

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
    fn len(&self) -> u64;
    /// Returns whether it's empty
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// detects the content type of the file by checking the first bytes
    async fn detect_content_type(&self) -> std::io::Result<Option<String>>;
}

pub fn validate_file_upload_id(file_upload_id: &Option<String>) -> crate::service::Result<()> {
    if let Some(id) = file_upload_id {
        if id.is_empty() {
            return Err(crate::service::Error::Validation(
                "Empty string is not a valid file upload id".to_string(),
            ));
        }
    }
    Ok(())
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
    format!(
        "{}_{}{}{}",
        stem,
        super::get_uuid_v4(),
        optional_dot,
        extension
    )
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn validate_file_upload_id_baseline() {
        assert!(validate_file_upload_id(&Some(String::from(""))).is_err(),);
        assert!(validate_file_upload_id(&Some(String::from("test"))).is_ok(),);
    }
}
