use super::{EmailMessage, NotificationEmailTransportApi};
use crate::{Error, Result};
use async_trait::async_trait;
use bcr_ebill_core::ServiceTraitBounds;
use log::error;
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct SendgridConfig {
    api_key: String,
    url: String,
}

pub struct SendgridTransport {
    config: SendgridConfig,
    client: reqwest::Client,
}

impl SendgridTransport {
    /// Creates a new instance of the SendgridTransport.
    #[allow(dead_code)]
    pub fn new(config: &SendgridConfig) -> Self {
        let client = reqwest::Client::new();
        Self {
            config: config.to_owned(),
            client,
        }
    }

    async fn send_http_request(&self, message: SendgridMessage) -> Result<()> {
        let url = format!("{}/v3/mail/send", self.config.url);
        let request = self
            .client
            .post(url)
            .json(&message)
            .bearer_auth(&self.config.api_key);
        let _ = request.send().await.map_err(|e| {
            error!("Failed to send email: {e}");
            Error::Network("Failed to send email".to_string())
        })?;
        Ok(())
    }
}

impl ServiceTraitBounds for SendgridTransport {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl NotificationEmailTransportApi for SendgridTransport {
    async fn send(&self, message: EmailMessage) -> Result<()> {
        self.send_http_request(message.try_into()?).await?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize)]
struct SendgridMessage {
    // This is very dynamic so I just use json value here
    personalizations: Vec<Value>,
    from: SendgridAddress,
    subject: String,
    content: Vec<SendgridContent>,
}

impl TryFrom<EmailMessage> for SendgridMessage {
    type Error = crate::Error;
    fn try_from(message: EmailMessage) -> Result<Self> {
        let from = SendgridAddress::new(message.from);
        let to = SendgridAddress::new(message.to);
        let personalizations = vec![serde_json::to_value(&from)?, serde_json::to_value(to)?];
        let m = SendgridMessage {
            personalizations,
            from,
            subject: message.subject,
            content: vec![SendgridContent::text(message.body)],
        };
        Ok(m)
    }
}

#[derive(Debug, Clone, Serialize)]
struct SendgridAddress {
    email: String,
    name: Option<String>,
}

impl SendgridAddress {
    /// Creates a new instance of the SendgridAddress struct.
    pub fn new(email: String) -> Self {
        Self { email, name: None }
    }
}

#[derive(Debug, Clone, Serialize)]
struct SendgridContent {
    #[serde(rename = "type")]
    content_type: String,
    value: String,
}

impl SendgridContent {
    /// Text content email
    #[allow(dead_code)]
    pub fn text(value: String) -> Self {
        Self {
            content_type: "text/plain".to_string(),
            value,
        }
    }

    /// HTML content email
    #[allow(dead_code)]
    pub fn html(value: String) -> Self {
        Self {
            content_type: "text/html".to_string(),
            value,
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_email_message_conversion() {
        let message = get_test_email_message();
        let m: SendgridMessage = message
            .clone()
            .try_into()
            .expect("Failed to convert email message");

        assert_eq!(&m.from.email, &message.from);
        assert!(m.personalizations.len() == 2);
        assert_eq!(&m.subject, &message.subject);
        assert_eq!(m.content.first().expect("No content").value, message.body);
    }

    #[tokio::test]
    async fn test_transport() {
        let _ = SendgridTransport::new(&SendgridConfig {
            api_key: "api_key".to_string(),
            url: "https://api.sendgrid.com".to_string(),
        });
    }

    pub fn get_test_email_message() -> EmailMessage {
        EmailMessage {
            from: "sender@example.com".to_string(),
            to: "recipient@example.com".to_string(),
            subject: "Hello World".to_string(),
            body: "This is a test email.".to_string(),
        }
    }
}
