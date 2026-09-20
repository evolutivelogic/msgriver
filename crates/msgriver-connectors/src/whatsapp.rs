//! Closed WhatsApp Cloud template command construction.
//!
//! This module deliberately accepts no URL, sender identity, bearer token,
//! header, or free-form body from a caller. Transport is added separately to
//! the same canonical command.

use crate::driver::{DeliveryOutcome, DriverError};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, StreamOwned,
    pki_types::{CertificateDer, ServerName},
};
use std::{
    io::{Read, Write},
    net::{IpAddr, TcpStream, ToSocketAddrs},
    sync::Arc,
    time::Duration,
};

const MAX_PARAMETERS: usize = 15;
const MAX_PARAMETER_BYTES: usize = 1_024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RESPONSE: usize = 16 * 1024;

/// A fixed operator-owned HTTPS Cloud endpoint.
#[derive(Clone, PartialEq, Eq)]
pub struct WhatsappEndpoint {
    host: String,
    port: u16,
    version: String,
    phone_id: String,
}

impl WhatsappEndpoint {
    /// Parse only the fixed Graph API shape. Callers never control this value.
    pub fn parse(url: &str, phone_id: &str) -> Result<Self, DriverError> {
        let authority_and_path = url
            .strip_prefix("https://")
            .ok_or(DriverError::InvalidEndpoint)?;
        if authority_and_path.is_empty()
            || authority_and_path.contains(['?', '#', '@'])
            || authority_and_path.contains(char::is_whitespace)
            || !valid_phone_id(phone_id)
        {
            return Err(DriverError::InvalidEndpoint);
        }
        let (authority, path) = authority_and_path
            .split_once('/')
            .ok_or(DriverError::InvalidEndpoint)?;
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) if !host.is_empty() && !host.contains(':') => (
                host,
                port.parse().map_err(|_| DriverError::InvalidEndpoint)?,
            ),
            Some(_) => return Err(DriverError::InvalidEndpoint),
            None => (authority, 443),
        };
        if !valid_host(host) || !valid_version(path) {
            return Err(DriverError::InvalidEndpoint);
        }
        Ok(Self {
            host: host.to_owned(),
            port,
            version: path.to_owned(),
            phone_id: phone_id.to_owned(),
        })
    }
}

/// One fixed endpoint/token/allowlist driver. Its token is intentionally not
/// `Debug` or otherwise printable.
#[derive(Clone, PartialEq, Eq)]
pub struct WhatsappDriver {
    endpoint: WhatsappEndpoint,
    token: String,
    registration: RegisteredTemplate,
    additional_root: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RegisteredTemplate {
    name: String,
    locale: String,
    parameter_count: usize,
}

impl std::fmt::Debug for WhatsappDriver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WhatsappDriver")
            .field("endpoint", &"redacted")
            .field("token", &"redacted")
            .field("registration", &self.registration)
            .finish()
    }
}

impl WhatsappDriver {
    pub fn new(
        endpoint: WhatsappEndpoint,
        token: String,
        registration: TemplateRegistration<'_>,
    ) -> Result<Self, DriverError> {
        Self::new_with_additional_root(endpoint, token, registration, None)
    }

    /// Construct a driver with one operator-owned DER trust anchor in addition
    /// to the WebPKI roots. This keeps loopback/private Cloud deployments from
    /// requiring an insecure TLS mode.
    pub fn new_with_additional_root(
        endpoint: WhatsappEndpoint,
        token: String,
        registration: TemplateRegistration<'_>,
        additional_root: Option<Vec<u8>>,
    ) -> Result<Self, DriverError> {
        if !valid_token(&token)
            || !valid_template(registration.name)
            || !valid_locale(registration.locale)
            || registration.parameter_count > MAX_PARAMETERS
            || additional_root
                .as_ref()
                .is_some_and(|certificate| certificate.is_empty() || certificate.len() > 32 * 1024)
        {
            return Err(DriverError::InvalidEndpoint);
        }
        if let Some(certificate) = additional_root.as_ref() {
            let mut roots = RootCertStore::empty();
            roots
                .add(CertificateDer::from(certificate.clone()))
                .map_err(|_| DriverError::InvalidEndpoint)?;
        }
        Ok(Self {
            endpoint,
            token,
            registration: RegisteredTemplate {
                name: registration.name.to_owned(),
                locale: registration.locale.to_owned(),
                parameter_count: registration.parameter_count,
            },
            additional_root,
        })
    }

    /// Make one verified HTTPS Cloud request. A write or response uncertainty
    /// is never retried here; the durable service owns any later decision.
    pub fn deliver(&self, message: WhatsappMessage<'_>) -> Result<DeliveryOutcome, DriverError> {
        let body = request_body(
            TemplateRegistration {
                name: &self.registration.name,
                locale: &self.registration.locale,
                parameter_count: self.registration.parameter_count,
            },
            message,
        )?;
        let address = (self.endpoint.host.as_str(), self.endpoint.port)
            .to_socket_addrs()
            .map_err(|_| DriverError::InvalidEndpoint)?
            .next()
            .ok_or(DriverError::InvalidEndpoint)?;
        let tcp = match TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) {
            Ok(stream) => stream,
            Err(_) => return Ok(DeliveryOutcome::Transient),
        };
        if tcp.set_read_timeout(Some(IO_TIMEOUT)).is_err()
            || tcp.set_write_timeout(Some(IO_TIMEOUT)).is_err()
        {
            return Ok(DeliveryOutcome::Transient);
        }
        let mut roots = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        if let Some(certificate) = self.additional_root.as_ref() {
            roots
                .add(CertificateDer::from(certificate.clone()))
                .map_err(|_| DriverError::InvalidEndpoint)?;
        }
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name = match self.endpoint.host.parse::<IpAddr>() {
            Ok(address) => ServerName::from(address).to_owned(),
            Err(_) => ServerName::try_from(self.endpoint.host.as_str())
                .map_err(|_| DriverError::InvalidEndpoint)?
                .to_owned(),
        };
        let connection = ClientConnection::new(Arc::new(config), name)
            .map_err(|_| DriverError::InvalidEndpoint)?;
        let mut stream = StreamOwned::new(connection, tcp);
        let request = self.request(&body);
        if stream.write_all(&request).is_err() || stream.flush().is_err() {
            return Ok(DeliveryOutcome::Ambiguous);
        }
        let response = read_response(&mut stream);
        Ok(classify_response(response.as_deref()))
    }

    fn request(&self, body: &[u8]) -> Vec<u8> {
        let host = if self.endpoint.port == 443 {
            self.endpoint.host.clone()
        } else {
            format!("{}:{}", self.endpoint.host, self.endpoint.port)
        };
        let mut request = format!(
            "POST /{}/{}/messages HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.endpoint.version, self.endpoint.phone_id, self.token, body.len(),
        ).into_bytes();
        request.extend_from_slice(body);
        request
    }
}

fn read_response(stream: &mut impl Read) -> Option<Vec<u8>> {
    let mut response = Vec::new();
    let mut chunk = [0_u8; 1024];
    while response.len() < MAX_RESPONSE {
        let count = stream.read(&mut chunk).ok()?;
        if count == 0 {
            return Some(response);
        }
        if response.len().checked_add(count)? > MAX_RESPONSE {
            return None;
        }
        response.extend_from_slice(&chunk[..count]);
    }
    None
}

fn classify_response(response: Option<&[u8]>) -> DeliveryOutcome {
    let Some(response) = response else {
        return DeliveryOutcome::Ambiguous;
    };
    let Some(separator) = response.windows(4).position(|window| window == b"\r\n\r\n") else {
        return DeliveryOutcome::Ambiguous;
    };
    let Ok(head) = std::str::from_utf8(&response[..separator]) else {
        return DeliveryOutcome::Ambiguous;
    };
    let Some(status) = head
        .lines()
        .next()
        .and_then(|line| line.split_ascii_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
    else {
        return DeliveryOutcome::Ambiguous;
    };
    if status == 200 {
        return serde_json::from_slice::<serde_json::Value>(&response[separator + 4..])
            .ok()
            .and_then(|value| {
                value
                    .get("messages")?
                    .as_array()?
                    .first()?
                    .get("id")?
                    .as_str()
                    .map(str::to_owned)
            })
            .filter(|value| !value.is_empty() && value.len() <= 256 && !value.contains('\0'))
            .map_or(DeliveryOutcome::Ambiguous, |acknowledgement| {
                DeliveryOutcome::Accepted { acknowledgement }
            });
    }
    match status {
        401 | 403 | 404 => DeliveryOutcome::AuthOrConfig,
        429 => DeliveryOutcome::RateLimited,
        400..=499 => DeliveryOutcome::Permanent,
        _ => DeliveryOutcome::Ambiguous,
    }
}

fn valid_host(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
}

fn valid_version(value: &str) -> bool {
    value.len() >= 2
        && value.starts_with('v')
        && value[1..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
}

fn valid_phone_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 32 && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn valid_token(value: &str) -> bool {
    !value.is_empty() && value.len() <= 4_096 && value.bytes().all(|byte| byte.is_ascii_graphic())
}

/// One operator-registered text-template shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TemplateRegistration<'a> {
    pub name: &'a str,
    pub locale: &'a str,
    pub parameter_count: usize,
}

/// A caller's closed WhatsApp template command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhatsappMessage<'a> {
    pub recipient: &'a str,
    pub template: &'a str,
    pub locale: &'a str,
    pub parameters: &'a [&'a str],
}

/// Validate a command against exactly one operator registration and construct
/// the fixed Cloud API JSON request body.
pub fn request_body(
    registration: TemplateRegistration<'_>,
    message: WhatsappMessage<'_>,
) -> Result<Vec<u8>, DriverError> {
    if !valid_recipient(message.recipient)
        || !valid_template(registration.name)
        || !valid_locale(registration.locale)
        || message.template != registration.name
        || message.locale != registration.locale
        || message.parameters.len() != registration.parameter_count
        || message.parameters.len() > MAX_PARAMETERS
        || message
            .parameters
            .iter()
            .any(|value| !valid_parameter(value))
    {
        return Err(DriverError::InvalidDelivery);
    }
    let parameters: Vec<serde_json::Value> = message
        .parameters
        .iter()
        .map(|text| serde_json::json!({ "type": "text", "text": text }))
        .collect();
    serde_json::to_vec(&serde_json::json!({
        "messaging_product": "whatsapp",
        "to": message.recipient,
        "type": "template",
        "template": {
            "name": message.template,
            "language": { "code": message.locale },
            "components": [{ "type": "body", "parameters": parameters }]
        }
    }))
    .map_err(|_| DriverError::InvalidDelivery)
}

fn valid_recipient(value: &str) -> bool {
    let bytes = value.as_bytes();
    (8..=16).contains(&bytes.len())
        && bytes.first() == Some(&b'+')
        && matches!(bytes.get(1), Some(b'1'..=b'9'))
        && bytes[2..].iter().all(u8::is_ascii_digit)
}

fn valid_template(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn valid_locale(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 5
        && bytes[2] == b'_'
        && bytes[..2].iter().all(u8::is_ascii_lowercase)
        && bytes[3..].iter().all(u8::is_ascii_uppercase)
}

fn valid_parameter(value: &&str) -> bool {
    !value.is_empty() && value.len() <= MAX_PARAMETER_BYTES && !value.contains('\0')
}

#[cfg(test)]
mod tests {
    use super::{TemplateRegistration, WhatsappMessage, request_body};

    #[test]
    fn a_registered_text_template_has_only_the_fixed_cloud_shape() {
        let bytes = request_body(
            TemplateRegistration {
                name: "delivery_notice",
                locale: "en_US",
                parameter_count: 1,
            },
            WhatsappMessage {
                recipient: "+15551234567",
                template: "delivery_notice",
                locale: "en_US",
                parameters: &["accepted"],
            },
        )
        .expect("registered command");
        assert_eq!(
            std::str::from_utf8(&bytes).expect("json"),
            r#"{"messaging_product":"whatsapp","template":{"components":[{"parameters":[{"text":"accepted","type":"text"}],"type":"body"}],"language":{"code":"en_US"},"name":"delivery_notice"},"to":"+15551234567","type":"template"}"#,
        );
    }

    #[test]
    fn unregistered_or_noncanonical_command_is_refused() {
        let registration = TemplateRegistration {
            name: "delivery_notice",
            locale: "en_US",
            parameter_count: 1,
        };
        for message in [
            WhatsappMessage {
                recipient: "15551234567",
                template: "delivery_notice",
                locale: "en_US",
                parameters: &["ok"],
            },
            WhatsappMessage {
                recipient: "+15551234567",
                template: "other",
                locale: "en_US",
                parameters: &["ok"],
            },
            WhatsappMessage {
                recipient: "+15551234567",
                template: "delivery_notice",
                locale: "pt_BR",
                parameters: &["ok"],
            },
            WhatsappMessage {
                recipient: "+15551234567",
                template: "delivery_notice",
                locale: "en_US",
                parameters: &[],
            },
        ] {
            assert!(request_body(registration, message).is_err());
        }
    }
}
