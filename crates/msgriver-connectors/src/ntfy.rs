//! Small, fixed-egress ntfy HTTP client used by the first runnable service.

use crate::driver::{DeliveryOutcome, DriverError};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    time::Duration,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RESPONSE_HEADERS: usize = 16 * 1024;

/// A validated, operator-owned ntfy HTTP endpoint. Callers can select neither
/// its host nor its credentials: a service creates this once from its config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfyEndpoint {
    host: String,
    port: u16,
    prefix: String,
}

/// A fixed-destination ntfy publication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfyMessage<'a> {
    pub topic: &'a str,
    pub title: Option<&'a str>,
    pub body: &'a str,
}

/// What is safely known after a single outbound attempt.
impl NtfyEndpoint {
    /// Parse only plain HTTP for the M2 local ntfy deployment. TLS transport is
    /// added with the published driver boundary in M3; accepting HTTPS without
    /// verification would be worse than refusing it.
    pub fn parse(value: &str) -> Result<Self, DriverError> {
        let authority_and_path = value
            .strip_prefix("http://")
            .ok_or(DriverError::InvalidEndpoint)?;
        if authority_and_path.is_empty()
            || authority_and_path.contains(['?', '#', '@'])
            || authority_and_path.contains(char::is_whitespace)
        {
            return Err(DriverError::InvalidEndpoint);
        }
        let (authority, suffix) = authority_and_path
            .split_once('/')
            .map_or((authority_and_path, ""), |(authority, path)| {
                (authority, path)
            });
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => (
                host,
                port.parse::<u16>()
                    .map_err(|_| DriverError::InvalidEndpoint)?,
            ),
            Some(_) => return Err(DriverError::InvalidEndpoint),
            None => (authority, 80),
        };
        if host != "127.0.0.1" && host != "localhost" {
            return Err(DriverError::InvalidEndpoint);
        }
        let prefix = if suffix.is_empty() {
            String::new()
        } else {
            let candidate = format!("/{suffix}");
            if candidate
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b' ')
            {
                return Err(DriverError::InvalidEndpoint);
            }
            candidate.trim_end_matches('/').to_owned()
        };
        Ok(Self {
            host: host.to_owned(),
            port,
            prefix,
        })
    }

    /// Send exactly one bounded HTTP/1.1 request. A successful status is a
    /// provider acknowledgement; any post-write failure remains ambiguous.
    pub fn deliver(&self, message: NtfyMessage<'_>) -> Result<DeliveryOutcome, DriverError> {
        validate_message(&message)?;
        let address = SocketAddr::from(([127, 0, 0, 1], self.port));
        let mut stream = match TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) {
            Ok(stream) => stream,
            Err(_) => return Ok(DeliveryOutcome::Transient),
        };
        if stream.set_read_timeout(Some(IO_TIMEOUT)).is_err()
            || stream.set_write_timeout(Some(IO_TIMEOUT)).is_err()
        {
            return Ok(DeliveryOutcome::Transient);
        }
        let request = request_bytes(self, &message);
        if stream.write_all(&request).is_err() || stream.flush().is_err() {
            return Ok(DeliveryOutcome::Ambiguous);
        }
        let response = match response(&mut stream) {
            Some(response) => response,
            None => return Ok(DeliveryOutcome::Ambiguous),
        };
        if (200..300).contains(&response.status) {
            let acknowledgement = serde_json::from_slice::<serde_json::Value>(&response.body)
                .ok()
                .and_then(|value| value.get("id")?.as_str().map(str::to_owned))
                .filter(|value| valid_acknowledgement(value))
                .ok_or(DriverError::InvalidDelivery)?;
            Ok(DeliveryOutcome::Accepted { acknowledgement })
        } else if response.status == 429 {
            Ok(DeliveryOutcome::RateLimited)
        } else if matches!(response.status, 401 | 403 | 404) {
            Ok(DeliveryOutcome::AuthOrConfig)
        } else if (400..500).contains(&response.status) {
            Ok(DeliveryOutcome::Permanent)
        } else {
            Ok(DeliveryOutcome::Ambiguous)
        }
    }
}

fn validate_message(message: &NtfyMessage<'_>) -> Result<(), DriverError> {
    if message.topic.is_empty()
        || message.topic.len() > 64
        || !message
            .topic
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        || message.body.is_empty()
        || message.body.len() > 4_096
        || message.body.contains('\0')
        || message.title.is_some_and(|title| {
            title.is_empty() || title.len() > 256 || title.contains(['\r', '\n', '\0'])
        })
    {
        return Err(DriverError::InvalidDelivery);
    }
    Ok(())
}

fn request_bytes(endpoint: &NtfyEndpoint, message: &NtfyMessage<'_>) -> Vec<u8> {
    let path = format!("{}/{}", endpoint.prefix, message.topic);
    let host = if endpoint.port == 80 {
        endpoint.host.clone()
    } else {
        format!("{}:{}", endpoint.host, endpoint.port)
    };
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: MsgRiver/0.1.0-alpha\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n",
        message.body.len()
    )
    .into_bytes();
    if let Some(title) = message.title {
        request.extend_from_slice(b"Title: ");
        request.extend_from_slice(title.as_bytes());
        request.extend_from_slice(b"\r\n");
    }
    request.extend_from_slice(b"\r\n");
    request.extend_from_slice(message.body.as_bytes());
    request
}

struct NtfyResponse {
    status: u16,
    body: Vec<u8>,
}

fn response(stream: &mut TcpStream) -> Option<NtfyResponse> {
    let deadline = std::time::Instant::now() + IO_TIMEOUT;
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 1024];
    while bytes.len() < MAX_RESPONSE_HEADERS {
        if std::time::Instant::now() >= deadline {
            return None;
        }
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        bytes.extend_from_slice(&chunk[..read]);
        if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
            let header_end = bytes.windows(4).position(|window| window == b"\r\n\r\n")? + 4;
            let line_end = bytes.windows(2).position(|window| window == b"\r\n")?;
            let line = std::str::from_utf8(&bytes[..line_end]).ok()?;
            let mut pieces = line.split_ascii_whitespace();
            let version = pieces.next()?;
            if version != "HTTP/1.1" && version != "HTTP/1.0" {
                return None;
            }
            let status = pieces.next()?.parse::<u16>().ok()?;
            let headers = std::str::from_utf8(&bytes[line_end + 2..header_end]).ok()?;
            let length = headers
                .split("\r\n")
                .filter_map(|line| line.split_once(':'))
                .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .map(|(_, value)| value.trim().parse::<usize>().ok())
                .collect::<Option<Vec<_>>>()?;
            if length.len() != 1 || length[0] > MAX_RESPONSE_HEADERS - header_end {
                return None;
            }
            while bytes.len() < header_end + length[0] {
                if std::time::Instant::now() >= deadline {
                    return None;
                }
                let read = stream.read(&mut chunk).ok()?;
                if read == 0 || bytes.len().checked_add(read)? > MAX_RESPONSE_HEADERS {
                    return None;
                }
                bytes.extend_from_slice(&chunk[..read]);
            }
            if bytes.len() != header_end + length[0] {
                return None;
            }
            return Some(NtfyResponse {
                status,
                body: bytes[header_end..].to_vec(),
            });
        }
    }
    None
}

fn valid_acknowledgement(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.contains('\0')
}
