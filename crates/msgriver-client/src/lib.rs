//! MsgRiver client library.
//!
//! This crate will provide API request construction, protected input handling,
//! rendering and stable CLI exit codes, API/CLI operation parity, and the
//! dependency and syscall-open exclusions that keep it structurally unable to
//! reach `msgriver-store` or SQLite. It depends only on `msgriver-protocol`
//! plus client transport and presentation support that is added in a later
//! layer.
//!
#![forbid(unsafe_code)]

use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::Path,
    time::Duration,
};

const IO_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RESPONSE: usize = 16 * 1024;

/// A local caller's message request. The service, not the caller, owns the
/// provider endpoint and ntfy topic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitRequest<'a> {
    pub idempotency_key: &'a str,
    pub body: &'a str,
    pub title: Option<&'a str>,
}

/// A durable acceptance response from the local service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitResponse {
    pub message_id: String,
    pub deduplicated: bool,
}

/// The client intentionally reveals no transport path or response body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientError {
    InvalidRequest,
    Connect,
    Transport,
    Rejected,
    Response,
}

/// Submit one message over the service's local Unix-domain HTTP interface.
pub fn submit(socket: &Path, request: SubmitRequest<'_>) -> Result<SubmitResponse, ClientError> {
    validate_request(&request)?;
    let body = json_body(&request);
    let mut stream = UnixStream::connect(socket).map_err(|_| ClientError::Connect)?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(IO_TIMEOUT)))
        .map_err(|_| ClientError::Transport)?;
    let head = format!(
        "POST /v1/messages HTTP/1.1\r\nHost: local\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(head.as_bytes())
        .and_then(|()| stream.write_all(body.as_bytes()))
        .and_then(|()| stream.flush())
        .map_err(|_| ClientError::Transport)?;
    let response = read_response(&mut stream)?;
    parse_response(&response)
}

fn validate_request(request: &SubmitRequest<'_>) -> Result<(), ClientError> {
    if request.idempotency_key.is_empty()
        || request.idempotency_key.len() > 128
        || !request
            .idempotency_key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        || request.body.is_empty()
        || request.body.len() > 4_096
        || request.body.contains('\0')
        || request
            .title
            .is_some_and(|title| title.is_empty() || title.len() > 256 || title.contains('\0'))
    {
        return Err(ClientError::InvalidRequest);
    }
    Ok(())
}

fn json_body(request: &SubmitRequest<'_>) -> String {
    let title = request.title.map_or_else(
        || "null".to_owned(),
        |value| format!("\"{}\"", json_escape(value)),
    );
    format!(
        "{{\"idempotency_key\":\"{}\",\"body\":\"{}\",\"title\":{title}}}",
        json_escape(request.idempotency_key),
        json_escape(request.body),
    )
}

fn json_escape(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            character if character.is_control() => {
                let code = character as u32;
                result.push_str("\\u");
                for shift in [12, 8, 4, 0] {
                    let digit = ((code >> shift) & 0xf) as u8;
                    result.push(char::from(b"0123456789abcdef"[usize::from(digit)]));
                }
            }
            character => result.push(character),
        }
    }
    result
}

fn read_response(stream: &mut UnixStream) -> Result<Vec<u8>, ClientError> {
    let mut response = Vec::new();
    let mut chunk = [0_u8; 1024];
    while response.len() < MAX_RESPONSE {
        let count = stream
            .read(&mut chunk)
            .map_err(|_| ClientError::Transport)?;
        if count == 0 {
            return Ok(response);
        }
        response.extend_from_slice(&chunk[..count]);
    }
    Err(ClientError::Response)
}

fn parse_response(response: &[u8]) -> Result<SubmitResponse, ClientError> {
    let separator = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(ClientError::Response)?;
    let head = std::str::from_utf8(&response[..separator]).map_err(|_| ClientError::Response)?;
    let mut line = head.lines();
    let status = line
        .next()
        .and_then(|line| line.split_ascii_whitespace().nth(1))
        .ok_or(ClientError::Response)?;
    if status == "409" || status == "400" || status == "401" || status == "403" {
        return Err(ClientError::Rejected);
    }
    if status != "202" && status != "200" {
        return Err(ClientError::Response);
    }
    let body =
        std::str::from_utf8(&response[separator + 4..]).map_err(|_| ClientError::Response)?;
    let message_id = json_string_field(body, "message_id").ok_or(ClientError::Response)?;
    let deduplicated = body.contains("\"deduplicated\":true");
    Ok(SubmitResponse {
        message_id,
        deduplicated,
    })
}

fn json_string_field(body: &str, key: &str) -> Option<String> {
    let prefix = format!("\"{key}\":\"");
    let (_, rest) = body.split_once(&prefix)?;
    let end = rest.find('"')?;
    let value = &rest[..end];
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Some(value.to_owned())
    } else {
        None
    }
}
