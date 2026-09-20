//! Closed provider-driver boundary.
//!
//! The service owns durable state and scheduling. A driver receives one
//! already-canonical delivery and reports only what can safely be known after
//! that single provider attempt.

use crate::ntfy::{NtfyEndpoint, NtfyMessage};
use crate::whatsapp::{WhatsappDriver, WhatsappMessage};

/// A bounded, provider-owned delivery shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery<'a> {
    /// Native ntfy text publication.
    Ntfy {
        topic: &'a str,
        title: Option<&'a str>,
        body: &'a str,
    },
    /// Official WhatsApp Cloud template send.
    Whatsapp {
        recipient: &'a str,
        template: &'a str,
        locale: &'a str,
        parameters: &'a [&'a str],
    },
}

/// Outcome of exactly one provider attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryOutcome {
    /// The provider returned a bounded acknowledgement identifier.
    Accepted { acknowledgement: String },
    /// The provider definitely asked the service to retry later.
    RateLimited,
    /// No request bytes were dispatched.
    Transient,
    /// The provider definitely rejected the canonical request.
    Permanent,
    /// Credentials, endpoint configuration, or trust policy are invalid.
    AuthOrConfig,
    /// Request bytes may have been dispatched; do not retry automatically.
    Ambiguous,
}

/// A local validation failure before any provider effect is possible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverError {
    InvalidEndpoint,
    InvalidDelivery,
}

/// The first-slice closed driver set. Adding a provider is an exhaustive,
/// reviewed extension rather than a plugin loader or caller-provided URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Driver {
    Ntfy(NtfyEndpoint),
    Whatsapp(WhatsappDriver),
}

impl Driver {
    /// Deliver one canonical item through its matching configured driver.
    pub fn deliver(&self, delivery: Delivery<'_>) -> Result<DeliveryOutcome, DriverError> {
        match (self, delivery) {
            (Self::Ntfy(endpoint), Delivery::Ntfy { topic, title, body }) => {
                endpoint.deliver(NtfyMessage { topic, title, body })
            }
            (
                Self::Whatsapp(driver),
                Delivery::Whatsapp {
                    recipient,
                    template,
                    locale,
                    parameters,
                },
            ) => driver.deliver(WhatsappMessage {
                recipient,
                template,
                locale,
                parameters,
            }),
            _ => Err(DriverError::InvalidDelivery),
        }
    }
}
