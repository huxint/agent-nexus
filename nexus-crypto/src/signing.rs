//! Canonical signing payload helpers shared across protocol domains.

use serde::Serialize;

/// Prefix every signed payload with a domain tag before canonical CBOR data.
///
/// This prevents a valid signature from one Nexus protocol structure being
/// replayed as another structure with an accidentally compatible encoding.
#[derive(Serialize)]
struct DomainSeparatedPayload<'a, T> {
    domain: &'a str,
    payload: &'a T,
}

/// Encode a domain-separated payload to deterministic CBOR bytes.
pub fn domain_separated_cbor<T: Serialize>(domain: &str, payload: &T) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    ciborium::into_writer(&DomainSeparatedPayload { domain, payload }, &mut buf)
        .map_err(|e| format!("CBOR encode: {e}"))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize)]
    struct Payload {
        value: u64,
    }

    #[test]
    fn domain_changes_payload_bytes() {
        let payload = Payload { value: 7 };
        let left = domain_separated_cbor("nexus:test:left", &payload).unwrap();
        let right = domain_separated_cbor("nexus:test:right", &payload).unwrap();

        assert_ne!(left, right);
    }
}
