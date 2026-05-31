//! JSON codec for the sync request-response protocol.

use libp2p::{request_response, StreamProtocol};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::message::{SyncRequest, SyncResponse};

/// Current sync JSON frame envelope version.
pub const SYNC_FRAME_VERSION: u16 = 1;

/// Maximum size of a single JSON sync protocol frame.
///
/// The current protocol sends each Merkle block as one JSON response with
/// base64-encoded CBOR, so this cap is intentionally high. Larger workspace
/// files should eventually move through chunked blocks instead of one frame.
pub const MAX_SYNC_MESSAGE_BYTES: usize = 128 * 1024 * 1024;

/// JSON codec for workspace sync messages.
#[derive(Clone, Debug, Default)]
pub struct SyncCodec;

#[async_trait::async_trait]
impl request_response::Codec for SyncCodec {
    type Protocol = StreamProtocol;
    type Request = SyncRequest;
    type Response = SyncResponse;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Request>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        read_limited_json(io, MAX_SYNC_MESSAGE_BYTES).await
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Response>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        read_limited_json(io, MAX_SYNC_MESSAGE_BYTES).await
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> std::io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        write_limited_json(io, &req, MAX_SYNC_MESSAGE_BYTES).await
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> std::io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        write_limited_json(io, &res, MAX_SYNC_MESSAGE_BYTES).await
    }
}

async fn read_limited_json<T, M>(io: &mut T, max_bytes: usize) -> std::io::Result<M>
where
    T: futures::AsyncRead + Unpin + Send,
    M: DeserializeOwned,
{
    use futures::AsyncReadExt;

    let mut buf = Vec::new();
    let mut limited = io.take(max_bytes as u64 + 1);
    limited.read_to_end(&mut buf).await?;
    if buf.len() > max_bytes {
        return Err(sync_message_too_large(max_bytes));
    }

    decode_versioned_json(&buf)
}

async fn write_limited_json<T, M>(io: &mut T, message: &M, max_bytes: usize) -> std::io::Result<()>
where
    T: futures::AsyncWrite + Unpin + Send,
    M: Serialize,
{
    use futures::AsyncWriteExt;

    let bytes = encode_versioned_json(message)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if bytes.len() > max_bytes {
        return Err(sync_message_too_large(max_bytes));
    }
    io.write_all(&bytes).await
}

#[derive(Serialize)]
struct SyncFrame<'a, M> {
    version: u16,
    message: &'a M,
}

#[derive(Deserialize)]
struct IncomingSyncFrame {
    version: u16,
    message: serde_json::Value,
}

fn encode_versioned_json<M: Serialize>(message: &M) -> serde_json::Result<Vec<u8>> {
    serde_json::to_vec(&SyncFrame {
        version: SYNC_FRAME_VERSION,
        message,
    })
}

fn decode_versioned_json<M: DeserializeOwned>(bytes: &[u8]) -> std::io::Result<M> {
    match serde_json::from_slice::<IncomingSyncFrame>(bytes) {
        Ok(frame) => {
            if frame.version != SYNC_FRAME_VERSION {
                return Err(unsupported_sync_frame_version(frame.version));
            }
            serde_json::from_value(frame.message)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        }
        Err(frame_err) => {
            // Backward compatibility for peers that still send bare v1 request
            // or response JSON without the versioned envelope.
            serde_json::from_slice(bytes)
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, frame_err))
        }
    }
}

fn unsupported_sync_frame_version(version: u16) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!(
            "unsupported sync protocol version {version}; supported version is {SYNC_FRAME_VERSION}"
        ),
    )
}

fn sync_message_too_large(max_bytes: usize) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("sync message exceeds {max_bytes} byte limit"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::io::Cursor;

    #[tokio::test]
    async fn read_limited_json_rejects_oversized_frame() {
        let mut input = Cursor::new(vec![b' '; 9]);
        let err = read_limited_json::<_, SyncRequest>(&mut input, 8)
            .await
            .expect_err("oversized frame should fail");

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("exceeds 8 byte limit"));
    }

    #[tokio::test]
    async fn write_limited_json_rejects_oversized_frame() {
        let response = SyncResponse::Error {
            message: "too large".repeat(4),
        };
        let mut output = Cursor::new(Vec::new());
        let err = write_limited_json(&mut output, &response, 8)
            .await
            .expect_err("oversized frame should fail");

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("exceeds 8 byte limit"));
    }

    #[tokio::test]
    async fn read_limited_json_accepts_valid_frame_within_limit() {
        let request = SyncRequest::SocialEventsRequest {
            known_event_ids: vec!["event-a".into()],
            limit: 10,
        };
        let bytes = encode_versioned_json(&request).unwrap();
        let mut input = Cursor::new(bytes.clone());

        let decoded: SyncRequest = read_limited_json(&mut input, bytes.len())
            .await
            .expect("valid frame should decode");

        assert!(matches!(
            decoded,
            SyncRequest::SocialEventsRequest { known_event_ids, limit: 10 }
                if known_event_ids == vec!["event-a".to_string()]
        ));
    }

    #[tokio::test]
    async fn read_limited_json_accepts_legacy_bare_v1_message() {
        let request = SyncRequest::SocialEventsRequest {
            known_event_ids: vec!["event-a".into()],
            limit: 10,
        };
        let bytes = serde_json::to_vec(&request).unwrap();
        let mut input = Cursor::new(bytes.clone());

        let decoded: SyncRequest = read_limited_json(&mut input, bytes.len())
            .await
            .expect("legacy v1 frame should decode");

        assert!(matches!(
            decoded,
            SyncRequest::SocialEventsRequest { known_event_ids, limit: 10 }
                if known_event_ids == vec!["event-a".to_string()]
        ));
    }

    #[tokio::test]
    async fn read_limited_json_rejects_unsupported_version() {
        let frame = serde_json::json!({
            "version": SYNC_FRAME_VERSION + 1,
            "message": {
                "type": "SocialEventsRequest",
                "payload": {
                    "known_event_ids": [],
                    "limit": 1
                }
            }
        });
        let bytes = serde_json::to_vec(&frame).unwrap();
        let mut input = Cursor::new(bytes.clone());

        let err = read_limited_json::<_, SyncRequest>(&mut input, bytes.len())
            .await
            .expect_err("unsupported versions must be rejected");

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err
            .to_string()
            .contains("unsupported sync protocol version"));
    }

    #[tokio::test]
    async fn write_limited_json_emits_versioned_frame() {
        let request = SyncRequest::SocialEventsRequest {
            known_event_ids: Vec::new(),
            limit: 1,
        };
        let mut output = Cursor::new(Vec::new());

        write_limited_json(&mut output, &request, MAX_SYNC_MESSAGE_BYTES)
            .await
            .expect("write should succeed");

        let frame: serde_json::Value = serde_json::from_slice(output.get_ref()).unwrap();
        assert_eq!(frame["version"], SYNC_FRAME_VERSION);
        assert_eq!(frame["message"]["type"], "SocialEventsRequest");
    }
}
