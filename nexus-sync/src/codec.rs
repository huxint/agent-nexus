//! JSON codec for the sync request-response protocol.

use libp2p::{request_response, StreamProtocol};
use serde::{de::DeserializeOwned, Serialize};

use crate::message::{SyncRequest, SyncResponse};

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

    serde_json::from_slice(&buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

async fn write_limited_json<T, M>(io: &mut T, message: &M, max_bytes: usize) -> std::io::Result<()>
where
    T: futures::AsyncWrite + Unpin + Send,
    M: Serialize,
{
    use futures::AsyncWriteExt;

    let bytes = serde_json::to_vec(message)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if bytes.len() > max_bytes {
        return Err(sync_message_too_large(max_bytes));
    }
    io.write_all(&bytes).await
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
        let bytes = serde_json::to_vec(&request).unwrap();
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
}
