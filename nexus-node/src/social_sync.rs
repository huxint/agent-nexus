use std::collections::HashSet;
use std::path::Path;
use std::time::Duration;

use nexus_agent::{SocialEvent, SocialMemory};
use nexus_network::Network;
use nexus_sync::codec::MAX_SYNC_MESSAGE_BYTES;
use nexus_sync::message::SyncResponse;
use nexus_sync::SyncClient;

use crate::state::write_file_atomic;

const MAX_SOCIAL_EVENTS_PER_RESPONSE: usize = 512;

pub fn load_social_memory(path: &Path) -> Result<SocialMemory, Box<dyn std::error::Error>> {
    if path.exists() {
        let data = std::fs::read(path)?;
        let memory = serde_json::from_slice(&data)?;
        Ok(memory)
    } else {
        Ok(SocialMemory::new())
    }
}

pub fn save_social_memory(
    path: &Path,
    memory: &SocialMemory,
) -> Result<(), Box<dyn std::error::Error>> {
    write_file_atomic(path, &serde_json::to_vec_pretty(memory)?)?;
    Ok(())
}

pub fn record_social_events(
    path: &Path,
    memory: &mut SocialMemory,
    events: impl IntoIterator<Item = SocialEvent>,
) -> Result<(), Box<dyn std::error::Error>> {
    if memory.ingest_events(events)? > 0 {
        save_social_memory(path, memory)?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocialIngestOutcome {
    Inserted,
    Duplicate,
}

pub fn ingest_social_event_bytes(
    data: &[u8],
    social_memory: &mut SocialMemory,
    memory_path: &Path,
) -> Result<SocialIngestOutcome, Box<dyn std::error::Error>> {
    if social_memory.ingest_json(data)? {
        save_social_memory(memory_path, social_memory)?;
        Ok(SocialIngestOutcome::Inserted)
    } else {
        Ok(SocialIngestOutcome::Duplicate)
    }
}

pub async fn publish_social_event_with_retry(network: &Network, event: &SocialEvent) {
    let data = match event.to_json() {
        Ok(data) => data,
        Err(err) => {
            tracing::warn!("failed to serialize social event {}: {err}", event.id);
            return;
        }
    };

    let mut last_error = None;
    for _ in 0..8 {
        match network.publish_social_event(data.clone()).await {
            Ok(()) => return,
            Err(err) => {
                last_error = Some(err);
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    }

    if let Some(err) = last_error {
        tracing::debug!("social event {} not broadcast yet: {err}", event.id);
    }
}

pub async fn replay_social_memory(network: &Network, social_memory: &SocialMemory) {
    for event in social_memory.events() {
        publish_social_event_with_retry(network, event).await;
    }
}

pub fn social_events_response(
    social_memory: &SocialMemory,
    known_event_ids: &[String],
    limit: usize,
) -> SyncResponse {
    social_events_response_with_caps(
        social_memory,
        known_event_ids,
        limit,
        MAX_SOCIAL_EVENTS_PER_RESPONSE,
        MAX_SYNC_MESSAGE_BYTES,
    )
}

pub fn social_events_response_with_caps(
    social_memory: &SocialMemory,
    known_event_ids: &[String],
    limit: usize,
    max_events: usize,
    max_frame_bytes: usize,
) -> SyncResponse {
    let known: HashSet<&str> = known_event_ids.iter().map(String::as_str).collect();
    let effective_limit = limit.min(max_events);
    let mut events_json = Vec::new();

    for event in social_memory.events() {
        if events_json.len() >= effective_limit {
            break;
        }
        if known.contains(event.id.as_str()) {
            continue;
        }
        match event.to_json() {
            Ok(json) => events_json.push(json),
            Err(err) => {
                return SyncResponse::Error {
                    message: format!("serialize social event {}: {err}", event.id),
                };
            }
        }
        match social_events_response_frame_len(&events_json) {
            Ok(frame_len) if frame_len <= max_frame_bytes => {}
            Ok(_) => {
                let oversized_event_id = event.id.clone();
                events_json.pop();
                if events_json.is_empty() {
                    tracing::warn!(
                        "skipping social event {oversized_event_id}: exceeds sync frame limit"
                    );
                    continue;
                }
                break;
            }
            Err(err) => {
                return SyncResponse::Error {
                    message: format!("serialize social events response: {err}"),
                };
            }
        }
    }

    SyncResponse::SocialEventsResponse { events_json }
}

pub fn social_events_response_frame_len(
    events_json: &[Vec<u8>],
) -> Result<usize, serde_json::Error> {
    serde_json::to_vec(&SyncResponse::SocialEventsResponse {
        events_json: events_json.to_vec(),
    })
    .map(|bytes| bytes.len())
}

pub async fn request_social_events_from_peer(
    network: &Network,
    peer: libp2p::PeerId,
    social_memory: &mut SocialMemory,
    memory_path: &Path,
) -> usize {
    let client = SyncClient::new(network.sync_request_channel());
    let known_event_ids = social_memory
        .events()
        .iter()
        .map(|event| event.id.clone())
        .collect();
    let mut inserted = 0;

    match client.get_social_events(peer, known_event_ids, 512).await {
        Ok(events_json) => {
            let event_slices = events_json.iter().map(Vec::as_slice).collect::<Vec<_>>();
            let results = social_memory.ingest_json_batch(event_slices);
            inserted = results
                .iter()
                .filter(|result| matches!(result, Ok(true)))
                .count();
            if inserted > 0 {
                if let Err(err) = save_social_memory(memory_path, social_memory) {
                    tracing::warn!("failed to save synced social events from {}: {err}", peer);
                } else {
                    tracing::info!(
                        "synced {} social events from {}; events={}, agents={}",
                        inserted,
                        peer,
                        social_memory.event_count(),
                        social_memory.agent_count()
                    );
                }
            }
            for result in results {
                if let Err(err) = result {
                    tracing::warn!("rejected synced social event from {}: {err}", peer);
                }
            }
        }
        Err(err) => {
            tracing::debug!("social event sync request to {} failed: {err}", peer);
        }
    }
    inserted
}
