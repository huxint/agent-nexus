use nexus_core::WorkspaceId;
use nexus_storage::Cid;

pub fn parse_workspace_id(value: &str) -> Result<WorkspaceId, Box<dyn std::error::Error>> {
    let bytes = hex::decode(value)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "workspace id must be 32 bytes hex")?;
    Ok(WorkspaceId::from_bytes(bytes))
}

pub fn parse_cid(value: &str) -> Result<Cid, Box<dyn std::error::Error>> {
    let value = value
        .strip_prefix("cid:")
        .or_else(|| {
            value
                .strip_prefix("cid(")
                .and_then(|inner| inner.strip_suffix(')'))
        })
        .unwrap_or(value);
    let bytes = hex::decode(value)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "cid root must be 32 bytes hex")?;
    Ok(Cid::from_bytes(bytes))
}
