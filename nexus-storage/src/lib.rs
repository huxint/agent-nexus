//! Nexus Storage — Merkle-DAG content-addressed block store.
//!
//! ## Model
//!
//! Every piece of data is stored as a content-addressed **block**.
//! The block's identifier is the SHA-256 hash of its content.
//!
//! There are two block types:
//!   - **Blob**: raw bytes (a file's contents).
//!   - **Tree**: a directory listing — `[(name, child_cid, kind)]`.
//!
//! Trees form a Merkle DAG: a tree node points to its children by CID,
//! and the children may themselves be trees or blobs.  The root CID of
//! a workspace is the CID of the top-level tree node.

pub mod cid;
pub mod node;
pub mod store;

pub use cid::Cid;
pub use node::{MerkleNode, NodeKind, TreeEntry};
pub use store::{BlockStore, DiskBlockStore, InMemoryBlockStore};
