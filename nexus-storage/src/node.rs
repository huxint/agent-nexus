//! Merkle node types — Blob and Tree.
//!
//! ## Wire format
//!
//! Both node types are serialised with CBOR for deterministic encoding.
//! The CID of a node is `SHA-256(CBOR(node))`.
//!
//! ### Blob
//! ```cbor
//! {"type": "blob", "data": <bytes>}
//! ```
//!
//! ### Tree
//! ```cbor
//! {"type": "tree", "entries": [
//!     {"name": <str>, "cid": <32 bytes>, "kind": "blob"|"tree"}
//! ]}
//! ```
//!
//! Entries are sorted by name to guarantee deterministic encoding.

use serde::{Deserialize, Serialize};

use crate::cid::Cid;

/// Whether a Merkle node is a blob (file) or tree (directory).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeKind {
    #[serde(rename = "blob")]
    Blob,
    #[serde(rename = "tree")]
    Tree,
}

/// A single entry in a tree (directory) node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeEntry {
    /// The entry name (file or directory name).
    pub name: String,
    /// CID of the child node.
    pub cid: Cid,
    /// Whether the child is a blob or a subtree.
    pub kind: NodeKind,
}

/// A Merkle-DAG node.
///
/// Blob nodes contain raw data; tree nodes contain directory entries.
/// Both are content-addressed: `CID = SHA-256(CBOR(node))`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum MerkleNode {
    #[serde(rename = "blob")]
    Blob {
        /// Raw payload.
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
    },
    #[serde(rename = "tree")]
    Tree {
        /// Directory entries, sorted by name.
        entries: Vec<TreeEntry>,
    },
}

impl MerkleNode {
    /// Create a new blob node.
    pub fn blob(data: Vec<u8>) -> Self {
        Self::Blob { data }
    }

    /// Create a new tree node (empty or with entries).
    pub fn tree(entries: Vec<TreeEntry>) -> Self {
        let mut sorted = entries;
        sorted.sort_by(|a, b| a.name.cmp(&b.name));
        Self::Tree { entries: sorted }
    }

    /// Serialise this node to canonical CBOR bytes.
    pub fn to_cbor(&self) -> Result<Vec<u8>, String> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).map_err(|e| format!("CBOR encode: {e}"))?;
        Ok(buf)
    }

    /// Deserialise from CBOR bytes.
    pub fn from_cbor(data: &[u8]) -> Result<Self, String> {
        ciborium::from_reader(data).map_err(|e| format!("CBOR decode: {e}"))
    }

    /// Compute the CID of this node.
    pub fn cid(&self) -> Cid {
        let cbor = self.to_cbor().expect("CBOR serialisation must not fail");
        Cid::hash_of(&cbor)
    }

    /// Returns the kind of this node.
    pub fn kind(&self) -> NodeKind {
        match self {
            Self::Blob { .. } => NodeKind::Blob,
            Self::Tree { .. } => NodeKind::Tree,
        }
    }

    /// If this is a blob, return a reference to its data.
    pub fn as_blob(&self) -> Option<&[u8]> {
        match self {
            Self::Blob { data } => Some(data),
            _ => None,
        }
    }

    /// If this is a tree, return a reference to its entries.
    pub fn as_tree(&self) -> Option<&[TreeEntry]> {
        match self {
            Self::Tree { entries } => Some(entries),
            _ => None,
        }
    }

    /// Look up a child entry by name in a tree node.
    pub fn lookup(&self, name: &str) -> Option<&TreeEntry> {
        match self {
            Self::Tree { entries } => entries.iter().find(|e| e.name == name),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_cid_deterministic() {
        let b1 = MerkleNode::blob(b"hello world".to_vec());
        let b2 = MerkleNode::blob(b"hello world".to_vec());
        assert_eq!(b1.cid(), b2.cid());
    }

    #[test]
    fn blob_cid_differs_on_content_change() {
        let b1 = MerkleNode::blob(b"hello".to_vec());
        let b2 = MerkleNode::blob(b"world".to_vec());
        assert_ne!(b1.cid(), b2.cid());
    }

    #[test]
    fn tree_entries_sorted() {
        let entries = vec![
            TreeEntry {
                name: "z".into(),
                cid: Cid::hash_of(b"z"),
                kind: NodeKind::Blob,
            },
            TreeEntry {
                name: "a".into(),
                cid: Cid::hash_of(b"a"),
                kind: NodeKind::Blob,
            },
            TreeEntry {
                name: "m".into(),
                cid: Cid::hash_of(b"m"),
                kind: NodeKind::Blob,
            },
        ];
        let tree = MerkleNode::tree(entries);
        let names: Vec<&str> = tree
            .as_tree()
            .unwrap()
            .iter()
            .map(|e| e.name.as_str())
            .collect();
        assert_eq!(names, vec!["a", "m", "z"]);
    }

    #[test]
    fn cbor_roundtrip() {
        let tree = MerkleNode::tree(vec![TreeEntry {
            name: "hello.txt".into(),
            cid: Cid::hash_of(b"data"),
            kind: NodeKind::Blob,
        }]);
        let cbor = tree.to_cbor().unwrap();
        let decoded = MerkleNode::from_cbor(&cbor).unwrap();
        assert_eq!(tree, decoded);
    }

    #[test]
    fn blob_roundtrip() {
        let blob = MerkleNode::blob(vec![1, 2, 3, 4]);
        let cbor = blob.to_cbor().unwrap();
        let decoded = MerkleNode::from_cbor(&cbor).unwrap();
        assert_eq!(blob, decoded);
    }

    #[test]
    fn lookup_finds_entry() {
        let tree = MerkleNode::tree(vec![
            TreeEntry {
                name: "foo.txt".into(),
                cid: Cid::hash_of(b"foo"),
                kind: NodeKind::Blob,
            },
            TreeEntry {
                name: "bar/".into(),
                cid: Cid::hash_of(b"bar"),
                kind: NodeKind::Tree,
            },
        ]);
        assert!(tree.lookup("foo.txt").is_some());
        assert!(tree.lookup("bar/").is_some());
        assert!(tree.lookup("nope").is_none());
    }
}
