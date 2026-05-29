//! Agent manifest — what an agent declares it can do.

use nexus_core::Did;
use serde::{Deserialize, Serialize};

/// A capability that an agent provides or requires.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CapabilityDecl {
    /// Short name, e.g. "python-exec", "data-fetch", "image-gen".
    pub name: String,

    /// Human-readable description.
    pub description: String,

    /// Version of this capability.
    pub version: String,

    /// Estimated cost per unit (credit units).
    pub price_per_unit: u64,

    /// Unit of pricing, e.g. "per-second", "per-request".
    pub price_unit: String,
}

/// What an agent declares about itself to the network.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentManifest {
    /// Who this agent is.
    pub did: Did,

    /// Human-readable name.
    pub name: String,

    /// Short description.
    pub description: String,

    /// Capabilities this agent provides to others.
    pub provides: Vec<CapabilityDecl>,

    /// Capabilities this agent requires from others.
    pub requires: Vec<CapabilityDecl>,

    /// Long-lived goals this agent is pursuing.
    pub goals: Vec<String>,

    /// Values or norms this agent wants peers to know.
    pub values: Vec<String>,

    /// Collaboration preferences, e.g. "async", "research", "high-autonomy".
    pub preferences: Vec<String>,

    /// Workspace roles this agent is comfortable taking.
    pub workspace_roles: Vec<String>,

    /// Version of the agent software.
    pub agent_version: String,

    /// Unix timestamp when this manifest was created.
    pub created_at: u64,
}

impl AgentManifest {
    /// Create a minimal manifest.
    pub fn new(did: Did, name: &str, now: u64) -> Self {
        Self {
            did,
            name: name.into(),
            description: String::new(),
            provides: Vec::new(),
            requires: Vec::new(),
            goals: Vec::new(),
            values: Vec::new(),
            preferences: Vec::new(),
            workspace_roles: Vec::new(),
            agent_version: env!("CARGO_PKG_VERSION").into(),
            created_at: now,
        }
    }

    /// Add a provided capability.
    pub fn provide(mut self, cap: CapabilityDecl) -> Self {
        self.provides.push(cap);
        self
    }

    /// Add a required capability.
    pub fn require(mut self, cap: CapabilityDecl) -> Self {
        self.requires.push(cap);
        self
    }

    /// Add a long-lived goal to the public profile.
    pub fn goal(mut self, goal: impl Into<String>) -> Self {
        self.goals.push(goal.into());
        self
    }

    /// Add a value/norm to the public profile.
    pub fn value(mut self, value: impl Into<String>) -> Self {
        self.values.push(value.into());
        self
    }

    /// Add a collaboration preference.
    pub fn preference(mut self, preference: impl Into<String>) -> Self {
        self.preferences.push(preference.into());
        self
    }

    /// Add a workspace role.
    pub fn workspace_role(mut self, role: impl Into<String>) -> Self {
        self.workspace_roles.push(role.into());
        self
    }

    /// Check if this agent provides a capability matching `name`.
    pub fn provides_named(&self, name: &str) -> bool {
        self.provides.iter().any(|c| c.name == name)
    }

    /// Find a provided capability by name.
    pub fn find_provided(&self, name: &str) -> Option<&CapabilityDecl> {
        self.provides.iter().find(|c| c.name == name)
    }

    /// Serialise to JSON for gossip.
    pub fn to_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Deserialise from JSON.
    pub fn from_json(data: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(data)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn did(s: &str) -> Did {
        Did::new(format!("did:key:{s}"))
    }

    #[test]
    fn manifest_provides_named() {
        let agent = did("agent1");
        let manifest = AgentManifest::new(agent, "test-agent", 0).provide(CapabilityDecl {
            name: "python-exec".into(),
            description: "Runs Python scripts".into(),
            version: "1.0".into(),
            price_per_unit: 5,
            price_unit: "per-second".into(),
        });

        assert!(manifest.provides_named("python-exec"));
        assert!(!manifest.provides_named("image-gen"));
    }

    #[test]
    fn manifest_json_roundtrip() {
        let agent = did("agent1");
        let manifest = AgentManifest::new(agent, "test", 100).provide(CapabilityDecl {
            name: "data-fetch".into(),
            description: "Fetches data".into(),
            version: "1.0".into(),
            price_per_unit: 10,
            price_unit: "per-request".into(),
        });

        let json = manifest.to_json().unwrap();
        let decoded = AgentManifest::from_json(&json).unwrap();
        assert_eq!(decoded.name, "test");
        assert!(decoded.provides_named("data-fetch"));
    }

    #[test]
    fn manifest_social_profile_roundtrip() {
        let agent = did("agent1");
        let manifest = AgentManifest::new(agent, "social-agent", 100)
            .goal("build shared memory")
            .value("autonomy")
            .preference("async collaboration")
            .workspace_role("researcher");

        let json = manifest.to_json().unwrap();
        let decoded = AgentManifest::from_json(&json).unwrap();
        assert_eq!(decoded.goals, vec!["build shared memory"]);
        assert_eq!(decoded.values, vec!["autonomy"]);
        assert_eq!(decoded.preferences, vec!["async collaboration"]);
        assert_eq!(decoded.workspace_roles, vec!["researcher"]);
    }
}
