//! Agent registry — local directory of known agents and their manifests.

use std::collections::HashMap;

use nexus_core::Did;

use crate::manifest::AgentManifest;

/// Local registry of agents and their declared capabilities.
#[derive(Clone, Debug, Default)]
pub struct AgentRegistry {
    /// Known agents, keyed by DID.
    agents: HashMap<Did, AgentManifest>,

    /// Index: capability name → set of DIDs that provide it.
    capability_index: HashMap<String, Vec<Did>>,
}

impl AgentRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register or update an agent's manifest.
    pub fn register(&mut self, manifest: AgentManifest) {
        // Collect old capability names first (to avoid borrow conflict)
        let old_caps: Vec<String> = self
            .agents
            .get(&manifest.did)
            .map(|old| old.provides.iter().map(|c| c.name.clone()).collect())
            .unwrap_or_default();

        // Remove old index entries
        for name in &old_caps {
            self.remove_from_index(name, &manifest.did);
        }

        // Add new capability entries
        for cap in &manifest.provides {
            self.capability_index
                .entry(cap.name.clone())
                .or_default()
                .push(manifest.did.clone());
        }

        self.agents.insert(manifest.did.clone(), manifest);
    }

    /// Remove an agent.
    pub fn unregister(&mut self, did: &Did) {
        if let Some(manifest) = self.agents.remove(did) {
            for cap in &manifest.provides {
                self.remove_from_index(&cap.name, did);
            }
        }
    }

    /// Get an agent's manifest.
    pub fn get(&self, did: &Did) -> Option<&AgentManifest> {
        self.agents.get(did)
    }

    /// Find agents that provide a given capability.
    pub fn find_by_capability(&self, capability: &str) -> Vec<&AgentManifest> {
        self.capability_index
            .get(capability)
            .map(|dids| dids.iter().filter_map(|did| self.agents.get(did)).collect())
            .unwrap_or_default()
    }

    /// List all known agents.
    pub fn all(&self) -> impl Iterator<Item = &AgentManifest> {
        self.agents.values()
    }

    /// Number of known agents.
    pub fn len(&self) -> usize {
        self.agents.len()
    }

    pub fn is_empty(&self) -> bool {
        self.agents.is_empty()
    }

    /// Find the cheapest agent for a given capability.
    pub fn cheapest_for(&self, capability: &str) -> Option<&AgentManifest> {
        self.find_by_capability(capability)
            .into_iter()
            .min_by_key(|m| {
                m.provides
                    .iter()
                    .find(|c| c.name == capability)
                    .map(|c| c.price_per_unit)
                    .unwrap_or(u64::MAX)
            })
    }

    fn remove_from_index(&mut self, name: &str, did: &Did) {
        if let Some(dids) = self.capability_index.get_mut(name) {
            dids.retain(|d| d != did);
            if dids.is_empty() {
                self.capability_index.remove(name);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{AgentManifest, CapabilityDecl};

    fn did(s: &str) -> Did {
        Did::new(format!("did:key:{s}"))
    }

    fn make_agent(did: Did, name: &str, capabilities: &[(&str, u64)]) -> AgentManifest {
        let mut m = AgentManifest::new(did, name, 0);
        for (cap_name, price) in capabilities {
            m = m.provide(CapabilityDecl {
                name: cap_name.to_string(),
                description: String::new(),
                version: "1.0".into(),
                price_per_unit: *price,
                price_unit: "per-second".into(),
            });
        }
        m
    }

    #[test]
    fn find_by_capability() {
        let mut reg = AgentRegistry::new();
        let a = did("A");
        let b = did("B");
        reg.register(make_agent(a.clone(), "Alice", &[("python-exec", 5)]));
        reg.register(make_agent(
            b.clone(),
            "Bob",
            &[("python-exec", 3), ("image-gen", 10)],
        ));

        let python_agents = reg.find_by_capability("python-exec");
        assert_eq!(python_agents.len(), 2);

        let image_agents = reg.find_by_capability("image-gen");
        assert_eq!(image_agents.len(), 1);
    }

    #[test]
    fn cheapest_for() {
        let mut reg = AgentRegistry::new();
        reg.register(make_agent(did("A"), "Alice", &[("python-exec", 10)]));
        reg.register(make_agent(did("B"), "Bob", &[("python-exec", 3)]));
        reg.register(make_agent(did("C"), "Carol", &[("python-exec", 7)]));

        let cheapest = reg.cheapest_for("python-exec").unwrap();
        assert_eq!(cheapest.name, "Bob");
    }

    #[test]
    fn unregister_removes_from_index() {
        let mut reg = AgentRegistry::new();
        let a = did("A");
        reg.register(make_agent(a.clone(), "Alice", &[("python-exec", 5)]));
        assert_eq!(reg.find_by_capability("python-exec").len(), 1);

        reg.unregister(&a);
        assert_eq!(reg.find_by_capability("python-exec").len(), 0);
        assert!(reg.get(&a).is_none());
    }

    #[test]
    fn reregister_updates_capabilities() {
        let mut reg = AgentRegistry::new();
        let a = did("A");
        reg.register(make_agent(a.clone(), "Alice", &[("python-exec", 5)]));
        reg.register(make_agent(a.clone(), "Alice", &[("image-gen", 8)]));

        assert!(reg.find_by_capability("python-exec").is_empty());
        assert_eq!(reg.find_by_capability("image-gen").len(), 1);
    }
}
