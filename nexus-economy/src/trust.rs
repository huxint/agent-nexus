//! Trust graph — models the network of bilateral credit relationships
//! and finds payment paths through chains of trust.
//!
//! ## Algorithm
//!
//! The trust graph is a directed graph where each edge (A → B) has
//! capacity = how much credit A extends to B.
//!
//! To route a payment from S to R, we run Edmonds-Karp max-flow
//! (BFS-based Ford-Fulkerson) on the trust graph and extract
//! one or more payment paths.

use std::collections::{HashMap, HashSet, VecDeque};

use nexus_core::Did;

use crate::ledger::CreditLedger;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A single hop in a payment path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentHop {
    /// The intermediary (or final recipient).
    pub to: Did,
    /// Amount to route through this hop.
    pub amount: u64,
}

/// A complete payment path from sender to recipient.
#[derive(Clone, Debug)]
pub struct PaymentPath {
    /// Ordered hops from sender to recipient.
    pub hops: Vec<PaymentHop>,
    /// Total amount that can flow through this path.
    pub capacity: u64,
}

/// The global trust graph, built from all agents' ledgers.
///
/// In a real decentralized system, this is assembled gossiply —
/// each agent only knows its local view.  The graph here is the
/// union of all known edges.
#[derive(Clone, Debug, Default)]
pub struct TrustGraph {
    /// Edges: (from, to) → capacity.
    edges: HashMap<(Did, Did), u64>,
    /// Adjacency list for BFS.
    adj: HashMap<Did, Vec<Did>>,
    /// All known nodes.
    nodes: HashSet<Did>,
}

impl TrustGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a directed edge with the given capacity.
    pub fn add_edge(&mut self, from: Did, to: Did, capacity: u64) {
        if capacity == 0 {
            return;
        }
        self.edges.insert((from.clone(), to.clone()), capacity);
        self.adj.entry(from.clone()).or_default().push(to.clone());
        self.nodes.insert(from);
        self.nodes.insert(to);
    }

    /// Import all edges from a credit ledger (from the perspective of `agent`).
    pub fn import_ledger(&mut self, agent: &Did, ledger: &CreditLedger) {
        // Outbound edges: agent extends credit to others
        for (counterparty, cap) in ledger.outbound_edges() {
            self.add_edge(agent.clone(), counterparty, cap);
        }
        // Inbound edges: others extend credit to agent (agent can borrow)
        // In the trust graph, this is an edge from counterparty to agent
        for line in ledger.iter() {
            let cap = line.available_debt();
            if cap > 0 {
                self.add_edge(line.counterparty.clone(), agent.clone(), cap);
            }
        }
    }

    /// Find up to `max_paths` payment paths from `sender` to `recipient`
    /// totalling at most `amount`.
    ///
    /// Uses repeated BFS (Edmonds-Karp) to find augmenting paths
    /// in the residual graph.  Returns a list of disjoint paths
    /// and the total amount that can be routed.
    pub fn find_paths(
        &self,
        sender: &Did,
        recipient: &Did,
        amount: u64,
        max_paths: usize,
    ) -> Vec<PaymentPath> {
        if amount == 0 || sender == recipient {
            return Vec::new();
        }

        // Build residual graph (mutable copy of capacities)
        let mut residual: HashMap<(Did, Did), u64> = self.edges.clone();

        let mut paths = Vec::new();
        let mut total_routed: u64 = 0;

        while total_routed < amount && paths.len() < max_paths {
            // BFS to find an augmenting path
            let path_edges = self.bfs_find_path(&residual, sender, recipient);
            if path_edges.is_empty() {
                break; // No more augmenting paths
            }

            // Find bottleneck capacity along the path
            let bottleneck = path_edges
                .iter()
                .map(|(f, t)| residual.get(&(f.clone(), t.clone())).copied().unwrap_or(0))
                .min()
                .unwrap_or(0);

            if bottleneck == 0 {
                break;
            }

            // Cap at remaining needed amount
            let flow = bottleneck.min(amount - total_routed);

            // Update residual graph
            for (from, to) in &path_edges {
                // Forward edge: reduce capacity
                let key = (from.clone(), to.clone());
                if let Some(cap) = residual.get_mut(&key) {
                    *cap -= flow;
                }
                // Reverse edge: increase capacity
                let rev_key = (to.clone(), from.clone());
                *residual.entry(rev_key).or_insert(0) += flow;
            }

            // Build payment path
            let hops: Vec<PaymentHop> = path_edges
                .iter()
                .map(|(_from, to)| PaymentHop {
                    to: to.clone(),
                    amount: flow,
                })
                .collect();

            paths.push(PaymentPath {
                hops,
                capacity: flow,
            });

            total_routed += flow;
        }

        paths
    }

    /// BFS to find a path from source to sink in the residual graph.
    /// Returns the list of edges in the path.
    fn bfs_find_path(
        &self,
        residual: &HashMap<(Did, Did), u64>,
        source: &Did,
        sink: &Did,
    ) -> Vec<(Did, Did)> {
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();
        let mut parent: HashMap<Did, Did> = HashMap::new();

        queue.push_back(source.clone());
        visited.insert(source.clone());

        while let Some(current) = queue.pop_front() {
            if current == *sink {
                // Reconstruct path
                let mut path = Vec::new();
                let mut node = sink.clone();
                while node != *source {
                    let Some(prev) = parent.get(&node).cloned() else {
                        return Vec::new();
                    };
                    path.push((prev.clone(), node.clone()));
                    node = prev;
                }
                path.reverse();
                return path;
            }

            for neighbor in self.residual_neighbors(residual, &current) {
                if visited.contains(&neighbor) {
                    continue;
                }
                let key = (current.clone(), neighbor.clone());
                if let Some(&cap) = residual.get(&key) {
                    if cap > 0 {
                        visited.insert(neighbor.clone());
                        parent.insert(neighbor.clone(), current.clone());
                        queue.push_back(neighbor);
                    }
                }
            }
        }

        Vec::new() // No path found
    }

    fn residual_neighbors(&self, residual: &HashMap<(Did, Did), u64>, current: &Did) -> Vec<Did> {
        let mut neighbors = self.adj.get(current).cloned().unwrap_or_default();
        for ((from, to), cap) in residual {
            if from == current && *cap > 0 && !neighbors.contains(to) {
                neighbors.push(to.clone());
            }
        }
        neighbors
    }
}

/// Convenience: build a trust graph from a set of ledgers and find paths.
pub fn find_payment_paths(
    ledgers: &[(&Did, &CreditLedger)],
    sender: &Did,
    recipient: &Did,
    amount: u64,
) -> Vec<PaymentPath> {
    let mut graph = TrustGraph::new();
    for (agent, ledger) in ledgers {
        graph.import_ledger(agent, ledger);
    }
    graph.find_paths(sender, recipient, amount, 5)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::CreditLedger;

    fn did(s: &str) -> Did {
        Did::new(format!("did:key:{s}"))
    }

    #[test]
    fn direct_edge_single_path() {
        let mut graph = TrustGraph::new();
        let alice = did("A");
        let bob = did("B");
        graph.add_edge(alice.clone(), bob.clone(), 50);

        let paths = graph.find_paths(&alice, &bob, 30, 5);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].capacity, 30);
        assert_eq!(paths[0].hops.len(), 1);
        assert_eq!(paths[0].hops[0].to, bob);
    }

    #[test]
    fn two_hop_path() {
        let mut graph = TrustGraph::new();
        let a = did("A");
        let b = did("B");
        let c = did("C");
        graph.add_edge(a.clone(), b.clone(), 100);
        graph.add_edge(b.clone(), c.clone(), 100);

        let paths = graph.find_paths(&a, &c, 50, 5);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].capacity, 50);
        assert_eq!(paths[0].hops.len(), 2); // A→B, B→C
    }

    #[test]
    fn no_path_when_no_connection() {
        let mut graph = TrustGraph::new();
        let a = did("A");
        let b = did("B");
        graph.add_edge(a.clone(), b.clone(), 100);

        let paths = graph.find_paths(&b, &a, 50, 5);
        assert!(paths.is_empty()); // No reverse edge
    }

    #[test]
    fn bottleneck_limits_flow() {
        let mut graph = TrustGraph::new();
        let a = did("A");
        let b = did("B");
        let c = did("C");
        graph.add_edge(a.clone(), b.clone(), 10); // Bottleneck here
        graph.add_edge(b.clone(), c.clone(), 100);

        let paths = graph.find_paths(&a, &c, 50, 5);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].capacity, 10); // Limited by A→B capacity
    }

    #[test]
    fn multiple_paths() {
        let mut graph = TrustGraph::new();
        let a = did("A");
        let b = did("B");
        let c = did("C");
        let d = did("D");
        // Path 1: A→B→D, capacity 30
        graph.add_edge(a.clone(), b.clone(), 30);
        graph.add_edge(b.clone(), d.clone(), 30);
        // Path 2: A→C→D, capacity 20
        graph.add_edge(a.clone(), c.clone(), 20);
        graph.add_edge(c.clone(), d.clone(), 20);

        let paths = graph.find_paths(&a, &d, 50, 5);
        let total: u64 = paths.iter().map(|p| p.capacity).sum();
        assert!(total >= 30); // Should find at least one path
    }

    #[test]
    fn residual_reverse_edges_allow_rerouting_flow() {
        let mut graph = TrustGraph::new();
        let source = did("S");
        let left = did("L");
        let right = did("R");
        let middle = did("M");
        let alternate = did("A");
        let sink = did("T");

        graph.add_edge(source.clone(), left.clone(), 1);
        graph.add_edge(source.clone(), right.clone(), 1);
        graph.add_edge(left.clone(), middle.clone(), 1);
        graph.add_edge(right.clone(), middle.clone(), 1);
        graph.add_edge(middle.clone(), sink.clone(), 1);
        graph.add_edge(left.clone(), alternate.clone(), 1);
        graph.add_edge(alternate.clone(), sink.clone(), 1);

        let paths = graph.find_paths(&source, &sink, 2, 5);
        let total: u64 = paths.iter().map(|path| path.capacity).sum();

        assert_eq!(total, 2);
    }

    #[test]
    fn ledger_import_creates_edges() {
        let alice = did("A");
        let bob = did("B");
        let mut ledger = CreditLedger::new();
        ledger.get_or_create(&bob, 100, 50, 0);

        let mut graph = TrustGraph::new();
        graph.import_ledger(&alice, &ledger);

        // Outbound: Alice extends 100 credit to Bob
        let paths = graph.find_paths(&alice, &bob, 50, 5);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].capacity, 50);
    }
}
