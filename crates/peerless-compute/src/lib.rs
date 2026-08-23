//! Decentralized task placement policy. The caller supplies its current view of peers.

use peerless_core::{ContentId, NodeCapability, NodeId, PowerState, Task, VerificationPolicy};
use std::collections::HashMap;
use thiserror::Error;

pub mod wasm;

pub const DEFAULT_TASK_MEMORY_LIMIT: u64 = 64 * 1024 * 1024;
pub const MAX_TASK_MEMORY_LIMIT: u64 = 512 * 1024 * 1024;

#[derive(Clone, Copy, Debug)]
pub struct PlacementWeights {
    pub cpu: f64,
    pub memory: f64,
    pub latency: f64,
    pub power: f64,
    pub locality: f64,
    pub load: f64,
    pub network: f64,
    pub history: f64,
    pub trust: f64,
    pub replication: f64,
    pub congestion: f64,
}

impl Default for PlacementWeights {
    fn default() -> Self {
        Self {
            cpu: 0.25,
            memory: 0.15,
            latency: 0.15,
            power: 0.10,
            locality: 0.20,
            load: 0.10,
            network: 0.05,
            history: 0.10,
            trust: 0.15,
            replication: 0.10,
            congestion: 0.10,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct PlacementObservation {
    pub inverse_latency: f64,
    pub locality: f64,
    pub transfer_cost: f64,
    pub historical_success: f64,
    pub trust: f64,
    pub replication_availability: f64,
    pub congestion: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PlacementCandidate {
    pub capability: NodeCapability,
    pub observation: PlacementObservation,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PlacementScore {
    pub node: NodeId,
    pub score: f64,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum PlacementError {
    #[error("no currently eligible node can execute the task")]
    NoEligibleNode,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum VerificationError {
    #[error("not enough executions to satisfy verification policy")]
    InsufficientExecutions,
    #[error("execution outputs did not satisfy verification policy")]
    NoAgreement,
}

pub fn verify_outputs(
    policy: &VerificationPolicy,
    outputs: &[ContentId],
) -> Result<ContentId, VerificationError> {
    match policy {
        VerificationPolicy::TrustExecutor => outputs
            .first()
            .copied()
            .ok_or(VerificationError::InsufficientExecutions),
        VerificationPolicy::Replicate(required) => {
            let required = usize::from(*required);
            if required == 0 || outputs.len() < required {
                return Err(VerificationError::InsufficientExecutions);
            }
            let first = outputs[0];
            outputs
                .iter()
                .take(required)
                .all(|output| *output == first)
                .then_some(first)
                .ok_or(VerificationError::NoAgreement)
        }
        VerificationPolicy::Quorum {
            executions,
            required_matches,
        } => {
            let executions = usize::from(*executions);
            let required_matches = usize::from(*required_matches);
            if executions == 0
                || required_matches == 0
                || required_matches > executions
                || outputs.len() < executions
            {
                return Err(VerificationError::InsufficientExecutions);
            }
            let mut counts = std::collections::HashMap::new();
            for output in outputs.iter().take(executions) {
                *counts.entry(*output).or_insert(0usize) += 1;
            }
            counts
                .into_iter()
                .filter(|(_, count)| *count >= required_matches)
                .max_by_key(|(_, count)| *count)
                .map(|(output, _)| output)
                .ok_or(VerificationError::NoAgreement)
        }
    }
}

pub struct Scheduler {
    weights: PlacementWeights,
}

impl Scheduler {
    pub fn new(weights: PlacementWeights) -> Self {
        Self { weights }
    }

    pub fn place(
        &self,
        task: &Task,
        candidates: &[PlacementCandidate],
        now: u64,
    ) -> Result<PlacementScore, PlacementError> {
        candidates
            .iter()
            .filter(|candidate| eligible(task, &candidate.capability, now))
            .map(|candidate| PlacementScore {
                node: candidate.capability.node.clone(),
                score: self.score(candidate),
            })
            .max_by(|left, right| {
                left.score
                    .total_cmp(&right.score)
                    .then_with(|| right.node.cmp(&left.node))
            })
            .ok_or(PlacementError::NoEligibleNode)
    }

    /// Prefer an eligible peer so adding machines reduces work retained by the
    /// requester. Local execution is a fallback when no remote candidate can
    /// satisfy the task's hard constraints.
    pub fn place_with_local_fallback(
        &self,
        task: &Task,
        candidates: &[PlacementCandidate],
        local: &NodeId,
        now: u64,
    ) -> Result<PlacementScore, PlacementError> {
        self.place_balanced_with_local_fallback(task, candidates, local, &HashMap::new(), now)
    }

    /// Weighted-fair peer selection. Assignment history prevents a sequence of
    /// short tasks from sticking to one otherwise-identical peer before system
    /// load metrics have time to change.
    pub fn place_balanced_with_local_fallback(
        &self,
        task: &Task,
        candidates: &[PlacementCandidate],
        local: &NodeId,
        assignments: &HashMap<NodeId, u64>,
        now: u64,
    ) -> Result<PlacementScore, PlacementError> {
        let remote = candidates
            .iter()
            .filter(|candidate| &candidate.capability.node != local)
            .filter(|candidate| eligible(task, &candidate.capability, now))
            .collect::<Vec<_>>();
        if remote.is_empty() {
            return self.place(task, candidates, now);
        }
        remote
            .into_iter()
            .map(|candidate| {
                let cap = &candidate.capability;
                let capacity =
                    (f64::from(cap.cpu_cores) * unit(cap.available_cpu) * (1.0 - unit(cap.load)))
                        .max(0.05);
                let assigned = assignments.get(&cap.node).copied().unwrap_or(0) as f64;
                (
                    PlacementScore {
                        node: cap.node.clone(),
                        score: self.score(candidate),
                    },
                    assigned / capacity,
                )
            })
            .min_by(|(left, left_pressure), (right, right_pressure)| {
                left_pressure
                    .total_cmp(right_pressure)
                    .then_with(|| right.score.total_cmp(&left.score))
                    .then_with(|| left.node.cmp(&right.node))
            })
            .map(|(placement, _)| placement)
            .ok_or(PlacementError::NoEligibleNode)
    }

    fn score(&self, candidate: &PlacementCandidate) -> f64 {
        let cap = &candidate.capability;
        let power = match cap.power {
            PowerState::Ac => 1.0,
            PowerState::Battery => 0.4,
            PowerState::Unknown => 0.6,
        };
        let memory = normalize_bytes(cap.available_memory);
        let raw = self.weights.cpu * unit(cap.available_cpu)
            + self.weights.memory * memory
            + self.weights.latency * unit(candidate.observation.inverse_latency)
            + self.weights.power * power
            + self.weights.locality * unit(candidate.observation.locality)
            - self.weights.load * unit(cap.load)
            - self.weights.network * unit(candidate.observation.transfer_cost);
        let raw = raw
            + self.weights.history * unit(candidate.observation.historical_success)
            + self.weights.trust * unit(candidate.observation.trust)
            + self.weights.replication * unit(candidate.observation.replication_availability)
            - self.weights.congestion * unit(candidate.observation.congestion);
        unit(raw)
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct PeerReputation {
    pub success: u64,
    pub failure: u64,
    pub invalid_result: u64,
    pub timeout: u64,
    pub average_latency_ms: f64,
}

impl PeerReputation {
    pub fn trust_score(&self) -> f64 {
        let positive = self.success as f64 + 1.0;
        let negative =
            self.failure as f64 + self.timeout as f64 + 2.0 * self.invalid_result as f64 + 1.0;
        positive / (positive + negative)
    }
    pub fn record_success(&mut self, latency_ms: f64) {
        self.average_latency_ms = if self.success == 0 {
            latency_ms
        } else {
            (self.average_latency_ms * self.success as f64 + latency_ms) / (self.success + 1) as f64
        };
        self.success += 1;
    }
}

pub fn eligible(task: &Task, node: &NodeCapability, now: u64) -> bool {
    node.is_fresh_at(now)
        && task_memory_limit(task).is_some_and(|limit| node.available_memory >= limit)
        && node.available_storage >= task.requirements.minimum_storage
        && node.supports(&task.requirements.runtime)
        && node.task_slots > 0
        && task.deadline.is_none_or(|deadline| deadline > now)
}

/// The declared memory requirement is also the enforced execution budget.
/// Small/legacy tasks receive a safe 64 MiB default; oversized tasks are
/// rejected instead of being allowed to consume the host unchecked.
pub fn task_memory_limit(task: &Task) -> Option<u64> {
    let limit = task
        .requirements
        .minimum_memory
        .max(DEFAULT_TASK_MEMORY_LIMIT);
    (limit <= MAX_TASK_MEMORY_LIMIT).then_some(limit)
}

fn unit(value: f64) -> f64 {
    value.clamp(0.0, 1.0)
}
fn normalize_bytes(value: u64) -> f64 {
    unit((value as f64 + 1.0).log2() / 48.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use peerless_core::{
        ContentId, NetworkRequirement, Requirements, RuntimeRequirement, VerificationPolicy,
    };

    fn task() -> Task {
        Task {
            task_id: "t1".into(),
            component: ContentId::of(b"component"),
            input: ContentId::of(b"input"),
            requirements: Requirements {
                minimum_memory: 1024,
                minimum_storage: 1024,
                runtime: RuntimeRequirement("wasi-0.3".into()),
                estimated_cpu_cost: 1,
                network: NetworkRequirement::None,
            },
            verification: VerificationPolicy::TrustExecutor,
            deadline: None,
        }
    }

    fn candidate(id: u8, cpu: f64, load: f64, expires_at: u64) -> PlacementCandidate {
        PlacementCandidate {
            capability: NodeCapability {
                node: NodeId::from_public_key_bytes(vec![id]),
                cpu_cores: 4,
                available_cpu: cpu,
                available_memory: 1024 * 1024 * 1024,
                available_storage: 8192,
                runtimes: vec!["wasi-0.3".into()],
                power: PowerState::Ac,
                load,
                task_slots: 1,
                expires_at,
            },
            observation: PlacementObservation::default(),
        }
    }

    #[test]
    fn expired_capabilities_are_never_selected() {
        let candidates = [candidate(1, 1.0, 0.0, 9), candidate(2, 0.5, 0.2, 20)];
        assert_eq!(
            Scheduler::new(PlacementWeights::default())
                .place(&task(), &candidates, 10)
                .unwrap()
                .node,
            NodeId::from_public_key_bytes(vec![2])
        );
    }

    #[test]
    fn hard_constraints_win_over_score() {
        let mut ineligible = candidate(1, 1.0, 0.0, 20);
        ineligible.capability.task_slots = 0;
        let selected = Scheduler::new(PlacementWeights::default())
            .place(&task(), &[ineligible, candidate(2, 0.2, 0.8, 20)], 10)
            .unwrap();
        assert_eq!(selected.node, NodeId::from_public_key_bytes(vec![2]));
    }

    #[test]
    fn every_resource_boundary_is_enforced() {
        let now = 10;
        let base = candidate(1, 1.0, 0.0, 20);
        assert!(eligible(&task(), &base.capability, now));

        let mut cases = Vec::new();
        let mut low_memory = base.capability.clone();
        low_memory.available_memory = DEFAULT_TASK_MEMORY_LIMIT - 1;
        cases.push(low_memory);
        let mut low_storage = base.capability.clone();
        low_storage.available_storage = 1023;
        cases.push(low_storage);
        let mut wrong_runtime = base.capability.clone();
        wrong_runtime.runtimes.clear();
        cases.push(wrong_runtime);
        let mut no_slots = base.capability.clone();
        no_slots.task_slots = 0;
        cases.push(no_slots);
        let mut expired = base.capability.clone();
        expired.expires_at = now;
        cases.push(expired);
        assert!(cases
            .iter()
            .all(|capability| !eligible(&task(), capability, now)));

        let mut oversized = task();
        oversized.requirements.minimum_memory = MAX_TASK_MEMORY_LIMIT + 1;
        assert!(!eligible(&oversized, &base.capability, now));

        let mut deadline_task = task();
        deadline_task.deadline = Some(now);
        assert!(!eligible(&deadline_task, &base.capability, now));
    }

    #[test]
    fn eligible_remote_is_preferred_and_local_is_only_a_fallback() {
        let scheduler = Scheduler::new(PlacementWeights::default());
        let local = NodeId::from_public_key_bytes(vec![1]);
        let excellent_local = candidate(1, 1.0, 0.0, 20);
        let weak_remote = candidate(2, 0.1, 0.9, 20);
        assert_eq!(
            scheduler
                .place_with_local_fallback(
                    &task(),
                    &[excellent_local.clone(), weak_remote.clone()],
                    &local,
                    10,
                )
                .unwrap()
                .node,
            weak_remote.capability.node
        );

        let mut unavailable_remote = weak_remote;
        unavailable_remote.capability.task_slots = 0;
        assert_eq!(
            scheduler
                .place_with_local_fallback(
                    &task(),
                    &[excellent_local.clone(), unavailable_remote],
                    &local,
                    10,
                )
                .unwrap()
                .node,
            excellent_local.capability.node
        );
    }

    #[test]
    fn short_tasks_are_balanced_across_equal_remote_peers() {
        let scheduler = Scheduler::new(PlacementWeights::default());
        let local = NodeId::from_public_key_bytes(vec![1]);
        let candidates = [
            candidate(1, 1.0, 0.0, 20),
            candidate(2, 0.8, 0.2, 20),
            candidate(3, 0.8, 0.2, 20),
        ];
        let mut assignments = HashMap::new();
        for _ in 0..20 {
            let selected = scheduler
                .place_balanced_with_local_fallback(&task(), &candidates, &local, &assignments, 10)
                .unwrap();
            assert_ne!(selected.node, local);
            *assignments.entry(selected.node).or_insert(0) += 1;
        }
        assert_eq!(assignments.values().sum::<u64>(), 20);
        assert_eq!(assignments.len(), 2);
        let counts = assignments.values().copied().collect::<Vec<_>>();
        assert!(counts.iter().max().unwrap() - counts.iter().min().unwrap() <= 1);
    }

    #[test]
    fn adaptive_history_trust_locality_and_congestion_change_placement() {
        let mut risky = candidate(1, 1.0, 0.0, 20);
        risky.observation = PlacementObservation {
            inverse_latency: 1.0,
            locality: 0.0,
            transfer_cost: 1.0,
            historical_success: 0.0,
            trust: 0.0,
            replication_availability: 0.0,
            congestion: 1.0,
        };
        let mut reliable_local = candidate(2, 0.5, 0.2, 20);
        reliable_local.observation = PlacementObservation {
            inverse_latency: 0.5,
            locality: 1.0,
            transfer_cost: 0.0,
            historical_success: 1.0,
            trust: 1.0,
            replication_availability: 1.0,
            congestion: 0.0,
        };
        assert_eq!(
            Scheduler::new(PlacementWeights::default())
                .place(&task(), &[risky, reliable_local], 10)
                .unwrap()
                .node,
            NodeId::from_public_key_bytes(vec![2])
        );

        let mut reputation = PeerReputation::default();
        reputation.record_success(20.0);
        reputation.record_success(40.0);
        assert!(reputation.trust_score() > 0.5);
        assert_eq!(reputation.average_latency_ms, 30.0);
    }

    #[test]
    fn replicated_and_quorum_verification_reject_disagreement() {
        let a = ContentId::of(b"a");
        let b = ContentId::of(b"b");
        assert_eq!(
            verify_outputs(
                &VerificationPolicy::Quorum {
                    executions: 3,
                    required_matches: 2
                },
                &[a, b, a]
            )
            .unwrap(),
            a
        );
        assert_eq!(
            verify_outputs(&VerificationPolicy::Replicate(2), &[a, b]),
            Err(VerificationError::NoAgreement)
        );
        assert_eq!(
            verify_outputs(
                &VerificationPolicy::Quorum {
                    executions: 3,
                    required_matches: 2
                },
                &[a, b]
            ),
            Err(VerificationError::InsufficientExecutions)
        );
    }
}
