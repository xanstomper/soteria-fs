//! Internal event bus for Soteria's embedded runtime.
//!
//! All module communication goes through this bus — no HTTP, no REST,
//! no sockets, no external processes. Modules publish events, other
//! modules subscribe and react. The bus is the single source of truth
//! for runtime state transitions.
//!
//! ## Design
//!
//! ```text
//! ┌──────────┐    ┌──────────┐    ┌──────────┐
//! │  Sensor  │    │  Policy  │    │   CLI    │
//! └────┬─────┘    └────┬─────┘    └────┬─────┘
//!      │               │               │
//!      ▼               ▼               ▼
//! ┌─────────────────────────────────────────┐
//! │           Internal Event Bus            │
//! │     (crossbeam channels, in-memory)     │
//! └─────────────────────────────────────────┘
//!      │               │               │
//!      ▼               ▼               ▼
//! ┌──────────┐    ┌──────────┐    ┌──────────┐
//! │  Aegis   │    │ Response │    │   TUI    │
//! │  Engine  │    │  Engine  │    │ Renderer │
//! └──────────┘    └──────────┘    └──────────┘
//! ```
//!
//! ## Event flow
//!
//! 1. A module creates an `Event` and calls `bus.publish(event)`.
//! 2. The bus delivers the event to all active subscribers.
//! 3. Subscribers process the event and may publish new events in response.
//! 4. The bus is synchronous within a single thread; cross-thread delivery
//!    uses crossbeam channels with zero-copy `Arc` wrapping.

use crossbeam_channel::{unbounded, Receiver, Sender};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Unique event ID.
pub type EventId = u64;

/// Subscriber ID.
pub type SubscriberId = u64;

/// Global event counter.
static NEXT_EVENT_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_SUBSCRIBER_ID: AtomicU64 = AtomicU64::new(1);

/// The internal event bus. All modules communicate through this —
/// no HTTP, no sockets, no external processes.
pub struct EventBus {
    /// Sender half of the bus channel.
    tx: Sender<Arc<Event>>,
    /// Receiver half (held by the dispatch loop).
    rx: Receiver<Arc<Event>>,
    /// Registered subscribers with their filter predicates.
    subscribers: RwLock<HashMap<SubscriberId, Subscriber>>,
    /// Event history (ring buffer for the TUI).
    history: RwLock<Vec<Arc<Event>>>,
    /// Maximum history size.
    history_limit: usize,
}

/// A subscriber with a category filter and channel sender.
struct Subscriber {
    /// Which event categories this subscriber cares about.
    /// Empty = all events.
    filter: Vec<EventCategory>,
    /// Channel to deliver events to this subscriber.
    tx: Sender<Arc<Event>>,
}

/// An event on the bus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: EventId,
    pub timestamp: u64,
    pub category: EventCategory,
    pub severity: Severity,
    pub source: String,
    pub message: String,
    pub data: EventData,
}

/// Event categories for filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventCategory {
    /// Encryption operation (encrypt, decrypt, key rotation).
    Encryption,
    /// Integrity check (lineage verification, header check).
    Integrity,
    /// Key lifecycle (creation, rotation, revocation).
    KeyLifecycle,
    /// Access control (capability grant, revocation).
    Access,
    /// Threat detection (canary hit, anomaly, honey interaction).
    Threat,
    /// System event (startup, shutdown, config change).
    System,
    /// TPM operation (seal, unseal, PCR read).
    Tpm,
    /// Audit log event.
    Audit,
}

/// Event severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    /// Routine information. No action needed.
    Info,
    /// Something changed. Review when convenient.
    Advisory,
    /// Something needs attention soon.
    Warning,
    /// Action required now.
    Critical,
}

/// Event-specific data payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventData {
    /// No additional data.
    None,
    /// Encryption operation completed.
    EncryptionComplete {
        path: String,
        algorithm: String,
        bytes: u64,
    },
    /// Integrity check result.
    IntegrityCheck {
        volumes_checked: u32,
        volumes_ok: u32,
        first_bad_block: Option<u64>,
    },
    /// Key rotation event.
    KeyRotated { domain: String, key_id: String },
    /// Capability revoked.
    CapabilityRevoked {
        process_id: u32,
        path_prefix: String,
        reason: String,
    },
    /// Threat detected.
    ThreatDetected {
        threat_type: String,
        source: String,
        contained: bool,
    },
    /// TPM operation.
    TpmOperation { operation: String, success: bool },
    /// Audit log entry.
    AuditEntry { seq: u64, action: String },
    /// Generic key-value data.
    KeyValue(HashMap<String, String>),
}

impl EventBus {
    /// Create a new event bus.
    pub fn new() -> Self {
        let (tx, rx) = unbounded();
        Self {
            tx,
            rx,
            subscribers: RwLock::new(HashMap::new()),
            history: RwLock::new(Vec::new()),
            history_limit: 10_000,
        }
    }

    /// Publish an event to the bus. Delivers to all matching subscribers
    /// and stores in history.
    pub fn publish(
        &self,
        category: EventCategory,
        severity: Severity,
        source: &str,
        message: &str,
        data: EventData,
    ) -> EventId {
        let id = NEXT_EVENT_ID.fetch_add(1, Ordering::Relaxed);
        let event = Arc::new(Event {
            id,
            timestamp: now_unix(),
            category,
            severity,
            source: source.to_string(),
            message: message.to_string(),
            data,
        });

        // Store in history.
        {
            let mut history = self.history.write();
            if history.len() >= self.history_limit {
                history.remove(0);
            }
            history.push(event.clone());
        }

        // Deliver to subscribers.
        let subs = self.subscribers.read();
        for sub in subs.values() {
            if sub.filter.is_empty() || sub.filter.contains(&category) {
                let _ = sub.tx.try_send(event.clone());
            }
        }

        id
    }

    /// Subscribe to events. Returns a subscriber ID and a receiver.
    /// Pass an empty filter to receive all events.
    pub fn subscribe(&self, filter: Vec<EventCategory>) -> (SubscriberId, Receiver<Arc<Event>>) {
        let id = NEXT_SUBSCRIBER_ID.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = unbounded();
        self.subscribers
            .write()
            .insert(id, Subscriber { filter, tx });
        (id, rx)
    }

    /// Unsubscribe a subscriber.
    pub fn unsubscribe(&self, id: SubscriberId) {
        self.subscribers.write().remove(&id);
    }

    /// Get recent events from history.
    pub fn recent(&self, limit: usize) -> Vec<Arc<Event>> {
        let history = self.history.read();
        let start = history.len().saturating_sub(limit);
        history[start..].to_vec()
    }

    /// Get all events from history.
    pub fn all(&self) -> Vec<Arc<Event>> {
        self.history.read().clone()
    }

    /// Count events by severity.
    pub fn count_by_severity(&self) -> HashMap<Severity, usize> {
        let history = self.history.read();
        let mut counts = HashMap::new();
        for event in history.iter() {
            *counts.entry(event.severity).or_insert(0) += 1;
        }
        counts
    }

    /// Count events by category.
    pub fn count_by_category(&self) -> HashMap<EventCategory, usize> {
        let history = self.history.read();
        let mut counts = HashMap::new();
        for event in history.iter() {
            *counts.entry(event.category).or_insert(0) += 1;
        }
        counts
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Backward compatibility ───────────────────────────────────────────

/// Backward-compatible event record wrapper.
pub type EventRecord = Arc<Event>;

/// Backward-compatible append method for the old API.
impl EventBus {
    /// Append a legacy `SoteriaEvent` to the bus. Converts it to the
    /// new `Event` format internally.
    pub fn append(
        &self,
        event: crate::event_bus::event::SoteriaEvent,
    ) -> crate::Result<EventRecord> {
        let category = EventCategory::System;
        let severity = match event.severity.0 {
            s if s >= 0.8 => Severity::Critical,
            s if s >= 0.5 => Severity::Warning,
            s if s >= 0.2 => Severity::Advisory,
            _ => Severity::Info,
        };
        let id = self.publish(
            category,
            severity,
            &event.source,
            &event.event_type,
            EventData::None,
        );
        let history = self.history.read();
        Ok(history.last().cloned().unwrap_or_else(|| {
            Arc::new(Event {
                id,
                timestamp: now_unix(),
                category,
                severity,
                source: event.source.clone(),
                message: event.event_type.clone(),
                data: EventData::None,
            })
        }))
    }
}
