//! Native terminal UI for Soteria.
//!
//! A full-screen TUI dashboard that communicates directly with the
//! Soteria runtime through function calls — no HTTP, no API, no
//! sockets, no browser. Everything is in-process.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────┐
//! │                  TUI Renderer                   │
//! │  (ratatui, crossterm, direct function calls)    │
//! └────────────────────────┬────────────────────────┘
//!                          │
//!                          ▼
//! ┌─────────────────────────────────────────────────┐
//! │              Soteria Runtime Core               │
//! │  EventBus · Aegis · KeyManager · PolicyEngine   │
//! └─────────────────────────────────────────────────┘
//! ```
//!
//! The TUI reads state directly from the runtime modules and renders
//! it in a terminal. User input is handled via crossterm key events.
//! No network, no browser, no external process.

pub mod app;
pub mod dashboard;
pub mod events_view;
pub mod keys_view;
pub mod recovery_view;
pub mod threats_view;
