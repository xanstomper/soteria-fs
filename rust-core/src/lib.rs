pub mod ai_observer;
pub mod config;
pub mod crypto_engine;
pub mod daemon;
pub mod deception_layer;
pub mod enterprise;
pub mod event_bus;
pub mod fs_layer;
pub mod key_manager;
pub mod policy;
pub mod response_engine;
pub mod security;
pub mod sensors;
pub mod simulation;
pub mod snapshot_engine;
pub mod tpm;
pub mod tui;

pub type Result<T> = anyhow::Result<T>;
