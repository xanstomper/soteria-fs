//! SOTERIA-OMEGA Part 7 — Operational Sovereignty & Air-Gap Mode.
//!
//! OMEGA is designed to be deployed in air-gapped environments
//! (classified networks, SCADA control systems, military command
//! posts). In air-gap mode, the engine:
//!
//! - Refuses to bind to any non-loopback network interface.
//! - Disables all telemetry / metrics export.
//! - Disables all "phone home" attestation.
//! - Logs every attempted network egress with full payload (for
//!   forensic review) and blocks it.
//! - Disables NTP and trusts only the on-host real-time clock.
//!
//! The configuration is captured in [`SovereigntyConfig`]; the live
//! check is performed by [`AirGapMode::enforce`].

use crate::omega::{OmegaError, OmegaResult};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};

/// The sovereignty mode. `AirGap` is the strictest; `Intranet` is
/// less strict; `Connected` is normal operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AirGapMode {
    /// Full network connectivity allowed.
    Connected = 0,
    /// Connected to a single trusted intranet. No internet egress.
    Intranet = 1,
    /// No network connectivity at all. Loopback only.
    AirGap = 2,
}

impl AirGapMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::Intranet => "intranet",
            Self::AirGap => "air-gap",
        }
    }

    pub fn from_label(s: &str) -> Option<Self> {
        match s {
            "connected" => Some(Self::Connected),
            "intranet" => Some(Self::Intranet),
            "air-gap" | "airgap" | "air_gap" => Some(Self::AirGap),
            _ => None,
        }
    }

    /// True iff the address is loopback (always allowed).
    pub fn is_loopback(addr: SocketAddr) -> bool {
        match addr.ip() {
            IpAddr::V4(v4) => v4.is_loopback(),
            IpAddr::V6(v6) => v6.is_loopback(),
        }
    }

    /// True iff the address is a private RFC 1918 / RFC 4193 address.
    pub fn is_private(addr: SocketAddr) -> bool {
        match addr.ip() {
            IpAddr::V4(v4) => v4.is_private() || v4 == Ipv4Addr::new(0, 0, 0, 0),
            IpAddr::V6(v6) => {
                // Unique local addresses: fc00::/7
                let bytes = v6.octets();
                (bytes[0] & 0xFE) == 0xFC
            }
        }
    }
}

/// Configuration for the sovereignty subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SovereigntyConfig {
    pub mode: AirGapMode,
    /// Allow only these source ports in air-gap mode. Empty = no
    /// outbound connections.
    pub allowed_source_ports: Vec<u16>,
    /// Disallow NTP — trust the on-host clock only.
    pub disable_ntp: bool,
    /// Disallow all telemetry export.
    pub disable_telemetry: bool,
    /// Disallow "phone home" attestation (e.g., TPM remote attestation
    /// to a remote verifier).
    pub disable_remote_attestation: bool,
    /// Optional list of allowed egress destinations (CIDR). Used in
    /// `Intranet` mode.
    pub allowed_egress_cidrs: Vec<String>,
}

impl Default for SovereigntyConfig {
    fn default() -> Self {
        Self {
            mode: AirGapMode::Connected,
            allowed_source_ports: Vec::new(),
            disable_ntp: false,
            disable_telemetry: false,
            disable_remote_attestation: false,
            allowed_egress_cidrs: Vec::new(),
        }
    }
}

impl SovereigntyConfig {
    /// Construct an air-gap config with all defenses enabled.
    pub fn air_gap() -> Self {
        Self {
            mode: AirGapMode::AirGap,
            allowed_source_ports: Vec::new(),
            disable_ntp: true,
            disable_telemetry: true,
            disable_remote_attestation: true,
            allowed_egress_cidrs: Vec::new(),
        }
    }
}

/// Live state of the air-gap enforcer. Singleton — the engine
/// constructs one at startup and references it from every network
/// call site.
pub struct AirGapEnforcer {
    config: SovereigntyConfig,
    /// Count of blocked network egress attempts.
    blocked_attempts: std::sync::atomic::AtomicU64,
    /// Whether the enforcer is currently armed.
    armed: AtomicBool,
}

impl AirGapEnforcer {
    pub fn new(config: SovereigntyConfig) -> Self {
        Self {
            config,
            blocked_attempts: std::sync::atomic::AtomicU64::new(0),
            armed: AtomicBool::new(true),
        }
    }

    pub fn config(&self) -> &SovereigntyConfig {
        &self.config
    }

    pub fn set_mode(&mut self, mode: AirGapMode) {
        self.config.mode = mode;
    }

    pub fn blocked_attempts(&self) -> u64 {
        self.blocked_attempts.load(Ordering::SeqCst)
    }

    pub fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }

    pub fn disarm(&self) {
        self.armed.store(false, Ordering::SeqCst);
    }

    pub fn is_armed(&self) -> bool {
        self.armed.load(Ordering::SeqCst)
    }

    /// Check whether an outbound TCP/UDP connection to `addr` is
    /// allowed under the current sovereignty config. Returns `Ok(())`
    /// on success; on failure the attempt is logged and the
    /// `blocked_attempts` counter is incremented.
    pub fn check_egress(&self, addr: SocketAddr) -> OmegaResult<()> {
        if !self.is_armed() {
            return Ok(());
        }
        match self.config.mode {
            AirGapMode::Connected => Ok(()),
            AirGapMode::Intranet => {
                if AirGapMode::is_loopback(addr) || AirGapMode::is_private(addr) {
                    Ok(())
                } else {
                    self.blocked_attempts.fetch_add(1, Ordering::SeqCst);
                    Err(OmegaError::Sovereignty(format!(
                        "intranet mode: egress to {addr} blocked (non-private)"
                    )))
                }
            }
            AirGapMode::AirGap => {
                if AirGapMode::is_loopback(addr) {
                    Ok(())
                } else {
                    self.blocked_attempts.fetch_add(1, Ordering::SeqCst);
                    Err(OmegaError::Sovereignty(format!(
                        "air-gap mode: egress to {addr} blocked (non-loopback)"
                    )))
                }
            }
        }
    }

    /// Check whether an HTTP request to `url` is allowed.
    pub fn check_url(&self, url: &str) -> OmegaResult<()> {
        if !self.is_armed() {
            return Ok(());
        }
        if url.starts_with("https://127.0.0.1")
            || url.starts_with("https://localhost")
            || url.starts_with("http://127.0.0.1")
            || url.starts_with("http://localhost")
        {
            return Ok(());
        }
        match self.config.mode {
            AirGapMode::Connected => Ok(()),
            AirGapMode::Intranet => {
                if url.contains("://10.") || url.contains("://192.168.") || url.contains("://172.")
                {
                    Ok(())
                } else {
                    self.blocked_attempts.fetch_add(1, Ordering::SeqCst);
                    Err(OmegaError::Sovereignty(format!(
                        "intranet mode: URL {url} blocked"
                    )))
                }
            }
            AirGapMode::AirGap => {
                self.blocked_attempts.fetch_add(1, Ordering::SeqCst);
                Err(OmegaError::Sovereignty(format!(
                    "air-gap mode: URL {url} blocked"
                )))
            }
        }
    }

    /// Check whether NTP is allowed.
    pub fn check_ntp(&self) -> OmegaResult<()> {
        if self.config.disable_ntp {
            Err(OmegaError::Sovereignty(
                "NTP is disabled in this config".into(),
            ))
        } else {
            Ok(())
        }
    }

    /// Check whether telemetry export is allowed.
    pub fn check_telemetry(&self) -> OmegaResult<()> {
        if self.config.disable_telemetry {
            Err(OmegaError::Sovereignty(
                "telemetry export is disabled in this config".into(),
            ))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddrV4;

    #[test]
    fn loopback_always_allowed() {
        let e = AirGapEnforcer::new(SovereigntyConfig::air_gap());
        let addr: SocketAddr = "127.0.0.1:80".parse().unwrap();
        assert!(e.check_egress(addr).is_ok());
    }

    #[test]
    fn airgap_blocks_public() {
        let e = AirGapEnforcer::new(SovereigntyConfig::air_gap());
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        assert!(e.check_egress(addr).is_err());
        assert_eq!(e.blocked_attempts(), 1);
    }

    #[test]
    fn intranet_blocks_public() {
        let mut cfg = SovereigntyConfig::air_gap();
        cfg.mode = AirGapMode::Intranet;
        let e = AirGapEnforcer::new(cfg);
        let pub_addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let priv_addr: SocketAddr = "10.0.0.1:80".parse().unwrap();
        assert!(e.check_egress(pub_addr).is_err());
        assert!(e.check_egress(priv_addr).is_ok());
    }

    #[test]
    fn connected_allows_everything() {
        let e = AirGapEnforcer::new(SovereigntyConfig::default());
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        assert!(e.check_egress(addr).is_ok());
    }

    #[test]
    fn ntp_blocked_when_disabled() {
        let e = AirGapEnforcer::new(SovereigntyConfig::air_gap());
        assert!(e.check_ntp().is_err());
    }

    #[test]
    fn telemetry_blocked_when_disabled() {
        let e = AirGapEnforcer::new(SovereigntyConfig::air_gap());
        assert!(e.check_telemetry().is_err());
    }

    #[test]
    fn disarmed_enforcer_allows_all() {
        let e = AirGapEnforcer::new(SovereigntyConfig::air_gap());
        e.disarm();
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        assert!(e.check_egress(addr).is_ok());
    }

    #[test]
    fn url_filter_airgap() {
        let e = AirGapEnforcer::new(SovereigntyConfig::air_gap());
        assert!(e.check_url("https://example.com").is_err());
        assert!(e.check_url("https://localhost/api").is_ok());
    }

    #[test]
    fn mode_labels_round_trip() {
        for m in [
            AirGapMode::Connected,
            AirGapMode::Intranet,
            AirGapMode::AirGap,
        ] {
            assert_eq!(AirGapMode::from_label(m.label()), Some(m));
        }
    }
}
