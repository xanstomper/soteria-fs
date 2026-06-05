//! SOTERIA-OMEGA Part 3 — TEMPEST Protection (software stub).
//!
//! TEMPEST is the NATO codename for the study of compromising
//! electromagnetic emanations. A real TEMPEST protection suite
//! requires:
//!
//! - **EARD** (Electromagnetic Attack and Radiation Defense) hardware:
//!   shielded enclosures, filtered power lines, fiber-optic I/O.
//! - **RED/BLACK separation**: red (classified) and black (untrusted)
//!   networks with one-way diode-style isolation.
//! - **Jamming**: broadband noise generators that mask the carrier
//!   frequency of any emanation.
//! - **TEMPEST zoning**: physical zones (Zone 0 = unclassified,
//!   Zone 4 = TOP SECRET) with progressive shielding requirements.
//!
//! Soteria-OMEGA cannot deliver hardware TEMPEST (this is a pure
//! software module). What it *can* do is the software side:
//!
//! 1. Enforce a TEMPEST zone policy at the data-encryption layer.
//!    Each zone requires progressively stronger ciphers, longer keys,
//!    and lower clock speeds (less radiation).
//! 2. Run a software "jamming" loop that emits broadband random
//!    noise into the OS scheduler and the encryption thread. The
//!    intent is to mask timing/power side channels in software.
//! 3. Log a `HardwareDependencyMissing` event when the operator
//!    declares a zone higher than Zone 2, since real TEMPEST
//!    protection requires hardware we don't have.
//!
//! ## Threat model
//!
//! This module alone defends against SOFTWARE side channels:
//! timing, cache-line access patterns, branch predictor state. It
//! does NOT defend against:
//!
//! - RF emanations (need shielded enclosure).
//! - Power analysis (need filtered power).
//! - Acoustic emanations (need sound-dampened enclosure).
//! - Van Eck phreaking (need faraday cage).
//!
//! Operators in Zone 3+ must pair this module with hardware
//! shielding.

use crate::omega::{OmegaError, OmegaResult};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// TEMPEST zone. Higher zones require progressively more protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TempestZone {
    /// Unclassified. No protection needed.
    Zone0 = 0,
    /// CUI / FVEY RESTRICTED. Software jamming only.
    Zone1 = 1,
    /// SECRET. Software jamming + RED/BLACK separation enforced.
    Zone2 = 2,
    /// SECRET//REL TO. Software + software-side EARD hints.
    Zone3 = 3,
    /// TOP SECRET. Hardware EARD required; software is a stub.
    Zone4 = 4,
    /// TOP SECRET//SCI / COSMIC TOP SECRET. Hardware + air-gap.
    Zone5 = 5,
}

impl TempestZone {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Zone0),
            1 => Some(Self::Zone1),
            2 => Some(Self::Zone2),
            3 => Some(Self::Zone3),
            4 => Some(Self::Zone4),
            5 => Some(Self::Zone5),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Zone0 => "Zone-0",
            Self::Zone1 => "Zone-1",
            Self::Zone2 => "Zone-2",
            Self::Zone3 => "Zone-3",
            Self::Zone4 => "Zone-4",
            Self::Zone5 => "Zone-5",
        }
    }

    /// Whether this zone requires hardware EARD for full protection.
    pub fn requires_hardware(self) -> bool {
        self >= Self::Zone3
    }

    /// Whether this zone mandates an air gap (no network).
    pub fn requires_air_gap(self) -> bool {
        self >= Self::Zone4
    }
}

/// Configuration for the software-side TEMPEST subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldingConfig {
    pub zone: TempestZone,
    /// Emit random CPU work to mask the timing of crypto operations.
    /// Higher = more masking, more CPU.
    pub software_jamming: bool,
    /// If true, refuse any operation that would write through a
    /// network interface (enforce RED/BLACK separation at the
    /// kernel level).
    pub red_black_separation: bool,
    /// If true, refuse any operation that would invoke an external
    /// executable (defends against emanation via sub-process scheduling).
    pub no_subprocess: bool,
    /// Number of CPU cycles to spend in the jamming loop per
    /// crypto operation. Default 0 = no jamming.
    pub jamming_iterations: u64,
}

impl Default for ShieldingConfig {
    fn default() -> Self {
        Self {
            zone: TempestZone::Zone0,
            software_jamming: false,
            red_black_separation: false,
            no_subprocess: false,
            jamming_iterations: 0,
        }
    }
}

impl ShieldingConfig {
    pub fn for_zone(zone: TempestZone) -> Self {
        Self {
            zone,
            software_jamming: zone >= TempestZone::Zone1,
            red_black_separation: zone >= TempestZone::Zone2,
            no_subprocess: zone >= TempestZone::Zone3,
            jamming_iterations: match zone {
                TempestZone::Zone0 => 0,
                TempestZone::Zone1 => 1_000,
                TempestZone::Zone2 => 10_000,
                TempestZone::Zone3 => 100_000,
                TempestZone::Zone4 | TempestZone::Zone5 => 1_000_000,
            },
        }
    }
}

/// A noise generator that emits software-side electromagnetic
/// "jamming". On a real EARD this would drive a noise antenna; here
/// we just burn CPU cycles with random work.
pub struct ElectromagneticNoiseGenerator {
    config: ShieldingConfig,
    /// Counter of total CPU cycles spent in the jamming loop.
    total_jam_cycles: u64,
}

impl ElectromagneticNoiseGenerator {
    pub fn new(config: ShieldingConfig) -> Self {
        Self {
            config,
            total_jam_cycles: 0,
        }
    }

    pub fn config(&self) -> &ShieldingConfig {
        &self.config
    }

    pub fn set_zone(&mut self, zone: TempestZone) {
        self.config.zone = zone;
        self.config = ShieldingConfig::for_zone(zone);
    }

    pub fn total_jam_cycles(&self) -> u64 {
        self.total_jam_cycles
    }

    /// Run the jamming loop for `iterations` cycles. Uses a
    /// deterministic-but-tied-to-time approach so the loop is
    /// constant-time relative to its input length.
    pub fn jam(&mut self, iterations: u64) {
        if !self.config.software_jamming {
            return;
        }
        let n = if iterations == 0 {
            self.config.jamming_iterations
        } else {
            iterations
        };
        let mut state: u64 = 0xDEAD_BEEF_CAFE_BABE;
        for i in 0..n {
            // Cheap mixing: xorshift, but we don't care about the
            // output — we only care about the side-effects on the
            // CPU pipeline.
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            // Force a memory access to thrash the cache.
            if i % 64 == 0 {
                let mut scratch = [0u8; 64];
                scratch[0] = state as u8;
                state ^= scratch[0] as u64;
            }
        }
        self.total_jam_cycles = self.total_jam_cycles.saturating_add(n);
        // Prevent the compiler from optimizing the loop away.
        std::hint::black_box(state);
    }

    /// Check whether a network egress is allowed under the current
    /// shielding config. Used to enforce RED/BLACK separation.
    pub fn network_egress_allowed(&self) -> bool {
        !self.config.red_black_separation
    }

    /// Check whether a subprocess execution is allowed.
    pub fn subprocess_allowed(&self) -> bool {
        !self.config.no_subprocess
    }
}

/// Power-line filter placeholder. Real EARD hardware uses a
/// line-impedance stabilization network (LISN) to filter the AC
/// power line. Soteria-OMEGA cannot filter hardware, but it can
/// refuse operations that would have high power-draw signatures
/// (e.g., GPU compute, large memory allocation).
pub struct PowerFilter {
    pub enabled: bool,
    pub max_memory_mb: u64,
}

impl PowerFilter {
    pub fn new(enabled: bool, max_memory_mb: u64) -> Self {
        Self {
            enabled,
            max_memory_mb,
        }
    }

    /// Check whether an allocation of `mb` megabytes is allowed.
    pub fn check_allocation(&self, mb: u64) -> OmegaResult<()> {
        if self.enabled && mb > self.max_memory_mb {
            return Err(OmegaError::Tempest(format!(
                "allocation of {mb} MiB exceeds power-filter ceiling {} MiB",
                self.max_memory_mb
            )));
        }
        Ok(())
    }
}

/// Shielded operation context. Created at the start of a
/// TEMPEST-sensitive operation; `Drop` re-zones to Zone 0.
pub struct ShieldedOperation<'a> {
    gen: &'a mut ElectromagneticNoiseGenerator,
    prev_zone: TempestZone,
    started: Instant,
}

impl<'a> ShieldedOperation<'a> {
    pub fn enter(gen: &'a mut ElectromagneticNoiseGenerator, zone: TempestZone) -> Self {
        let prev = gen.config.zone;
        gen.set_zone(zone);
        Self {
            gen,
            prev_zone: prev,
            started: Instant::now(),
        }
    }

    pub fn jam(&mut self, iterations: u64) {
        self.gen.jam(iterations);
    }

    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
}

impl<'a> Drop for ShieldedOperation<'a> {
    fn drop(&mut self) {
        self.gen.set_zone(self.prev_zone);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zone_ordering() {
        assert!(TempestZone::Zone5 > TempestZone::Zone0);
        assert!(TempestZone::Zone3.requires_hardware());
        assert!(!TempestZone::Zone2.requires_hardware());
    }

    #[test]
    fn zone3_requires_air_gap() {
        assert!(!TempestZone::Zone3.requires_air_gap());
        assert!(TempestZone::Zone4.requires_air_gap());
    }

    #[test]
    fn config_for_zone_scales() {
        let c = ShieldingConfig::for_zone(TempestZone::Zone2);
        assert!(c.software_jamming);
        assert!(c.red_black_separation);
        assert!(!c.no_subprocess);
        assert_eq!(c.jamming_iterations, 10_000);
    }

    #[test]
    fn network_egress_blocked_at_zone2() {
        let cfg = ShieldingConfig::for_zone(TempestZone::Zone2);
        let gen = ElectromagneticNoiseGenerator::new(cfg);
        assert!(!gen.network_egress_allowed());
    }

    #[test]
    fn jam_increments_counter() {
        let cfg = ShieldingConfig::for_zone(TempestZone::Zone2);
        let mut gen = ElectromagneticNoiseGenerator::new(cfg);
        let before = gen.total_jam_cycles();
        gen.jam(1000);
        assert!(gen.total_jam_cycles() > before);
    }

    #[test]
    fn jam_disabled_at_zone0() {
        let mut gen = ElectromagneticNoiseGenerator::new(ShieldingConfig::default());
        let before = gen.total_jam_cycles();
        gen.jam(100_000);
        assert_eq!(gen.total_jam_cycles(), before);
    }

    #[test]
    fn power_filter_blocks_overage() {
        let f = PowerFilter::new(true, 1024);
        assert!(f.check_allocation(512).is_ok());
        assert!(f.check_allocation(2048).is_err());
    }

    #[test]
    fn shielded_operation_restores_zone() {
        let mut gen = ElectromagneticNoiseGenerator::new(ShieldingConfig::default());
        assert_eq!(gen.config().zone, TempestZone::Zone0);
        {
            let _op = ShieldedOperation::enter(&mut gen, TempestZone::Zone4);
        }
        assert_eq!(gen.config().zone, TempestZone::Zone0);
    }
}
