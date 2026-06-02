pub mod interface;

/// Software-based key sealing (always available).
pub mod software;

/// Real TPM2 hardware backend (feature-gated, requires `tpm` feature).
#[cfg(feature = "tpm")]
pub mod hardware;

/// Detect whether TPM2 hardware is available.
pub fn tpm_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        std::path::Path::new("/dev/tpmrm0").exists() || std::path::Path::new("/dev/tpm0").exists()
    }

    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("sc")
            .args(["query", "TBS"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("RUNNING"))
            .unwrap_or(false)
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        false
    }
}

/// Create the best available TPM provider for this platform.
pub fn create_provider() -> crate::Result<Box<dyn interface::TpmProvider>> {
    if tpm_available() {
        tracing::info!("TPM2 hardware detected");
        #[cfg(feature = "tpm")]
        {
            let provider = hardware::Tpm2HardwareProvider::new()?;
            return Ok(Box::new(provider));
        }
        #[cfg(not(feature = "tpm"))]
        {
            tracing::warn!(
                "TPM2 hardware detected but 'tpm' feature not enabled; \
                 rebuild with --features tpm for hardware support"
            );
        }
    }

    tracing::info!("Using software-backed key sealing");
    Ok(Box::new(software::SoftwareSealingProvider::new()?))
}
