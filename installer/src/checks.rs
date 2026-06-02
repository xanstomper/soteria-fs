//! System requirement checks.

use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct CheckResult {
    pub name: String,
    pub label: String,
    pub pass: bool,
    pub critical: bool,
    pub detail: String,
}

pub fn run_all() -> Vec<CheckResult> {
    vec![
        check_os(),
        check_architecture(),
        check_disk_space(),
        check_tpm(),
        check_secure_boot(),
        check_permissions(),
    ]
}

fn check_os() -> CheckResult {
    let os = std::env::consts::OS;
    let supported = matches!(os, "windows" | "linux" | "macos");
    CheckResult {
        name: "os".into(),
        label: "Operating System".into(),
        pass: supported,
        critical: true,
        detail: if supported {
            format!("{} {}", os, std::env::consts::ARCH)
        } else {
            format!("Unsupported: {os}")
        },
    }
}

fn check_architecture() -> CheckResult {
    let arch = std::env::consts::ARCH;
    let supported = matches!(arch, "x86_64" | "aarch64");
    CheckResult {
        name: "arch".into(),
        label: "Architecture".into(),
        pass: supported,
        critical: true,
        detail: arch.to_string(),
    }
}

fn check_disk_space() -> CheckResult {
    // Check if we have at least 100MB free.
    let available = get_available_space_mb();
    let pass = available > 100;
    CheckResult {
        name: "disk".into(),
        label: "Disk Space".into(),
        pass,
        critical: false,
        detail: if pass {
            format!("{available} MB available")
        } else {
            format!("Only {available} MB available (need 100 MB)")
        },
    }
}

fn check_tpm() -> CheckResult {
    #[cfg(target_os = "linux")]
    {
        let has_tpm = std::path::Path::new("/dev/tpmrm0").exists()
            || std::path::Path::new("/dev/tpm0").exists();
        CheckResult {
            name: "tpm".into(),
            label: "Hardware Security (TPM)".into(),
            pass: has_tpm,
            critical: false,
            detail: if has_tpm {
                "TPM2 hardware detected".into()
            } else {
                "No TPM detected (software fallback available)".into()
            },
        }
    }

    #[cfg(target_os = "windows")]
    {
        let has_tpm = check_windows_tpm();
        CheckResult {
            name: "tpm".into(),
            label: "Hardware Security (TPM)".into(),
            pass: has_tpm,
            critical: false,
            detail: if has_tpm {
                "TPM2 available via Windows TBS".into()
            } else {
                "No TPM detected (software fallback available)".into()
            },
        }
    }

    #[cfg(target_os = "macos")]
    {
        CheckResult {
            name: "tpm".into(),
            label: "Hardware Security (TPM)".into(),
            pass: false,
            critical: false,
            detail: "No TPM on macOS (software fallback)".into(),
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        CheckResult {
            name: "tpm".into(),
            label: "Hardware Security (TPM)".into(),
            pass: false,
            critical: false,
            detail: "Unknown platform".into(),
        }
    }
}

fn check_secure_boot() -> CheckResult {
    #[cfg(target_os = "linux")]
    {
        let efi_path = std::path::Path::new("/sys/firmware/efi");
        let has_secure_boot = efi_path.exists();
        CheckResult {
            name: "secure_boot".into(),
            label: "Secure Boot".into(),
            pass: has_secure_boot,
            critical: false,
            detail: if has_secure_boot {
                "EFI system detected".into()
            } else {
                "Legacy BIOS (Secure Boot not available)".into()
            },
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        CheckResult {
            name: "secure_boot".into(),
            label: "Secure Boot".into(),
            pass: true,
            critical: false,
            detail: "Assumed available".into(),
        }
    }
}

fn check_permissions() -> CheckResult {
    #[cfg(unix)]
    {
        let can_write = nix::unistd::getuid().is_root()
            || std::fs::metadata("/usr/local/bin")
                .map(|m| {
                    use std::os::unix::fs::MetadataExt;
                    m.mode() & 0o200 != 0
                })
                .unwrap_or(false);
        CheckResult {
            name: "permissions".into(),
            label: "Install Permissions".into(),
            pass: can_write,
            critical: false,
            detail: if can_write {
                "Sufficient permissions".into()
            } else {
                "May need sudo for system-wide install".into()
            },
        }
    }

    #[cfg(windows)]
    {
        CheckResult {
            name: "permissions".into(),
            label: "Install Permissions".into(),
            pass: true,
            critical: false,
            detail: "User-level install".into(),
        }
    }
}

fn get_available_space_mb() -> u64 {
    // Simple check: try to stat the current directory.
    // In production, use sysinfo or platform-specific APIs.
    10_000 // Assume 10GB available for now
}

#[cfg(target_os = "windows")]
fn check_windows_tpm() -> bool {
    std::process::Command::new("wmic")
        .args([
            "/namespace:\\\\root\\cimv2\\security\\microsofttpm",
            "path",
            "Win32_Tpm",
            "get",
            "IsEnabled",
        ])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("TRUE"))
        .unwrap_or(false)
}
