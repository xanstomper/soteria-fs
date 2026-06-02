//! Installation logic.

use anyhow::{Context, Result};
use std::path::PathBuf;

pub struct InstallConfig {
    pub portable: bool,
    pub install_dir: PathBuf,
}

pub fn default_install_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("C:\\ProgramData"))
            .join("Soteria")
    }

    #[cfg(target_os = "macos")]
    {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("/usr/local"))
            .join("Applications/Soteria")
    }

    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/usr/local")
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        PathBuf::from("./soteria")
    }
}

pub fn run(config: &InstallConfig) -> Result<()> {
    let install_dir = &config.install_dir;

    // Step 1: Create install directory
    println!("  [1/6] Creating install directory...");
    std::fs::create_dir_all(install_dir)
        .with_context(|| format!("Failed to create {}", install_dir.display()))?;

    // Step 2: Copy binary
    println!("  [2/6] Installing soteriad...");
    let binary_name = if cfg!(windows) {
        "soteriad.exe"
    } else {
        "soteriad"
    };
    let source = find_binary(binary_name)?;
    let dest = install_dir.join(binary_name);
    std::fs::copy(&source, &dest)
        .with_context(|| format!("Failed to copy {} to {}", source.display(), dest.display()))?;

    // Step 3: Create config directory
    println!("  [3/6] Setting up configuration...");
    let config_dir = config_dir();
    std::fs::create_dir_all(&config_dir)?;
    let default_config = include_str!("../../config/soteria.toml");
    let config_path = config_dir.join("soteria.toml");
    if !config_path.exists() {
        std::fs::write(&config_path, default_config)?;
    }

    // Step 4: Create data directory
    println!("  [4/6] Creating data directory...");
    let data_dir = data_dir();
    std::fs::create_dir_all(&data_dir)?;
    std::fs::create_dir_all(data_dir.join("volumes"))?;

    // Step 5: Add to PATH
    println!("  [5/6] Configuring PATH...");
    add_to_path(install_dir)?;

    // Step 6: Create shortcuts
    println!("  [6/6] Creating shortcuts...");
    create_shortcuts(install_dir, config)?;

    Ok(())
}

pub fn uninstall() -> Result<()> {
    let install_dir = default_install_dir();

    // Remove binary
    let binary_name = if cfg!(windows) {
        "soteriad.exe"
    } else {
        "soteriad"
    };
    let binary_path = install_dir.join(binary_name);
    if binary_path.exists() {
        std::fs::remove_file(&binary_path)?;
    }

    // Remove from PATH
    remove_from_path(&install_dir)?;

    // Remove shortcuts
    #[cfg(target_os = "windows")]
    {
        let start_menu = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("C:\\ProgramData"))
            .join("Microsoft\\Windows\\Start Menu\\Programs\\Soteria");
        if start_menu.exists() {
            std::fs::remove_dir_all(&start_menu)?;
        }
    }

    println!("  Removed soteriad from {}", install_dir.display());
    println!("  Config files preserved at {}", config_dir().display());
    Ok(())
}

fn find_binary(name: &str) -> Result<PathBuf> {
    // Check common locations.
    let candidates = vec![
        PathBuf::from(format!("rust-core/target/release/{name}")),
        PathBuf::from(format!("target/release/{name}")),
        PathBuf::from(name),
    ];

    for candidate in &candidates {
        if candidate.exists() {
            return Ok(candidate.clone());
        }
    }

    anyhow::bail!("Could not find {name}. Build it first: cd rust-core && cargo build --release")
}

pub fn config_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("C:\\Users\\Default\\AppData\\Roaming"))
            .join("Soteria")
    }

    #[cfg(not(target_os = "windows"))]
    {
        PathBuf::from("/etc/soteria")
    }
}

pub fn data_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("C:\\ProgramData"))
            .join("Soteria")
    }

    #[cfg(not(target_os = "windows"))]
    {
        PathBuf::from("/var/lib/soteria")
    }
}

fn add_to_path(dir: &PathBuf) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        use winreg::enums::*;
        use winreg::RegKey;
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let env = hkcu.open_subkey_with_flags("Environment", KEY_READ | KEY_WRITE)?;
        let current_path: String = env.get_value("Path").unwrap_or_default();
        let dir_str = dir.to_string_lossy();
        if !current_path.contains(&*dir_str) {
            let new_path = if current_path.is_empty() {
                dir_str.to_string()
            } else {
                format!("{current_path};{dir_str}")
            };
            env.set_value("Path", &new_path)?;
        }
    }

    #[cfg(unix)]
    {
        // Create a symlink in /usr/local/bin or ~/.local/bin
        let link_dir = if nix::unistd::getuid().is_root() {
            PathBuf::from("/usr/local/bin")
        } else {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("/tmp"))
                .join(".local/bin")
        };
        std::fs::create_dir_all(&link_dir)?;
        let binary_name = "soteriad";
        let link = link_dir.join(binary_name);
        let target = dir.join(binary_name);
        if link.exists() {
            std::fs::remove_file(&link)?;
        }
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &link)?;
    }

    Ok(())
}

fn remove_from_path(dir: &PathBuf) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        use winreg::enums::*;
        use winreg::RegKey;
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let env = hkcu.open_subkey_with_flags("Environment", KEY_READ | KEY_WRITE)?;
        let current_path: String = env.get_value("Path").unwrap_or_default();
        let dir_str = dir.to_string_lossy();
        let new_path = current_path
            .split(';')
            .filter(|p| p.trim() != &*dir_str)
            .collect::<Vec<_>>()
            .join(";");
        env.set_value("Path", &new_path)?;
    }

    #[cfg(unix)]
    {
        let link_dir = if nix::unistd::getuid().is_root() {
            PathBuf::from("/usr/local/bin")
        } else {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("/tmp"))
                .join(".local/bin")
        };
        let link = link_dir.join("soteriad");
        if link.exists() {
            std::fs::remove_file(&link)?;
        }
    }

    Ok(())
}

fn create_shortcuts(install_dir: &PathBuf, config: &InstallConfig) -> Result<()> {
    if config.portable {
        return Ok(());
    }

    #[cfg(target_os = "windows")]
    {
        let start_menu = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("C:\\ProgramData"))
            .join("Microsoft\\Windows\\Start Menu\\Programs\\Soteria");
        std::fs::create_dir_all(&start_menu)?;

        // Create a .bat launcher
        let bat_content = format!(
            r#"@echo off
title Soteria Aegis
"{install_dir}\soteriad.exe" %*
"#,
            install_dir = install_dir.display()
        );
        std::fs::write(start_menu.join("Soteria Aegis.bat"), bat_content)?;

        // Create an uninstaller
        let uninstall_bat = format!(
            r#"@echo off
"{install_dir}\SoteriaAegis-Setup.exe" --uninstall
pause
"#,
            install_dir = install_dir.display()
        );
        std::fs::write(start_menu.join("Uninstall.bat"), uninstall_bat)?;
    }

    #[cfg(target_os = "linux")]
    {
        let desktop_dir = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("/usr/share"))
            .join("applications");
        std::fs::create_dir_all(&desktop_dir)?;

        let desktop_content = format!(
            r#"[Desktop Entry]
Name=Soteria Aegis
Comment=Encrypted Security Platform
Exec={install_dir}/soteriad
Icon=security-high
Terminal=true
Type=Application
Categories=Security;System;
"#,
            install_dir = install_dir.display()
        );
        std::fs::write(desktop_dir.join("soteria.desktop"), desktop_content)?;
    }

    Ok(())
}
