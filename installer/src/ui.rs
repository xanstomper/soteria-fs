//! Installer UI — terminal output formatting.

use crate::checks::CheckResult;
use crate::install::InstallConfig;
use colored::Colorize;

pub fn print_banner() {
    println!();
    println!("  {}", "Soteria Aegis".cyan().bold());
    println!("  {}", "Encrypted Security Platform".dimmed());
    println!("  {}", "v0.2.0".dimmed());
    println!();
    println!("  {} Your files stay private", "✓".green());
    println!("  {} Your system defends itself", "✓".green());
    println!("  {} You stay in control", "✓".green());
    println!();
}

pub fn section(title: &str) {
    println!("  {}", title.bold());
    println!("  {}", "─".repeat(40).dimmed());
}

pub fn print_checks(checks: &[CheckResult]) {
    for check in checks {
        let icon = if check.pass {
            "✓".green()
        } else if check.critical {
            "✗".red()
        } else {
            "◐".yellow()
        };
        println!("  {} {}", icon, check.label);
        println!("    {}", check.detail.dimmed());
    }
}

pub fn print_success(config: &InstallConfig) {
    println!();
    println!("  {}", "─".repeat(40).dimmed());
    println!();
    println!("  {}", "Soteria Aegis Installed".green().bold());
    println!();
    println!("  Install directory: {}", config.install_dir.display());
    println!(
        "  Config:            {}",
        crate::install::config_dir().display()
    );
    println!(
        "  Data:              {}",
        crate::install::data_dir().display()
    );
    println!();
    println!("  {}", "Getting Started:".bold());
    println!("    soteriad --help              Show all commands");
    println!("    soteriad encrypt --help      Encrypt a file");
    println!("    soteriad keygen --help       Generate a keypair");
    println!("    soteriad share --help        Manage sharing");
    println!();
    println!("  {}", "Documentation:".bold());
    println!("    https://github.com/xanstomper/soteria-fs");
    println!();
    println!("  {}", "Restart your terminal to use soteriad.".yellow());
    println!();
}

impl std::fmt::Display for CheckResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.label, self.detail)
    }
}
