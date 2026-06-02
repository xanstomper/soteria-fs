//! Soteria Aegis Installer
//!
//! Self-contained installer that:
//! 1. Checks system requirements (TPM, disk space, OS)
//! 2. Installs soteriad binary to the install directory
//! 3. Sets up configuration files
//! 4. Adds to PATH
//! 5. Creates shortcuts (Start Menu on Windows, .desktop on Linux)
//! 6. Optionally installs the desktop app

mod checks;
mod install;
mod ui;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let silent = args.contains(&"--silent".to_string());
    let uninstall = args.contains(&"--uninstall".to_string());
    let portable = args.contains(&"--portable".to_string());

    if uninstall {
        ui::print_banner();
        match install::uninstall() {
            Ok(()) => println!("\n  Soteria has been uninstalled."),
            Err(e) => eprintln!("\n  Uninstall failed: {e}"),
        }
        return;
    }

    ui::print_banner();

    // Step 1: System checks
    ui::section("System Check");
    let results = checks::run_all();
    ui::print_checks(&results);

    let has_critical = results.iter().any(|r| r.critical && !r.pass);
    if has_critical && !silent {
        println!("\n  Some checks failed. Installation may not work correctly.");
        println!("  Continue anyway? [Y/n] ");
        let mut input = String::new();
        let _ = std::io::stdin().read_line(&mut input);
        if input.trim().eq_ignore_ascii_case("n") {
            println!("  Installation cancelled.");
            return;
        }
    }

    if !silent {
        println!("\n  Press Enter to begin installation...");
        let mut input = String::new();
        let _ = std::io::stdin().read_line(&mut input);
    }

    // Step 2: Install
    ui::section("Installing Soteria Aegis");
    let config = install::InstallConfig {
        portable,
        install_dir: if portable {
            std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."))
        } else {
            install::default_install_dir()
        },
    };

    match install::run(&config) {
        Ok(()) => ui::print_success(&config),
        Err(e) => {
            eprintln!("\n  Installation failed: {e}");
            std::process::exit(1);
        }
    }
}
