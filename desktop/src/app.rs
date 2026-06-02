//! Main application state — switches between setup wizard and dashboard.

use crate::{dashboard, setup, style};
use egui::{Context, Ui};

pub enum Screen {
    Setup(setup::SetupState),
    Dashboard(dashboard::DashboardState),
}

pub struct SoteriaApp {
    screen: Screen,
}

impl SoteriaApp {
    pub fn new() -> Self {
        let first_run = !config_dir().join(".setup-complete").exists();
        Self {
            screen: if first_run {
                Screen::Setup(setup::SetupState::new())
            } else {
                Screen::Dashboard(dashboard::DashboardState::new())
            },
        }
    }
}

impl eframe::App for SoteriaApp {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        match &mut self.screen {
            Screen::Setup(state) => {
                if state.show(ctx) {
                    let _ = std::fs::create_dir_all(config_dir());
                    let _ = std::fs::write(config_dir().join(".setup-complete"), "done");
                    self.screen = Screen::Dashboard(dashboard::DashboardState::new());
                }
            }
            Screen::Dashboard(state) => {
                state.show(ctx);
            }
        }
    }
}

fn config_dir() -> std::path::PathBuf {
    #[cfg(target_os = "windows")]
    {
        dirs::config_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("C:\\Users\\Default\\AppData\\Roaming"))
            .join("Soteria")
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::path::PathBuf::from("/etc/soteria")
    }
}
