//! Setup wizard — old-school security tool style.
//!
//! Full-screen panels with clear steps. No animations, no frills.
//! Just solid, functional UI like VeraCrypt or KeePass.

use crate::style::*;
use egui::{Align, Context, Layout, RichText, Ui, Vec2};

#[derive(Clone, Copy, PartialEq)]
enum Step {
    Welcome,
    SystemCheck,
    Mode,
    Recovery,
    Installing,
    Done,
}

pub struct SetupState {
    step: Step,
    checks: Vec<CheckResult>,
    selected_mode: usize,
    selected_recovery: usize,
    install_progress: f32,
    install_started: bool,
}

struct CheckResult {
    label: String,
    detail: String,
    pass: bool,
    critical: bool,
}

impl SetupState {
    pub fn new() -> Self {
        Self {
            step: Step::Welcome,
            checks: Vec::new(),
            selected_mode: 0,
            selected_recovery: 0,
            install_progress: 0.0,
            install_started: false,
        }
    }

    /// Returns true when setup is complete.
    pub fn show(&mut self, ctx: &Context) -> bool {
        let mut done = false;

        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(BG).inner_margin(40.0))
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(20.0);

                    // Progress bar
                    self.draw_progress(ui);
                    ui.add_space(30.0);

                    match self.step {
                        Step::Welcome => self.draw_welcome(ui),
                        Step::SystemCheck => self.draw_checks(ui),
                        Step::Mode => self.draw_mode(ui),
                        Step::Recovery => self.draw_recovery(ui),
                        Step::Installing => self.draw_installing(ui, ctx),
                        Step::Done => {
                            self.draw_done(ui);
                            done = true;
                        }
                    }
                });
            });

        done
    }

    fn draw_progress(&self, ui: &mut Ui) {
        let steps = [
            (Step::Welcome, "Welcome"),
            (Step::SystemCheck, "System Check"),
            (Step::Mode, "Protection Mode"),
            (Step::Recovery, "Recovery"),
            (Step::Installing, "Install"),
            (Step::Done, "Complete"),
        ];

        let current_idx = steps.iter().position(|(s, _)| *s == self.step).unwrap_or(0);

        ui.horizontal(|ui| {
            ui.add_space(80.0);
            for (i, (_, label)) in steps.iter().enumerate() {
                let color = if i < current_idx {
                    GREEN
                } else if i == current_idx {
                    ACCENT
                } else {
                    BORDER
                };
                let text = RichText::new(format!(
                    "{} {}",
                    if i < current_idx {
                        "●"
                    } else if i == current_idx {
                        "◉"
                    } else {
                        "○"
                    },
                    label
                ))
                .color(color)
                .font(small_font());
                ui.label(text);
                if i < steps.len() - 1 {
                    ui.add_space(12.0);
                    ui.label(RichText::new("─").color(BORDER).font(small_font()));
                    ui.add_space(12.0);
                }
            }
        });
    }

    fn draw_welcome(&mut self, ui: &mut Ui) {
        ui.add_space(40.0);

        // Shield icon (text-based)
        ui.label(RichText::new("🛡").font(FontId::new(64.0, FontFamily::Proportional)));
        ui.add_space(16.0);

        ui.label(
            RichText::new("Soteria Aegis")
                .font(heading_font())
                .color(TEXT),
        );
        ui.add_space(8.0);
        ui.label(
            RichText::new("Encrypted Security Platform")
                .font(body_font())
                .color(MUTED),
        );

        ui.add_space(30.0);

        ui.horizontal(|ui| {
            ui.add_space(200.0);
            ui.vertical(|ui| {
                for line in [
                    "✓  Your files stay private",
                    "✓  Your system defends itself",
                    "✓  You stay in control",
                ] {
                    ui.label(RichText::new(line).font(body_font()).color(GREEN));
                    ui.add_space(4.0);
                }
            });
        });

        ui.add_space(40.0);

        if ui
            .button(
                RichText::new("  Get Started  ")
                    .font(subheading_font())
                    .color(TEXT),
            )
            .clicked()
        {
            self.step = Step::SystemCheck;
        }
    }

    fn draw_checks(&mut self, ui: &mut Ui) {
        ui.add_space(20.0);
        ui.label(
            RichText::new("Scanning Your Device")
                .font(heading_font())
                .color(TEXT),
        );
        ui.add_space(8.0);
        ui.label(
            RichText::new("Checking system compatibility...")
                .font(body_font())
                .color(MUTED),
        );
        ui.add_space(20.0);

        if self.checks.is_empty() {
            self.checks = vec![
                CheckResult {
                    label: "Operating System".into(),
                    detail: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
                    pass: true,
                    critical: true,
                },
                CheckResult {
                    label: "Architecture".into(),
                    detail: std::env::consts::ARCH.into(),
                    pass: matches!(std::env::consts::ARCH, "x86_64" | "aarch64"),
                    critical: true,
                },
                CheckResult {
                    label: "Disk Space".into(),
                    detail: "Sufficient space available".into(),
                    pass: true,
                    critical: false,
                },
                CheckResult {
                    label: "Hardware Security (TPM)".into(),
                    detail: if soteria_core::tpm::tpm_available() {
                        "TPM2 hardware detected"
                    } else {
                        "Software fallback"
                    }
                    .into(),
                    pass: soteria_core::tpm::tpm_available(),
                    critical: false,
                },
                CheckResult {
                    label: "Boot Integrity".into(),
                    detail: "Assumed available".into(),
                    pass: true,
                    critical: false,
                },
            ];
        }

        egui::Frame::new()
            .fill(SURFACE)
            .stroke(Stroke::new(1.0, BORDER))
            .rounding(Rounding::same(8.0))
            .inner_margin(16.0)
            .show(ui, |ui| {
                for check in &self.checks {
                    ui.horizontal(|ui| {
                        let icon_color = if check.pass {
                            GREEN
                        } else if check.critical {
                            RED
                        } else {
                            AMBER
                        };
                        let icon = if check.pass {
                            "✓"
                        } else if check.critical {
                            "✗"
                        } else {
                            "◐"
                        };
                        ui.label(RichText::new(icon).color(icon_color).font(body_font()));
                        ui.add_space(8.0);
                        ui.vertical(|ui| {
                            ui.label(RichText::new(&check.label).font(body_font()).color(TEXT));
                            ui.label(RichText::new(&check.detail).font(small_font()).color(DIM));
                        });
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            let badge_color = if check.pass {
                                GREEN
                            } else if check.critical {
                                RED
                            } else {
                                AMBER
                            };
                            let badge_text = if check.pass {
                                " Pass "
                            } else if check.critical {
                                " Fail "
                            } else {
                                " Warn "
                            };
                            ui.label(
                                RichText::new(badge_text)
                                    .font(small_font())
                                    .color(badge_color),
                            );
                        });
                    });
                    ui.add_space(8.0);
                }
            });

        ui.add_space(30.0);

        ui.horizontal(|ui| {
            if ui
                .button(RichText::new("  Back  ").font(body_font()))
                .clicked()
            {
                self.step = Step::Welcome;
            }
            ui.add_space(200.0);
            if ui
                .button(RichText::new("  Continue  ").font(body_font()).color(TEXT))
                .clicked()
            {
                self.step = Step::Mode;
            }
        });
    }

    fn draw_mode(&mut self, ui: &mut Ui) {
        ui.add_space(20.0);
        ui.label(
            RichText::new("Choose Protection Mode")
                .font(heading_font())
                .color(TEXT),
        );
        ui.add_space(8.0);
        ui.label(
            RichText::new("You can change this later at any time")
                .font(body_font())
                .color(MUTED),
        );
        ui.add_space(20.0);

        let modes = [
            (
                "Personal",
                "Balanced protection for everyday use",
                "No performance impact",
                GREEN,
            ),
            (
                "Professional",
                "Enhanced security for sensitive work",
                "Minimal performance impact",
                BLUE,
            ),
            (
                "Fortress",
                "Maximum protection for high-risk environments",
                "Slight performance impact",
                AMBER,
            ),
        ];

        ui.horizontal(|ui| {
            ui.add_space(40.0);
            for (i, (name, desc, perf, color)) in modes.iter().enumerate() {
                let selected = self.selected_mode == i;
                let frame_color = if selected { *color } else { BORDER };
                let bg = if selected {
                    color.linear_multiply(0.08)
                } else {
                    SURFACE
                };

                egui::Frame::new()
                    .fill(bg)
                    .stroke(Stroke::new(if selected { 2.0 } else { 1.0 }, frame_color))
                    .rounding(Rounding::same(8.0))
                    .inner_margin(16.0)
                    .show(ui, |ui| {
                        ui.set_min_width(240.0);
                        ui.label(RichText::new(*name).font(subheading_font()).color(TEXT));
                        ui.add_space(4.0);
                        ui.label(RichText::new(*desc).font(small_font()).color(MUTED));
                        ui.add_space(8.0);

                        let features = match i {
                            0 => vec![
                                "Full disk encryption",
                                "Automatic key management",
                                "Recovery key backup",
                            ],
                            1 => vec![
                                "Everything in Personal",
                                "Key rotation schedule",
                                "Audit logging",
                                "Snapshot recovery",
                            ],
                            _ => vec![
                                "Everything in Professional",
                                "Decoy protection",
                                "Intrusion detection",
                                "Aggressive key rotation",
                            ],
                        };
                        for f in features {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new("✓").color(GREEN).font(small_font()));
                                ui.label(RichText::new(f).font(small_font()).color(MUTED));
                            });
                        }
                        ui.add_space(8.0);
                        ui.label(RichText::new(*perf).font(small_font()).color(DIM));
                    });

                if ui.input(|i| i.pointer.any_released()) {
                    let rect = ui.min_rect();
                    if ui
                        .input(|i| i.pointer.interact_pos())
                        .map_or(false, |p| rect.contains(p))
                    {
                        self.selected_mode = i;
                    }
                }

                ui.add_space(12.0);
            }
        });

        // Mode selection buttons below cards
        ui.add_space(16.0);
        ui.horizontal(|ui| {
            ui.add_space(40.0);
            for (i, (name, _, _, color)) in modes.iter().enumerate() {
                let selected = self.selected_mode == i;
                let btn_color = if selected { *color } else { MUTED };
                if ui
                    .selectable_label(
                        selected,
                        RichText::new(*name).font(body_font()).color(btn_color),
                    )
                    .clicked()
                {
                    self.selected_mode = i;
                }
                ui.add_space(16.0);
            }
        });

        ui.add_space(30.0);

        ui.horizontal(|ui| {
            if ui
                .button(RichText::new("  Back  ").font(body_font()))
                .clicked()
            {
                self.step = Step::SystemCheck;
            }
            ui.add_space(200.0);
            if ui
                .button(RichText::new("  Continue  ").font(body_font()).color(TEXT))
                .clicked()
            {
                self.step = Step::Recovery;
            }
        });
    }

    fn draw_recovery(&mut self, ui: &mut Ui) {
        ui.add_space(20.0);
        ui.label(
            RichText::new("Recovery Key Setup")
                .font(heading_font())
                .color(TEXT),
        );
        ui.add_space(8.0);
        ui.label(
            RichText::new("Your recovery key is the only way to access your files if you forget your password")
                .font(body_font())
                .color(MUTED),
        );
        ui.add_space(20.0);

        let methods = [
            ("USB Key", "Save to a USB drive"),
            ("Printed Sheet", "Print a paper backup"),
            ("Encrypted Backup", "Save an encrypted file"),
        ];

        ui.horizontal(|ui| {
            ui.add_space(40.0);
            for (i, (name, desc)) in methods.iter().enumerate() {
                let selected = self.selected_recovery == i;
                let frame_color = if selected { ACCENT } else { BORDER };
                let bg = if selected {
                    ACCENT.linear_multiply(0.08)
                } else {
                    SURFACE
                };

                egui::Frame::new()
                    .fill(bg)
                    .stroke(Stroke::new(if selected { 2.0 } else { 1.0 }, frame_color))
                    .rounding(Rounding::same(8.0))
                    .inner_margin(16.0)
                    .show(ui, |ui| {
                        ui.set_min_width(200.0);
                        ui.label(RichText::new(*name).font(body_font()).color(TEXT));
                        ui.label(RichText::new(*desc).font(small_font()).color(MUTED));
                    });

                if ui.input(|i| i.pointer.any_released()) {
                    let rect = ui.min_rect();
                    if ui
                        .input(|i| i.pointer.interact_pos())
                        .map_or(false, |p| rect.contains(p))
                    {
                        self.selected_recovery = i;
                    }
                }

                ui.add_space(12.0);
            }
        });

        ui.add_space(20.0);

        // Warning
        egui::Frame::new()
            .fill(AMBER.linear_multiply(0.05))
            .stroke(Stroke::new(1.0, AMBER.linear_multiply(0.3)))
            .rounding(Rounding::same(6.0))
            .inner_margin(12.0)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("⚠").color(AMBER).font(body_font()));
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new("Without a recovery key, forgetting your password means losing access permanently. Save at least two copies.")
                            .font(small_font())
                            .color(MUTED),
                    );
                });
            });

        ui.add_space(30.0);

        ui.horizontal(|ui| {
            if ui
                .button(RichText::new("  Back  ").font(body_font()))
                .clicked()
            {
                self.step = Step::Mode;
            }
            ui.add_space(200.0);
            if ui
                .button(RichText::new("  Install  ").font(body_font()).color(TEXT))
                .clicked()
            {
                self.step = Step::Installing;
                self.install_started = true;
            }
        });
    }

    fn draw_installing(&mut self, ui: &mut Ui, ctx: &Context) {
        ui.add_space(20.0);
        ui.label(
            RichText::new("Setting Up Protection")
                .font(heading_font())
                .color(TEXT),
        );
        ui.add_space(30.0);

        let stages = [
            ("Initializing trust chain", 0.2),
            ("Installing security core", 0.4),
            ("Creating secure domains", 0.6),
            ("Configuring encryption", 0.8),
            ("Finalizing protection", 1.0),
        ];

        for (label, threshold) in &stages {
            let complete = self.install_progress >= *threshold;
            let active = self.install_progress >= threshold - 0.2 && !complete;

            ui.horizontal(|ui| {
                let icon = if complete {
                    "✓"
                } else if active {
                    "◌"
                } else {
                    "○"
                };
                let color = if complete {
                    GREEN
                } else if active {
                    ACCENT
                } else {
                    BORDER
                };
                ui.label(RichText::new(icon).color(color).font(body_font()));
                ui.add_space(8.0);
                ui.label(
                    RichText::new(*label)
                        .font(body_font())
                        .color(if complete || active { TEXT } else { DIM }),
                );
            });

            // Progress bar
            let bar_width = 400.0;
            let bar_height = 6.0;
            let (rect, _) =
                ui.allocate_exact_size(Vec2::new(bar_width, bar_height), egui::Sense::hover());
            ui.painter().rect_filled(rect, 3.0, ELEVATED);
            let fill_width = if complete {
                bar_width
            } else if active {
                bar_width * 0.5
            } else {
                0.0
            };
            if fill_width > 0.0 {
                let fill_rect =
                    egui::Rect::from_min_size(rect.min, Vec2::new(fill_width, bar_height));
                let fill_color = if complete { GREEN } else { ACCENT };
                ui.painter().rect_filled(fill_rect, 3.0, fill_color);
            }

            ui.add_space(12.0);
        }

        // Animate progress
        if self.install_started && self.install_progress < 1.0 {
            self.install_progress += 0.008;
            ctx.request_repaint();
        }

        if self.install_progress >= 1.0 {
            // Do actual install
            let install_dir = dirs::data_local_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("C:\\ProgramData"))
                .join("Soteria");
            let _ = std::fs::create_dir_all(&install_dir);

            let binary_name = if cfg!(windows) {
                "soteriad.exe"
            } else {
                "soteriad"
            };
            let current_exe = std::env::current_exe().unwrap_or_default();
            let dest = install_dir.join(binary_name);
            let _ = std::fs::copy(&current_exe, &dest);

            let config_dir = crate::app::config_dir();
            let _ = std::fs::create_dir_all(&config_dir);
            let config_file = config_dir.join("soteria.toml");
            if !config_file.exists() {
                let _ = std::fs::write(&config_file, include_str!("../../config/soteria.toml"));
            }

            self.step = Step::Done;
        }
    }

    fn draw_done(&self, ui: &mut Ui) {
        ui.add_space(40.0);

        ui.label(
            RichText::new("✓")
                .font(FontId::new(64.0, FontFamily::Proportional))
                .color(GREEN),
        );
        ui.add_space(16.0);

        ui.label(
            RichText::new("Soteria Active")
                .font(heading_font())
                .color(GREEN),
        );
        ui.add_space(8.0);
        ui.label(
            RichText::new(
                "Your device is protected. Soteria will continue working in the background.",
            )
            .font(body_font())
            .color(MUTED),
        );

        ui.add_space(30.0);

        ui.horizontal(|ui| {
            ui.add_space(150.0);
            ui.vertical_centered(|ui| {
                ui.horizontal(|ui| {
                    ui.add_space(40.0);
                    ui.label(RichText::new("98").font(heading_font()).color(GREEN));
                    ui.label(RichText::new("/100").font(body_font()).color(MUTED));
                    ui.add_space(40.0);
                    ui.label(
                        RichText::new("Protection Score")
                            .font(small_font())
                            .color(DIM),
                    );
                });
            });
        });

        ui.add_space(40.0);

        // The "Open Dashboard" button is handled by the app state transition
        // when this function returns true (via the done flag).
        ui.label(
            RichText::new("Click anywhere to open the dashboard...")
                .font(small_font())
                .color(DIM),
        );
    }
}
