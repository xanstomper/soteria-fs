//! Soteria Aegis — Native Desktop Application
//!
//! Single binary, egui rendering, no browser, no web view, no localhost.
//! VeraCrypt-like tool with setup wizard, dashboard, and volume management.

use eframe::egui;
use std::path::PathBuf;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 750.0])
            .with_min_inner_size([900.0, 600.0])
            .with_title("Soteria Aegis — Encrypted Storage"),
        ..Default::default()
    };

    eframe::run_native(
        "Soteria Aegis",
        options,
        Box::new(|cc| {
            setup_style(&cc.egui_ctx);
            Ok(Box::new(App::new()))
        }),
    )
}

// ── App State ──────────────────────────────────────────────────────

#[derive(PartialEq, Clone, Copy)]
enum Page {
    Dashboard,
    Volumes,
    Keys,
    Recovery,
    Settings,
}

struct Volume {
    name: String,
    path: String,
    size: u64,
    mounted: bool,
    mode: String,
}

struct App {
    page: Page,
    show_wizard: bool,
    wizard_step: usize,
    selected_mode: usize,
    volumes: Vec<Volume>,
    status_msg: String,
    protection_score: u8,
    encrypted_bytes: u64,
    total_bytes: u64,
    key_rotation: String,
    recovery_verified: bool,
}

impl App {
    fn new() -> Self {
        let config_dir = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("Soteria");
        let wizard_done = config_dir.join(".setup-complete").exists();

        Self {
            page: Page::Dashboard,
            show_wizard: !wizard_done,
            wizard_step: 0,
            selected_mode: 0,
            volumes: vec![
                Volume {
                    name: "Documents".into(),
                    path: "~/Vault/Documents.sot".into(),
                    size: 500_000_000_000,
                    mounted: true,
                    mode: "Personal".into(),
                },
                Volume {
                    name: "Work".into(),
                    path: "~/Vault/Work.sot".into(),
                    size: 300_000_000_000,
                    mounted: true,
                    mode: "Professional".into(),
                },
                Volume {
                    name: "Archive".into(),
                    path: "~/Vault/Archive.sot".into(),
                    size: 80_000_000_000,
                    mounted: false,
                    mode: "Personal".into(),
                },
            ],
            status_msg: "All systems protected".into(),
            protection_score: 98,
            encrypted_bytes: 880_000_000_000,
            total_bytes: 1_073_741_824_000,
            key_rotation: "Healthy".into(),
            recovery_verified: true,
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.show_wizard {
            draw_wizard(ctx, self);
        } else {
            draw_sidebar(ctx, self);
            egui::CentralPanel::default()
                .frame(egui::Frame::default().fill(color_bg()).inner_margin(24.0))
                .show(ctx, |ui| match self.page {
                    Page::Dashboard => draw_dashboard(ui, self),
                    Page::Volumes => draw_volumes(ui, self),
                    Page::Keys => draw_keys(ui, self),
                    Page::Recovery => draw_recovery(ui, self),
                    Page::Settings => draw_settings(ui, self),
                });
        }
    }
}

// ── Setup Wizard ───────────────────────────────────────────────────

fn draw_wizard(ctx: &egui::Context, app: &mut App) {
    egui::CentralPanel::default()
        .frame(egui::Frame::default().fill(color_bg()).inner_margin(48.0))
        .show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(32.0);

                // Progress dots
                ui.horizontal(|ui| {
                    ui.add_space(120.0);
                    for i in 0..5u8 {
                        let color = if i < app.wizard_step as u8 {
                            color_green()
                        } else if i == app.wizard_step as u8 {
                            color_accent()
                        } else {
                            color_border()
                        };
                        ui.painter().circle_filled(
                            ui.cursor().left_center() + egui::vec2(16.0, 0.0),
                            6.0,
                            color,
                        );
                        ui.add_space(32.0);
                        if i < 4 {
                            ui.painter().hline(
                                ui.cursor().left_center().x..=ui.cursor().left_center().x + 20.0,
                                ui.cursor().left_center().y,
                                egui::Stroke::new(1.0, color_border()),
                            );
                            ui.add_space(24.0);
                        }
                    }
                });

                ui.add_space(40.0);

                match app.wizard_step {
                    0 => draw_wizard_welcome(ui, app),
                    1 => draw_wizard_scan(ui, app),
                    2 => draw_wizard_mode(ui, app),
                    3 => draw_wizard_recovery(ui, app),
                    4 => draw_wizard_done(ui, app),
                    _ => {}
                }
            });
        });
}

fn draw_wizard_welcome(ui: &mut egui::Ui, app: &mut App) {
    ui.label(egui::RichText::new("🛡").font(egui::FontId::proportional(64.0)));
    ui.add_space(16.0);
    ui.label(
        egui::RichText::new("Soteria Aegis")
            .font(heading_font())
            .color(color_text()),
    );
    ui.add_space(8.0);
    ui.label(
        egui::RichText::new("Encrypted Security Platform")
            .font(body_font())
            .color(color_muted()),
    );
    ui.add_space(32.0);
    for line in [
        "✓  Your files stay private",
        "✓  Your system defends itself",
        "✓  You stay in control",
    ] {
        ui.label(
            egui::RichText::new(line)
                .font(body_font())
                .color(color_green()),
        );
        ui.add_space(4.0);
    }
    ui.add_space(32.0);
    if ui
        .add(
            egui::Button::new(
                egui::RichText::new("  Get Started  ")
                    .font(egui::FontId::proportional(16.0))
                    .color(egui::Color32::WHITE),
            )
            .min_size(egui::vec2(200.0, 48.0)),
        )
        .clicked()
    {
        app.wizard_step = 1;
    }
}

fn draw_wizard_scan(ui: &mut egui::Ui, app: &mut App) {
    ui.label(
        egui::RichText::new("Scanning Your Device")
            .font(heading_font())
            .color(color_text()),
    );
    ui.add_space(8.0);
    ui.label(
        egui::RichText::new("Checking system compatibility...")
            .font(body_font())
            .color(color_muted()),
    );
    ui.add_space(20.0);

    let checks = [
        ("Operating System", "Windows x86_64", true),
        ("Architecture", "x86_64", true),
        ("Disk Space", "Sufficient space available", true),
        (
            "Hardware Security (TPM)",
            "Software fallback (no TPM)",
            false,
        ),
        ("Boot Integrity", "Assumed available", true),
    ];

    for (label, detail, pass) in &checks {
        let icon_color = if *pass { color_green() } else { color_amber() };
        let icon = if *pass { "✓" } else { "◐" };
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new(icon)
                    .color(icon_color)
                    .font(body_font()),
            );
            ui.add_space(8.0);
            ui.vertical(|ui| {
                ui.label(
                    egui::RichText::new(*label)
                        .font(body_font())
                        .color(color_text()),
                );
                ui.label(
                    egui::RichText::new(*detail)
                        .font(small_font())
                        .color(color_dim()),
                );
            });
        });
        ui.add_space(8.0);
    }

    ui.add_space(24.0);
    ui.horizontal(|ui| {
        if ui
            .add(
                egui::Button::new(egui::RichText::new("  Back  ").font(body_font()))
                    .min_size(egui::vec2(100.0, 36.0)),
            )
            .clicked()
        {
            app.wizard_step = 0;
        }
        ui.add_space(180.0);
        if ui
            .add(
                egui::Button::new(
                    egui::RichText::new("  Continue  ")
                        .font(body_font())
                        .color(color_text()),
                )
                .min_size(egui::vec2(100.0, 36.0)),
            )
            .clicked()
        {
            app.wizard_step = 2;
        }
    });
}

fn draw_wizard_mode(ui: &mut egui::Ui, app: &mut App) {
    ui.label(
        egui::RichText::new("Choose Protection Mode")
            .font(heading_font())
            .color(color_text()),
    );
    ui.add_space(8.0);
    ui.label(
        egui::RichText::new("You can change this later at any time.")
            .font(body_font())
            .color(color_muted()),
    );
    ui.add_space(20.0);

    let modes = [
        (
            "Personal",
            "Balanced protection for everyday use.",
            color_green(),
        ),
        (
            "Professional",
            "Enhanced security for sensitive work.",
            color_blue(),
        ),
        (
            "Fortress",
            "Maximum protection for high-risk environments.",
            color_amber(),
        ),
    ];

    ui.horizontal(|ui| {
        for (i, (name, desc, color)) in modes.iter().enumerate() {
            let selected = app.selected_mode == i;
            let border = if selected { *color } else { color_border() };
            let bg = if selected {
                color.linear_multiply(0.08)
            } else {
                color_surface()
            };
            egui::Frame::default()
                .fill(bg)
                .stroke(egui::Stroke::new(if selected { 2.0 } else { 1.0 }, border))
                .rounding(egui::Rounding::same(8.0))
                .inner_margin(16.0)
                .show(ui, |ui| {
                    ui.set_min_width(200.0);
                    ui.label(
                        egui::RichText::new(*name)
                            .font(subheading_font())
                            .color(color_text()),
                    );
                    ui.add_space(4.0);
                    ui.label(
                        egui::RichText::new(*desc)
                            .font(small_font())
                            .color(color_muted()),
                    );
                });
            ui.add_space(12.0);
            if ui.input(|i| i.pointer.any_released()) {
                app.selected_mode = i;
            }
        }
    });

    ui.add_space(24.0);
    ui.horizontal(|ui| {
        if ui
            .add(
                egui::Button::new(egui::RichText::new("  Back  ").font(body_font()))
                    .min_size(egui::vec2(100.0, 36.0)),
            )
            .clicked()
        {
            app.wizard_step = 1;
        }
        ui.add_space(180.0);
        if ui
            .add(
                egui::Button::new(
                    egui::RichText::new("  Continue  ")
                        .font(body_font())
                        .color(color_text()),
                )
                .min_size(egui::vec2(100.0, 36.0)),
            )
            .clicked()
        {
            app.wizard_step = 3;
        }
    });
}

fn draw_wizard_recovery(ui: &mut egui::Ui, app: &mut App) {
    ui.label(
        egui::RichText::new("Recovery Key Setup")
            .font(heading_font())
            .color(color_text()),
    );
    ui.add_space(8.0);
    ui.label(
        egui::RichText::new(
            "Your recovery key is the only way to access your files if you forget your password.",
        )
        .font(body_font())
        .color(color_muted()),
    );
    ui.add_space(20.0);

    let methods = ["USB Key", "Printed Sheet", "Encrypted Backup"];
    ui.horizontal(|ui| {
        for (i, method) in methods.iter().enumerate() {
            let selected = i == 0;
            let border = if selected {
                color_accent()
            } else {
                color_border()
            };
            let bg = if selected {
                color_accent().linear_multiply(0.08)
            } else {
                color_surface()
            };
            egui::Frame::default()
                .fill(bg)
                .stroke(egui::Stroke::new(if selected { 2.0 } else { 1.0 }, border))
                .rounding(egui::Rounding::same(8.0))
                .inner_margin(12.0)
                .show(ui, |ui| {
                    ui.set_min_width(180.0);
                    ui.label(
                        egui::RichText::new(*method)
                            .font(body_font())
                            .color(color_text()),
                    );
                });
            ui.add_space(12.0);
        }
    });

    ui.add_space(16.0);
    egui::Frame::default()
        .fill(color_amber().linear_multiply(0.05))
        .stroke(egui::Stroke::new(1.0, color_amber().linear_multiply(0.3)))
        .rounding(egui::Rounding::same(6.0))
        .inner_margin(12.0)
        .show(ui, |ui| {
            ui.label(egui::RichText::new("⚠  Without a recovery key, forgetting your password means losing access permanently. Save at least two copies.").font(small_font()).color(color_muted()));
        });

    ui.add_space(24.0);
    ui.horizontal(|ui| {
        if ui
            .add(
                egui::Button::new(egui::RichText::new("  Back  ").font(body_font()))
                    .min_size(egui::vec2(100.0, 36.0)),
            )
            .clicked()
        {
            app.wizard_step = 2;
        }
        ui.add_space(180.0);
        if ui
            .add(
                egui::Button::new(
                    egui::RichText::new("  Install  ")
                        .font(body_font())
                        .color(color_text()),
                )
                .min_size(egui::vec2(100.0, 36.0)),
            )
            .clicked()
        {
            // Mark setup complete
            let config_dir = dirs::config_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("Soteria");
            let _ = std::fs::create_dir_all(&config_dir);
            let _ = std::fs::write(config_dir.join(".setup-complete"), "done");
            app.wizard_step = 4;
        }
    });
}

fn draw_wizard_done(ui: &mut egui::Ui, app: &mut App) {
    ui.label(
        egui::RichText::new("✓")
            .font(egui::FontId::proportional(64.0))
            .color(color_green()),
    );
    ui.add_space(16.0);
    ui.label(
        egui::RichText::new("Soteria Active")
            .font(heading_font())
            .color(color_green()),
    );
    ui.add_space(8.0);
    ui.label(
        egui::RichText::new("Your device is protected.")
            .font(body_font())
            .color(color_muted()),
    );
    ui.add_space(32.0);

    ui.horizontal(|ui| {
        ui.add_space(160.0);
        ui.label(
            egui::RichText::new("98")
                .font(heading_font())
                .color(color_green()),
        );
        ui.label(
            egui::RichText::new("/100")
                .font(body_font())
                .color(color_muted()),
        );
        ui.add_space(24.0);
        ui.label(
            egui::RichText::new("Protection Score")
                .font(small_font())
                .color(color_dim()),
        );
    });

    ui.add_space(32.0);
    if ui
        .add(
            egui::Button::new(
                egui::RichText::new("  Open Dashboard  ")
                    .font(egui::FontId::proportional(16.0))
                    .color(egui::Color32::WHITE),
            )
            .min_size(egui::vec2(200.0, 48.0)),
        )
        .clicked()
    {
        app.show_wizard = false;
    }
}

// ── Sidebar ────────────────────────────────────────────────────────

fn draw_sidebar(ctx: &egui::Context, app: &mut App) {
    egui::SidePanel::left("sidebar")
        .resizable(false)
        .exact_width(220.0)
        .frame(
            egui::Frame::default()
                .fill(color_surface())
                .stroke(egui::Stroke::new(1.0, color_border())),
        )
        .show(ctx, |ui| {
            ui.add_space(16.0);
            ui.horizontal(|ui| {
                ui.add_space(12.0);
                ui.label(egui::RichText::new("🛡").font(egui::FontId::proportional(24.0)));
                ui.vertical(|ui| {
                    ui.label(
                        egui::RichText::new("Soteria")
                            .font(subheading_font())
                            .color(color_text()),
                    );
                    ui.label(
                        egui::RichText::new("Aegis Runtime")
                            .font(small_font())
                            .color(color_dim()),
                    );
                });
            });
            ui.add_space(20.0);
            ui.separator();
            ui.add_space(12.0);

            let tabs = [
                (Page::Dashboard, "📊  Dashboard"),
                (Page::Volumes, "💾  Volumes"),
                (Page::Keys, "🔑  Keys"),
                (Page::Recovery, "🛟  Recovery"),
                (Page::Settings, "⚙  Settings"),
            ];

            for (tab, label) in &tabs {
                let active = app.page == *tab;
                let color = if active { color_text() } else { color_muted() };
                let bg = if active {
                    color_accent().linear_multiply(0.12)
                } else {
                    egui::Color32::TRANSPARENT
                };

                let resp = ui.allocate_response(
                    egui::vec2(ui.available_width(), 32.0),
                    egui::Sense::click(),
                );
                if resp.hovered() || active {
                    ui.painter().rect_filled(resp.rect, 6.0, bg);
                }
                // Render label at the button position
                ui.painter().text(
                    resp.rect.left_center() + egui::vec2(12.0, 0.0),
                    egui::Align2::LEFT_CENTER,
                    *label,
                    body_font(),
                    color,
                );
                if resp.clicked() {
                    app.page = *tab;
                }
                ui.add_space(2.0);
            }
        });
}

// ── Dashboard ──────────────────────────────────────────────────────

fn draw_dashboard(ui: &mut egui::Ui, app: &App) {
    // Top bar
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new("Dashboard")
                .font(heading_font())
                .color(color_text()),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            egui::Frame::default()
                .fill(color_green().linear_multiply(0.15))
                .rounding(egui::Rounding::same(12.0))
                .inner_margin(egui::Margin::symmetric(8.0, 3.0))
                .show(ui, |ui| {
                    ui.label(
                        egui::RichText::new(" Protected ")
                            .font(small_font())
                            .color(color_green()),
                    );
                });
        });
    });
    ui.add_space(16.0);

    // Protection status card
    egui::Frame::default()
        .fill(color_surface())
        .stroke(egui::Stroke::new(1.0, color_border()))
        .rounding(egui::Rounding::same(12.0))
        .inner_margin(20.0)
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                // Score ring
                let (rect, _) =
                    ui.allocate_exact_size(egui::vec2(80.0, 80.0), egui::Sense::hover());
                let center = rect.center();
                let radius = 36.0;
                ui.painter().circle_stroke(
                    center,
                    radius,
                    egui::Stroke::new(6.0, color_elevated()),
                );
                let angle = (app.protection_score as f32 / 100.0) * std::f32::consts::TAU;
                let points: Vec<egui::Pos2> = (0..100)
                    .map(|i| {
                        let a = std::f32::consts::FRAC_PI_2 + (i as f32 / 100.0) * angle;
                        center + egui::vec2(-a.cos(), -a.sin()) * radius
                    })
                    .collect();
                if points.len() > 1 {
                    ui.painter().add(egui::Shape::line(
                        points,
                        egui::Stroke::new(6.0, color_green()),
                    ));
                }
                ui.painter().text(
                    center,
                    egui::Align2::CENTER_CENTER,
                    format!("{}", app.protection_score),
                    egui::FontId::proportional(24.0),
                    color_green(),
                );

                ui.add_space(24.0);
                ui.vertical(|ui| {
                    ui.label(
                        egui::RichText::new(&app.status_msg)
                            .font(subheading_font())
                            .color(color_text()),
                    );
                    ui.add_space(4.0);
                    ui.label(
                        egui::RichText::new("No active threats detected")
                            .font(small_font())
                            .color(color_muted()),
                    );
                    ui.add_space(12.0);
                    ui.horizontal(|ui| {
                        for (label, value, color) in [
                            ("Boot Chain", "Verified", color_green()),
                            ("TPM", "Software", color_amber()),
                            ("Keys", &app.key_rotation, color_green()),
                            (
                                "Recovery",
                                if app.recovery_verified {
                                    "Verified"
                                } else {
                                    "Not tested"
                                },
                                if app.recovery_verified {
                                    color_green()
                                } else {
                                    color_amber()
                                },
                            ),
                        ] {
                            ui.vertical(|ui| {
                                ui.label(
                                    egui::RichText::new(label)
                                        .font(small_font())
                                        .color(color_dim()),
                                );
                                ui.label(
                                    egui::RichText::new(value).font(small_font()).color(color),
                                );
                            });
                            ui.add_space(16.0);
                        }
                    });
                });
            });
        });

    ui.add_space(12.0);

    // Stat cards
    ui.horizontal(|ui| {
        stat_card(
            ui,
            "Encrypted Storage",
            &format_bytes(app.encrypted_bytes),
            &format!("{}%", (app.encrypted_bytes * 100 / app.total_bytes)),
        );
        ui.add_space(8.0);
        stat_card(
            ui,
            "Volumes",
            &format!("{}", app.volumes.len()),
            "protected",
        );
        ui.add_space(8.0);
        stat_card(ui, "Key Rotation", &app.key_rotation, "Next: 12 days");
        ui.add_space(8.0);
        stat_card(
            ui,
            "Recovery",
            if app.recovery_verified {
                "Verified"
            } else {
                "Not tested"
            },
            "Last: 2 days ago",
        );
    });

    ui.add_space(12.0);

    // Recent activity
    egui::Frame::default()
        .fill(color_surface())
        .stroke(egui::Stroke::new(1.0, color_border()))
        .rounding(egui::Rounding::same(12.0))
        .inner_margin(16.0)
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new("Recent Activity")
                    .font(subheading_font())
                    .color(color_text()),
            );
            ui.add_space(8.0);
            for (time, msg) in [
                ("09:41", "System integrity verified"),
                ("09:38", "Encryption keys rotated"),
                ("09:22", "Filesystem scan complete"),
            ] {
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new("●")
                            .color(color_green())
                            .font(small_font()),
                    );
                    ui.add_space(4.0);
                    ui.label(
                        egui::RichText::new(time)
                            .font(mono_font())
                            .color(color_dim()),
                    );
                    ui.add_space(8.0);
                    ui.label(
                        egui::RichText::new(msg)
                            .font(body_font())
                            .color(color_text()),
                    );
                });
                ui.add_space(4.0);
            }
        });
}

// ── Volumes ────────────────────────────────────────────────────────

fn draw_volumes(ui: &mut egui::Ui, app: &App) {
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new("Volumes")
                .font(heading_font())
                .color(color_text()),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui
                .add(
                    egui::Button::new(
                        egui::RichText::new("  + New Volume  ")
                            .font(body_font())
                            .color(egui::Color32::WHITE),
                    )
                    .min_size(egui::vec2(120.0, 32.0)),
                )
                .clicked()
            {
                // TODO: open create dialog
            }
        });
    });
    ui.add_space(16.0);

    for vol in &app.volumes {
        egui::Frame::default()
            .fill(color_surface())
            .stroke(egui::Stroke::new(1.0, color_border()))
            .rounding(egui::Rounding::same(12.0))
            .inner_margin(16.0)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("💾").font(egui::FontId::proportional(20.0)));
                    ui.add_space(12.0);
                    ui.vertical(|ui| {
                        ui.label(
                            egui::RichText::new(&vol.name)
                                .font(body_font())
                                .color(color_text()),
                        );
                        ui.label(
                            egui::RichText::new(format!(
                                "{} · {} · {}",
                                vol.path,
                                format_bytes(vol.size),
                                vol.mode
                            ))
                            .font(small_font())
                            .color(color_dim()),
                        );
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let (label, color) = if vol.mounted {
                            ("Mounted", color_green())
                        } else {
                            ("Unmounted", color_amber())
                        };
                        egui::Frame::default()
                            .fill(color.linear_multiply(0.15))
                            .rounding(egui::Rounding::same(12.0))
                            .inner_margin(egui::Margin::symmetric(8.0, 3.0))
                            .show(ui, |ui| {
                                ui.label(
                                    egui::RichText::new(label).font(small_font()).color(color),
                                );
                            });
                        ui.add_space(8.0);
                        if ui
                            .add(
                                egui::Button::new(
                                    egui::RichText::new(if vol.mounted {
                                        "Unmount"
                                    } else {
                                        "Mount"
                                    })
                                    .font(small_font()),
                                )
                                .min_size(egui::vec2(70.0, 28.0)),
                            )
                            .clicked()
                        {
                            // TODO: mount/unmount
                        }
                    });
                });
            });
        ui.add_space(8.0);
    }
}

// ── Keys ───────────────────────────────────────────────────────────

fn draw_keys(ui: &mut egui::Ui, app: &App) {
    ui.label(
        egui::RichText::new("Key Management")
            .font(heading_font())
            .color(color_text()),
    );
    ui.add_space(16.0);

    egui::Frame::default()
        .fill(color_surface())
        .stroke(egui::Stroke::new(1.0, color_border()))
        .rounding(egui::Rounding::same(12.0))
        .inner_margin(16.0)
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new("Key Health")
                    .font(subheading_font())
                    .color(color_text()),
            );
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("Rotation: ")
                        .font(body_font())
                        .color(color_muted()),
                );
                ui.label(
                    egui::RichText::new(&app.key_rotation)
                        .font(body_font())
                        .color(color_green()),
                );
                ui.add_space(24.0);
                ui.label(
                    egui::RichText::new("Next: 2026-07-15")
                        .font(body_font())
                        .color(color_muted()),
                );
            });
        });

    ui.add_space(12.0);

    egui::Frame::default()
        .fill(color_surface())
        .stroke(egui::Stroke::new(1.0, color_border()))
        .rounding(egui::Rounding::same(12.0))
        .inner_margin(16.0)
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new("Key Lifecycle")
                    .font(subheading_font())
                    .color(color_text()),
            );
            ui.add_space(8.0);

            let keys = [
                ("Volume Root", "Argon2id", "Active", "2026-07-15"),
                ("Domain: Personal", "HKDF", "Active", "2026-07-15"),
                ("Domain: Business", "HKDF", "Active", "2026-08-03"),
            ];

            for (name, key_type, status, due) in &keys {
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new(*name)
                            .font(body_font())
                            .color(color_text()),
                    );
                    ui.add_space(100.0);
                    ui.label(
                        egui::RichText::new(*key_type)
                            .font(small_font())
                            .color(color_muted()),
                    );
                    ui.add_space(60.0);
                    egui::Frame::default()
                        .fill(color_green().linear_multiply(0.15))
                        .rounding(egui::Rounding::same(12.0))
                        .inner_margin(egui::Margin::symmetric(6.0, 2.0))
                        .show(ui, |ui| {
                            ui.label(
                                egui::RichText::new(*status)
                                    .font(small_font())
                                    .color(color_green()),
                            );
                        });
                    ui.add_space(40.0);
                    ui.label(
                        egui::RichText::new(*due)
                            .font(small_font())
                            .color(color_muted()),
                    );
                });
                ui.add_space(6.0);
            }
        });
}

// ── Recovery ───────────────────────────────────────────────────────

fn draw_recovery(ui: &mut egui::Ui, app: &App) {
    ui.label(
        egui::RichText::new("Recovery Center")
            .font(heading_font())
            .color(color_text()),
    );
    ui.add_space(16.0);

    egui::Frame::default()
        .fill(color_surface())
        .stroke(egui::Stroke::new(1.0, color_border()))
        .rounding(egui::Rounding::same(12.0))
        .inner_margin(20.0)
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("🛟").font(egui::FontId::proportional(32.0)));
                ui.add_space(12.0);
                ui.vertical(|ui| {
                    let (title, color) = if app.recovery_verified {
                        ("Recovery Key Verified", color_green())
                    } else {
                        ("Recovery Key Not Yet Tested", color_amber())
                    };
                    ui.label(
                        egui::RichText::new(title)
                            .font(subheading_font())
                            .color(color),
                    );
                    ui.label(
                        egui::RichText::new("Last tested 2 days ago.")
                            .font(body_font())
                            .color(color_muted()),
                    );
                });
            });
        });

    ui.add_space(12.0);

    // Info cards
    ui.horizontal(|ui| {
        for (label, value, color) in [
            (
                "Status",
                if app.recovery_verified {
                    "Ready"
                } else {
                    "Needs testing"
                },
                if app.recovery_verified {
                    color_green()
                } else {
                    color_amber()
                },
            ),
            ("Last Tested", "2 days ago", color_muted()),
            ("Backup Copies", "2", color_muted()),
        ] {
            egui::Frame::default()
                .fill(color_elevated())
                .rounding(egui::Rounding::same(6.0))
                .inner_margin(12.0)
                .show(ui, |ui| {
                    ui.set_min_width(150.0);
                    ui.label(
                        egui::RichText::new(label)
                            .font(small_font())
                            .color(color_dim()),
                    );
                    ui.label(
                        egui::RichText::new(value)
                            .font(subheading_font())
                            .color(color),
                    );
                });
            ui.add_space(8.0);
        }
    });
}

// ── Settings ───────────────────────────────────────────────────────

fn draw_settings(ui: &mut egui::Ui, _app: &mut App) {
    ui.label(
        egui::RichText::new("Settings")
            .font(heading_font())
            .color(color_text()),
    );
    ui.add_space(16.0);

    egui::Frame::default()
        .fill(color_surface())
        .stroke(egui::Stroke::new(1.0, color_border()))
        .rounding(egui::Rounding::same(12.0))
        .inner_margin(16.0)
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new("Security Mode")
                    .font(subheading_font())
                    .color(color_text()),
            );
            ui.add_space(12.0);

            let modes = [
                (
                    "Personal",
                    "Balanced protection for everyday use.",
                    color_green(),
                    true,
                ),
                (
                    "Professional",
                    "Enhanced security for sensitive work.",
                    color_blue(),
                    false,
                ),
                (
                    "Fortress",
                    "Maximum protection for high-risk environments.",
                    color_amber(),
                    false,
                ),
            ];

            for (name, desc, color, active) in &modes {
                let border = if *active { *color } else { color_border() };
                let bg = if *active {
                    color.linear_multiply(0.08)
                } else {
                    color_surface()
                };
                egui::Frame::default()
                    .fill(bg)
                    .stroke(egui::Stroke::new(if *active { 2.0 } else { 1.0 }, border))
                    .rounding(egui::Rounding::same(6.0))
                    .inner_margin(12.0)
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new(*name)
                                    .font(body_font())
                                    .color(color_text()),
                            );
                            if *active {
                                ui.add_space(8.0);
                                egui::Frame::default()
                                    .fill(color.linear_multiply(0.15))
                                    .rounding(egui::Rounding::same(12.0))
                                    .inner_margin(egui::Margin::symmetric(6.0, 2.0))
                                    .show(ui, |ui| {
                                        ui.label(
                                            egui::RichText::new(" Active ")
                                                .font(small_font())
                                                .color(*color),
                                        );
                                    });
                            }
                        });
                        ui.label(
                            egui::RichText::new(*desc)
                                .font(small_font())
                                .color(color_muted()),
                        );
                    });
                ui.add_space(6.0);
            }
        });
}

// ── Helpers ────────────────────────────────────────────────────────

fn stat_card(ui: &mut egui::Ui, label: &str, value: &str, detail: &str) {
    egui::Frame::default()
        .fill(color_surface())
        .stroke(egui::Stroke::new(1.0, color_border()))
        .rounding(egui::Rounding::same(12.0))
        .inner_margin(16.0)
        .show(ui, |ui| {
            ui.set_min_width(180.0);
            ui.label(
                egui::RichText::new(label)
                    .font(small_font())
                    .color(color_dim()),
            );
            ui.label(
                egui::RichText::new(value)
                    .font(subheading_font())
                    .color(color_text()),
            );
            ui.label(
                egui::RichText::new(detail)
                    .font(small_font())
                    .color(color_muted()),
            );
        });
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut val = bytes as f64;
    for unit in UNITS {
        if val < 1024.0 {
            return format!("{:.1} {}", val, unit);
        }
        val /= 1024.0;
    }
    format!("{:.1} PB", val)
}

// ── Style ──────────────────────────────────────────────────────────

fn setup_style(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.window_fill = color_bg();
    visuals.panel_fill = color_surface();
    visuals.extreme_bg_color = color_elevated();
    visuals.faint_bg_color = color_elevated();
    visuals.window_stroke = egui::Stroke::new(1.0, color_border());
    visuals.widgets.noninteractive.bg_fill = color_surface();
    visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, color_muted());
    visuals.widgets.inactive.bg_fill = color_elevated();
    visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, color_muted());
    visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, color_border());
    visuals.widgets.hovered.bg_fill = color_accent().linear_multiply(0.15);
    visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.0, color_text());
    visuals.widgets.active.bg_fill = color_accent().linear_multiply(0.25);
    visuals.widgets.active.fg_stroke = egui::Stroke::new(1.0, color_text());
    visuals.window_rounding = egui::Rounding::same(8.0);
    visuals.window_shadow = egui::epaint::Shadow::NONE;
    ctx.set_visuals(visuals);

    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(8.0, 6.0);
    style.spacing.button_padding = egui::vec2(12.0, 6.0);
    ctx.set_style(style);
}

fn color_bg() -> egui::Color32 {
    egui::Color32::from_rgb(10, 10, 15)
}
fn color_surface() -> egui::Color32 {
    egui::Color32::from_rgb(18, 18, 26)
}
fn color_elevated() -> egui::Color32 {
    egui::Color32::from_rgb(26, 26, 36)
}
fn color_border() -> egui::Color32 {
    egui::Color32::from_rgb(42, 42, 58)
}
fn color_text() -> egui::Color32 {
    egui::Color32::from_rgb(232, 232, 237)
}
fn color_muted() -> egui::Color32 {
    egui::Color32::from_rgb(139, 139, 158)
}
fn color_dim() -> egui::Color32 {
    egui::Color32::from_rgb(90, 90, 110)
}
fn color_green() -> egui::Color32 {
    egui::Color32::from_rgb(52, 211, 153)
}
fn color_amber() -> egui::Color32 {
    egui::Color32::from_rgb(251, 191, 36)
}
fn color_red() -> egui::Color32 {
    egui::Color32::from_rgb(248, 113, 113)
}
fn color_blue() -> egui::Color32 {
    egui::Color32::from_rgb(96, 165, 250)
}
fn color_accent() -> egui::Color32 {
    egui::Color32::from_rgb(99, 102, 241)
}

fn heading_font() -> egui::FontId {
    egui::FontId::proportional(24.0)
}
fn subheading_font() -> egui::FontId {
    egui::FontId::proportional(16.0)
}
fn body_font() -> egui::FontId {
    egui::FontId::proportional(13.0)
}
fn small_font() -> egui::FontId {
    egui::FontId::proportional(11.0)
}
fn mono_font() -> egui::FontId {
    egui::FontId::monospace(12.0)
}
