//! Main dashboard — native egui rendering.
//!
//! Old-school security tool layout: sidebar nav, main content area,
//! status indicators, data tables. No fancy animations, just functional.

use crate::style::*;
use egui::{Context, RichText, Ui, Vec2};

#[derive(Clone, Copy, PartialEq)]
enum Tab {
    Dashboard,
    Volumes,
    Keys,
    Recovery,
    Settings,
}

pub struct DashboardState {
    active_tab: Tab,
    score: u8,
    encrypted_bytes: u64,
    total_bytes: u64,
    domains: Vec<Domain>,
    keys: Vec<KeyEntry>,
    events: Vec<Event>,
}

struct Domain {
    name: String,
    path: String,
    size: String,
    status: String,
}

struct KeyEntry {
    name: String,
    key_type: String,
    status: String,
    rotation_due: String,
}

struct Event {
    time: String,
    message: String,
    severity: String,
}

impl DashboardState {
    pub fn new() -> Self {
        Self {
            active_tab: Tab::Dashboard,
            score: 98,
            encrypted_bytes: 879_609_302_220,
            total_bytes: 1_073_741_824_000,
            domains: vec![
                Domain {
                    name: "Personal".into(),
                    path: "~/Documents".into(),
                    size: "500 GB".into(),
                    status: "Protected".into(),
                },
                Domain {
                    name: "Business".into(),
                    path: "~/Work".into(),
                    size: "300 GB".into(),
                    status: "Protected".into(),
                },
                Domain {
                    name: "Archive".into(),
                    path: "~/Archive".into(),
                    size: "80 GB".into(),
                    status: "Protected".into(),
                },
            ],
            keys: vec![
                KeyEntry {
                    name: "Volume Root".into(),
                    key_type: "Argon2id".into(),
                    status: "Active".into(),
                    rotation_due: "2026-07-15".into(),
                },
                KeyEntry {
                    name: "Domain: Personal".into(),
                    key_type: "HKDF".into(),
                    status: "Active".into(),
                    rotation_due: "2026-07-15".into(),
                },
                KeyEntry {
                    name: "Domain: Business".into(),
                    key_type: "HKDF".into(),
                    status: "Active".into(),
                    rotation_due: "2026-08-03".into(),
                },
            ],
            events: vec![
                Event {
                    time: "09:41".into(),
                    message: "System integrity verified".into(),
                    severity: "info".into(),
                },
                Event {
                    time: "09:38".into(),
                    message: "Encryption keys rotated".into(),
                    severity: "info".into(),
                },
                Event {
                    time: "09:22".into(),
                    message: "Filesystem scan complete".into(),
                    severity: "info".into(),
                },
            ],
        }
    }

    pub fn show(&mut self, ctx: &Context) {
        // Sidebar
        egui::SidePanel::left("sidebar")
            .resizable(false)
            .exact_width(200.0)
            .frame(
                egui::Frame::new()
                    .fill(SURFACE)
                    .stroke(Stroke::new(1.0, BORDER)),
            )
            .show(ctx, |ui| {
                self.draw_sidebar(ui);
            });

        // Main content
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(BG).inner_margin(20.0))
            .show(ctx, |ui| {
                // Top bar
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(match self.active_tab {
                            Tab::Dashboard => "Dashboard",
                            Tab::Volumes => "Volumes",
                            Tab::Keys => "Keys",
                            Tab::Recovery => "Recovery",
                            Tab::Settings => "Settings",
                        })
                        .font(heading_font())
                        .color(TEXT),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        egui::Frame::new()
                            .fill(GREEN.linear_multiply(0.15))
                            .rounding(Rounding::same(12.0))
                            .inner_margin(egui::Margin::symmetric(8, 3))
                            .show(ui, |ui| {
                                ui.label(
                                    RichText::new(" Protected ").font(small_font()).color(GREEN),
                                );
                            });
                    });
                });

                ui.add_space(16.0);
                ui.separator();
                ui.add_space(16.0);

                match self.active_tab {
                    Tab::Dashboard => self.draw_dashboard(ui),
                    Tab::Volumes => self.draw_volumes(ui),
                    Tab::Keys => self.draw_keys(ui),
                    Tab::Recovery => self.draw_recovery(ui),
                    Tab::Settings => self.draw_settings(ui),
                }
            });
    }

    fn draw_sidebar(&mut self, ui: &mut Ui) {
        ui.add_space(16.0);

        // Logo
        ui.horizontal(|ui| {
            ui.add_space(12.0);
            ui.label(RichText::new("🛡").font(FontId::new(24.0, FontFamily::Proportional)));
            ui.vertical(|ui| {
                ui.label(RichText::new("Soteria").font(subheading_font()).color(TEXT));
                ui.label(RichText::new("Aegis Runtime").font(small_font()).color(DIM));
            });
        });

        ui.add_space(20.0);
        ui.separator();
        ui.add_space(12.0);

        let tabs = [
            (Tab::Dashboard, "📊  Dashboard"),
            (Tab::Volumes, "💾  Volumes"),
            (Tab::Keys, "🔑  Keys"),
            (Tab::Recovery, "🛟  Recovery"),
            (Tab::Settings, "⚙  Settings"),
        ];

        for (tab, label) in &tabs {
            let active = self.active_tab == *tab;
            let color = if active { TEXT } else { MUTED };
            let bg = if active {
                ACCENT.linear_multiply(0.12)
            } else {
                egui::Color32::TRANSPARENT
            };

            let resp =
                ui.allocate_response(Vec2::new(ui.available_width(), 32.0), egui::Sense::click());

            if resp.hovered() || active {
                ui.painter().rect_filled(resp.rect, 6.0, bg);
            }

            ui.put(resp.rect, |ui: &mut Ui| {
                ui.horizontal(|ui| {
                    ui.add_space(12.0);
                    ui.label(RichText::new(*label).font(body_font()).color(color));
                });
            });

            if resp.clicked() {
                self.active_tab = *tab;
            }

            ui.add_space(2.0);
        }
    }

    fn draw_dashboard(&self, ui: &mut Ui) {
        // Protection score
        egui::Frame::new()
            .fill(SURFACE)
            .stroke(Stroke::new(1.0, BORDER))
            .rounding(Rounding::same(8.0))
            .inner_margin(16.0)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    // Score circle
                    let (rect, _) =
                        ui.allocate_exact_size(Vec2::new(80.0, 80.0), egui::Sense::hover());
                    let center = rect.center();
                    let radius = 36.0;
                    let color = if self.score >= 80 {
                        GREEN
                    } else if self.score >= 50 {
                        AMBER
                    } else {
                        RED
                    };

                    // Background ring
                    ui.painter()
                        .circle_stroke(center, radius, Stroke::new(6.0, ELEVATED));
                    // Foreground arc
                    let angle = (self.score as f32 / 100.0) * std::f32::consts::TAU;
                    let points: Vec<egui::Pos2> = (0..100)
                        .map(|i| {
                            let a = std::f32::consts::FRAC_PI_2 + (i as f32 / 100.0) * angle;
                            center + Vec2::new(-a.cos(), -a.sin()) * radius
                        })
                        .collect();
                    if points.len() > 1 {
                        ui.painter()
                            .add(egui::Shape::line(points, Stroke::new(6.0, color)));
                    }

                    // Score text
                    ui.painter().text(
                        center,
                        egui::Align2::CENTER_CENTER,
                        format!("{}", self.score),
                        FontId::new(24.0, FontFamily::Proportional),
                        color,
                    );

                    ui.add_space(20.0);

                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new("All Systems Protected")
                                .font(subheading_font())
                                .color(TEXT),
                        );
                        ui.add_space(4.0);
                        ui.label(
                            RichText::new("No active threats detected")
                                .font(small_font())
                                .color(MUTED),
                        );

                        ui.add_space(12.0);

                        ui.horizontal(|ui| {
                            for (label, value, color) in [
                                ("Boot Chain", "Verified", GREEN),
                                ("TPM", "Software", AMBER),
                                ("Keys", "Healthy", GREEN),
                                ("Recovery", "Verified", GREEN),
                            ] {
                                ui.vertical(|ui| {
                                    ui.label(RichText::new(label).font(small_font()).color(DIM));
                                    ui.label(RichText::new(value).font(small_font()).color(color));
                                });
                                ui.add_space(16.0);
                            }
                        });
                    });
                });
            });

        ui.add_space(12.0);

        // Stats row
        ui.horizontal(|ui| {
            let pct = if self.total_bytes > 0 {
                (self.encrypted_bytes as f64 / self.total_bytes as f64 * 100.0) as u32
            } else {
                0
            };

            stat_card(
                ui,
                "Encrypted Storage",
                &format_bytes(self.encrypted_bytes),
                &format!("{}% of {}", pct, format_bytes(self.total_bytes)),
            );
            ui.add_space(8.0);
            stat_card(
                ui,
                "Security Domains",
                &format!("{}", self.domains.len()),
                "Active domains",
            );
            ui.add_space(8.0);
            stat_card(ui, "Key Rotation", "Healthy", "Next: 12 days");
            ui.add_space(8.0);
            stat_card(ui, "Recovery", "Verified", "Last tested: 2 days ago");
        });

        ui.add_space(12.0);

        // Events
        egui::Frame::new()
            .fill(SURFACE)
            .stroke(Stroke::new(1.0, BORDER))
            .rounding(Rounding::same(8.0))
            .inner_margin(12.0)
            .show(ui, |ui| {
                ui.label(
                    RichText::new("Recent Activity")
                        .font(subheading_font())
                        .color(TEXT),
                );
                ui.add_space(8.0);

                for event in &self.events {
                    ui.horizontal(|ui| {
                        let color = match event.severity.as_str() {
                            "critical" => RED,
                            "warning" => AMBER,
                            _ => DIM,
                        };
                        ui.label(RichText::new("●").color(color).font(small_font()));
                        ui.add_space(4.0);
                        ui.label(RichText::new(&event.time).font(mono_font()).color(DIM));
                        ui.add_space(8.0);
                        ui.label(RichText::new(&event.message).font(body_font()).color(TEXT));
                    });
                    ui.add_space(4.0);
                }
            });
    }

    fn draw_volumes(&self, ui: &mut Ui) {
        ui.label(
            RichText::new("Protected Volumes")
                .font(subheading_font())
                .color(TEXT),
        );
        ui.add_space(12.0);

        egui::Frame::new()
            .fill(SURFACE)
            .stroke(Stroke::new(1.0, BORDER))
            .rounding(Rounding::same(8.0))
            .inner_margin(12.0)
            .show(ui, |ui| {
                for domain in &self.domains {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("💾").font(body_font()));
                        ui.add_space(8.0);
                        ui.vertical(|ui| {
                            ui.label(RichText::new(&domain.name).font(body_font()).color(TEXT));
                            ui.label(
                                RichText::new(format!("{} · {}", domain.path, domain.size))
                                    .font(small_font())
                                    .color(DIM),
                            );
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            egui::Frame::new()
                                .fill(GREEN.linear_multiply(0.15))
                                .rounding(Rounding::same(12.0))
                                .inner_margin(egui::Margin::symmetric(8, 3))
                                .show(ui, |ui| {
                                    ui.label(
                                        RichText::new(" Protected ")
                                            .font(small_font())
                                            .color(GREEN),
                                    );
                                });
                        });
                    });
                    ui.add_space(8.0);
                    ui.separator();
                    ui.add_space(8.0);
                }
            });
    }

    fn draw_keys(&self, ui: &mut Ui) {
        ui.label(
            RichText::new("Key Lifecycle")
                .font(subheading_font())
                .color(TEXT),
        );
        ui.add_space(12.0);

        egui::Frame::new()
            .fill(SURFACE)
            .stroke(Stroke::new(1.0, BORDER))
            .rounding(Rounding::same(8.0))
            .inner_margin(12.0)
            .show(ui, |ui| {
                // Table header
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Key").font(small_font()).color(DIM));
                    ui.add_space(120.0);
                    ui.label(RichText::new("Type").font(small_font()).color(DIM));
                    ui.add_space(80.0);
                    ui.label(RichText::new("Status").font(small_font()).color(DIM));
                    ui.add_space(80.0);
                    ui.label(RichText::new("Rotation Due").font(small_font()).color(DIM));
                });
                ui.add_space(8.0);
                ui.separator();
                ui.add_space(8.0);

                for key in &self.keys {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(&key.name).font(body_font()).color(TEXT));
                        ui.add_space(120.0 - key.name.len() as f32 * 6.0);
                        ui.label(RichText::new(&key.key_type).font(small_font()).color(MUTED));
                        ui.add_space(80.0);
                        egui::Frame::new()
                            .fill(GREEN.linear_multiply(0.15))
                            .rounding(Rounding::same(12.0))
                            .inner_margin(egui::Margin::symmetric(8, 3))
                            .show(ui, |ui| {
                                ui.label(
                                    RichText::new(&key.status).font(small_font()).color(GREEN),
                                );
                            });
                        ui.add_space(80.0);
                        ui.label(
                            RichText::new(&key.rotation_due)
                                .font(small_font())
                                .color(MUTED),
                        );
                    });
                    ui.add_space(8.0);
                }
            });
    }

    fn draw_recovery(&self, ui: &mut Ui) {
        ui.label(
            RichText::new("Recovery Center")
                .font(subheading_font())
                .color(TEXT),
        );
        ui.add_space(12.0);

        egui::Frame::new()
            .fill(SURFACE)
            .stroke(Stroke::new(1.0, BORDER))
            .rounding(Rounding::same(8.0))
            .inner_margin(16.0)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("🛟").font(FontId::new(32.0, FontFamily::Proportional)));
                    ui.add_space(12.0);
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new("Recovery Key Verified")
                                .font(subheading_font())
                                .color(GREEN),
                        );
                        ui.label(
                            RichText::new("Last tested 2 days ago. Your backup is working.")
                                .font(body_font())
                                .color(MUTED),
                        );
                    });
                });

                ui.add_space(16.0);

                ui.horizontal(|ui| {
                    for (label, value, color) in [
                        ("Status", "Ready", GREEN),
                        ("Last Tested", "2 days ago", MUTED),
                        ("Backup Copies", "2", MUTED),
                    ] {
                        egui::Frame::new()
                            .fill(ELEVATED)
                            .rounding(Rounding::same(6.0))
                            .inner_margin(12.0)
                            .show(ui, |ui| {
                                ui.set_min_width(150.0);
                                ui.label(RichText::new(label).font(small_font()).color(DIM));
                                ui.label(RichText::new(value).font(subheading_font()).color(color));
                            });
                        ui.add_space(8.0);
                    }
                });
            });
    }

    fn draw_settings(&mut self, ui: &mut Ui) {
        ui.label(
            RichText::new("Security Mode")
                .font(subheading_font())
                .color(TEXT),
        );
        ui.add_space(12.0);

        let modes = [
            ("Personal", "Balanced protection for everyday use", GREEN),
            ("Professional", "Enhanced security for sensitive work", BLUE),
            (
                "Fortress",
                "Maximum protection for high-risk environments",
                AMBER,
            ),
        ];

        egui::Frame::new()
            .fill(SURFACE)
            .stroke(Stroke::new(1.0, BORDER))
            .rounding(Rounding::same(8.0))
            .inner_margin(16.0)
            .show(ui, |ui| {
                for (i, (name, desc, color)) in modes.iter().enumerate() {
                    let selected = i == 0; // default to personal
                    let bg = if selected {
                        color.linear_multiply(0.08)
                    } else {
                        SURFACE
                    };
                    let border = if selected { *color } else { BORDER };

                    egui::Frame::new()
                        .fill(bg)
                        .stroke(Stroke::new(if selected { 2.0 } else { 1.0 }, border))
                        .rounding(Rounding::same(6.0))
                        .inner_margin(12.0)
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(*name).font(body_font()).color(TEXT));
                                ui.add_space(8.0);
                                if selected {
                                    egui::Frame::new()
                                        .fill(color.linear_multiply(0.15))
                                        .rounding(Rounding::same(12.0))
                                        .inner_margin(egui::Margin::symmetric(6, 2))
                                        .show(ui, |ui| {
                                            ui.label(
                                                RichText::new(" Active ")
                                                    .font(small_font())
                                                    .color(*color),
                                            );
                                        });
                                }
                            });
                            ui.label(RichText::new(*desc).font(small_font()).color(MUTED));
                        });
                    ui.add_space(6.0);
                }
            });
    }
}

fn stat_card(ui: &mut Ui, label: &str, value: &str, detail: &str) {
    egui::Frame::new()
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, BORDER))
        .rounding(Rounding::same(8.0))
        .inner_margin(12.0)
        .show(ui, |ui| {
            ui.set_min_width(200.0);
            ui.label(RichText::new(label).font(small_font()).color(DIM));
            ui.label(RichText::new(value).font(subheading_font()).color(TEXT));
            ui.label(RichText::new(detail).font(small_font()).color(MUTED));
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
