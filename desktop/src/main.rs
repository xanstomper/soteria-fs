//! Soteria Aegis — VeraCrypt-class desktop application.
//!
//! Layout: menu bar · volume target field · Mount / Dismount / Auto-Mount
//! buttons · scrollable volume list · status bar.
//!
//! Operations call the desktop core bridge directly.  No subprocess, no HTTP.
//! First-launch wizard mirrors VeraCrypt's "Volume Creation Wizard".

mod core;

use eframe::egui;
use std::path::PathBuf;

// ═══════════════════════════════════════════════════════════════════════════════
// Entry point
// ═══════════════════════════════════════════════════════════════════════════════
fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([920.0, 660.0])
            .with_min_inner_size([750.0, 500.0])
            .with_title("Soteria"),
        ..Default::default()
    };
    eframe::run_native(
        "Soteria",
        options,
        Box::new(|cc| {
            apply_classic_style(&cc.egui_ctx);
            Ok(Box::new(App::new()))
        }),
    )
}

// ═══════════════════════════════════════════════════════════════════════════════
// State
// ═══════════════════════════════════════════════════════════════════════════════
#[derive(Clone)]
struct Volume {
    name: String,
    path: PathBuf,
    size_bytes: u64,
    mounted: bool,
    mount_point: Option<String>,
    algo: String,
    size_str: String,
}

impl Volume {
    fn new(name: String, path: PathBuf, size_bytes: u64) -> Self {
        Self {
            name,
            path,
            size_bytes,
            mounted: false,
            mount_point: None,
            algo: "AES-256-XTS".into(),
            size_str: fmt_size(size_bytes),
        }
    }
}

#[derive(PartialEq)]
enum Dialog {
    None,
    CreateVolume,
}

struct App {
    volumes: Vec<Volume>,
    volume_target: String,
    volume_target_path: PathBuf,
    password: String,
    show_password: bool,
    status: String,
    detail: String,
    busy: bool,
    dialog: Dialog,
    first_run: bool,
    cv_size_mb: u64,
    cv_pass1: String,
    cv_pass2: String,
    cv_fast_kdf: bool,
    cv_step: usize,
    cv_last_path: Option<PathBuf>,
    cv_error: String,
    cv_progress: f32,
}

impl App {
    fn new() -> Self {
        let vault = default_vault();
        let _ = std::fs::create_dir_all(&vault);
        let mut app = Self {
            volumes: Vec::new(),
            volume_target: String::new(),
            volume_target_path: PathBuf::new(),
            password: String::new(),
            show_password: false,
            status: "Ready".into(),
            detail: String::new(),
            busy: false,
            dialog: Dialog::None,
            first_run: true,
            cv_size_mb: 1024,
            cv_pass1: String::new(),
            cv_pass2: String::new(),
            cv_fast_kdf: false,
            cv_step: 0,
            cv_last_path: None,
            cv_error: String::new(),
            cv_progress: 0.0,
        };
        app.reload_volumes();
        if app.volumes.is_empty() {
            app.first_run = true;
        }
        app
    }

    fn reload_volumes(&mut self) {
        let vault = default_vault();
        let files = core::list_volumes(&vault);
        self.volumes = files
            .into_iter()
            .map(|(name, size)| Volume::new(name.clone(), backing_path(&vault, &name), size))
            .collect();
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Classic Windows styling
// ═══════════════════════════════════════════════════════════════════════════════
fn apply_classic_style(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.visuals.panel_fill = egui::Color32::from_rgb(236, 233, 216);
    style.visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(212, 212, 212);
    style.visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(236, 233, 216);
    style.visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(255, 255, 255);
    style.visuals.widgets.active.bg_fill = egui::Color32::from_rgb(180, 180, 180);
    style.visuals.selection.bg_fill = egui::Color32::from_rgb(0, 120, 215);
    style.visuals.selection.stroke.color = egui::Color32::WHITE;
    style.spacing.button_padding = egui::vec2(8.0, 4.0);
    style.spacing.menu_margin = egui::Margin::same(2.0);
    ctx.set_style(style);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════════
fn default_vault() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("Soteria")
        .join("volumes")
}

fn backing_path(vault: &PathBuf, name: &str) -> PathBuf {
    vault.join(format!("{name}.sot"))
}

fn fmt_size(b: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if b >= GB {
        format!("{:.2} GB", b as f64 / GB as f64)
    } else if b >= MB {
        format!("{:.1} MB", b as f64 / MB as f64)
    } else if b >= KB {
        format!("{:.0} KB", b as f64 / KB as f64)
    } else {
        format!("{b} B")
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// eframe App impl
// ═══════════════════════════════════════════════════════════════════════════════
impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let show_wizard = self.first_run && self.volumes.is_empty();

        if show_wizard {
            egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
                self.draw_menu_bar(ui);
            });
            egui::CentralPanel::default()
                .frame(egui::Frame::none().fill(egui::Color32::from_rgb(240, 240, 240)))
                .show(ctx, |ui| {
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        self.draw_welcome(ui);
                    });
                });
            egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
                self.draw_status_bar(ui);
            });
            if let Dialog::CreateVolume = self.dialog {
                egui::Window::new("Soteria Volume Creation Wizard")
                    .collapsible(false)
                    .resizable(false)
                    .default_size(egui::vec2(620.0, 460.0))
                    .show(ctx, |ui| self.draw_cv_wizard_ui(ui));
            }
            return;
        }

        // ── Normal main window ──────────────────────────────────────────
        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            self.draw_menu_bar(ui);
        });

        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(egui::Color32::from_rgb(240, 240, 240)))
            .show(ctx, |ui| {
                ui.add_space(4.0);
                self.draw_mount_area(ui);
                ui.add_space(6.0);
                self.draw_action_buttons(ui);
                ui.add_space(6.0);
                self.draw_volume_list(ui);
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.small(
                        egui::RichText::new(
                            "Ctrl+P  Focus password   |   Ctrl+M  Mount   |   Ctrl+D  Dismount",
                        )
                        .italics()
                        .color(egui::Color32::GRAY),
                    );
                });
            });

        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            self.draw_status_bar(ui);
        });

        // Modal wizard
        if let Dialog::CreateVolume = self.dialog {
            egui::Window::new("Soteria Volume Creation Wizard")
                .collapsible(false)
                .resizable(false)
                .default_size(egui::vec2(620.0, 460.0))
                .show(ctx, |ui| self.draw_cv_wizard_ui(ui));
        }

        // Keyboard shortcuts
        let input = ctx.input(|i| i.clone());
        if input.key_pressed(egui::Key::P) && input.modifiers.ctrl {
            // Focus password by reopening — for demo, just log
        }
        if input.key_pressed(egui::Key::M) && input.modifiers.ctrl {
            if !self.busy
                && !self.volume_target_path.as_os_str().is_empty()
                && !self.password.is_empty()
            {
                self.do_mount();
            }
        }
        if input.key_pressed(egui::Key::D) && input.modifiers.ctrl {
            if !self.busy && self.volumes.iter().any(|v| v.mounted) {
                self.do_dismount_all();
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Menu bar
// ═══════════════════════════════════════════════════════════════════════════════
impl App {
    fn draw_menu_bar(&mut self, ui: &mut egui::Ui) {
        egui::Frame::none()
            .fill(egui::Color32::from_rgb(236, 233, 216))
            .stroke(egui::Stroke::new(
                1.0,
                egui::Color32::from_rgb(180, 180, 180),
            ))
            .inner_margin(4.0)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.menu_button("File", |ui| {
                        if ui.button("Create Volume File...").clicked() {
                            self.dialog = Dialog::CreateVolume;
                            self.cv_step = 0;
                            self.cv_error.clear();
                            ui.close_menu();
                        }
                        if ui.button("Exit").clicked() {
                            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                            ui.close_menu();
                        }
                    });

                    ui.menu_button("Volume", |ui| {
                        let can = !self.busy
                            && !self.volume_target.is_empty()
                            && !self.password.is_empty();
                        if ui.add_enabled(can, egui::Button::new("Mount")).clicked() {
                            self.do_mount();
                            ui.close_menu();
                        }
                        let has_mounted = self.volumes.iter().any(|v| v.mounted);
                        if ui
                            .add_enabled(has_mounted, egui::Button::new("Dismount"))
                            .clicked()
                        {
                            self.do_dismount_all();
                            ui.close_menu();
                        }
                    });

                    ui.menu_button("Tools", |ui| {
                        if ui.button("Test Volume...").clicked() {
                            ui.close_menu();
                        }
                        if ui.button("Benchmark...").clicked() {
                            ui.close_menu();
                        }
                    });

                    ui.menu_button("Settings", |ui| {
                        if ui.button("Preferences").clicked() {
                            ui.close_menu();
                        }
                    });

                    ui.menu_button("Help", |ui| {
                        if ui.button("About Soteria...").clicked() {
                            ui.close_menu();
                        }
                    });

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            egui::RichText::new("Soteria v0.1.1")
                                .size(11.0)
                                .italics()
                                .color(egui::Color32::GRAY),
                        );
                    });
                });
            });
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Mount area (VeraCrypt upper panel)
// ═══════════════════════════════════════════════════════════════════════════════
impl App {
    fn draw_mount_area(&mut self, ui: &mut egui::Ui) {
        egui::Frame::none()
            .fill(egui::Color32::from_rgb(222, 222, 222))
            .stroke(egui::Stroke::new(
                1.0,
                egui::Color32::from_rgb(160, 160, 160),
            ))
            .inner_margin(8.0)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Volume:").size(12.0).strong());
                    ui.add_sized(
                        egui::vec2(440.0, 24.0),
                        egui::TextEdit::singleline(&mut self.volume_target)
                            .hint_text("C:\\path\\to\\volume.sot")
                            .margin(egui::vec2(4.0, 2.0)),
                    );
                    if ui.button("Select File...").clicked() {
                        if let Some(path) = rfd::FileDialog::new()
                            .add_filter("Soteria volume", &["sot"])
                            .pick_file()
                        {
                            let name = path
                                .file_stem()
                                .and_then(|s| s.to_str())
                                .unwrap_or("")
                                .to_string();
                            self.volume_target = name;
                            self.volume_target_path = path;
                        }
                    }
                });
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Password:").size(12.0).strong());
                    ui.add_sized(
                        egui::vec2(220.0, 24.0),
                        egui::TextEdit::singleline(&mut self.password)
                            .password(!self.show_password)
                            .hint_text("Enter password")
                            .margin(egui::vec2(4.0, 2.0)),
                    );
                    ui.checkbox(&mut self.show_password, "Show password");
                    ui.add_space(12.0);
                    ui.small(
                        egui::RichText::new(format!("File: {}", self.volume_target_path.display()))
                            .color(egui::Color32::GRAY),
                    );
                });
            });
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Mount / Dismount buttons (exact VeraCrypt layout)
// ═══════════════════════════════════════════════════════════════════════════════
impl App {
    fn draw_action_buttons(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let can_mount = !self.busy
                && !self.volume_target_path.as_os_str().is_empty()
                && !self.password.is_empty();
            let has_mounted = self.volumes.iter().any(|v| v.mounted);

            let m_btn = ui.add_enabled(can_mount, classic_btn("Mount"));
            if m_btn.clicked() {
                self.do_mount();
            }

            let d_btn = ui.add_enabled(has_mounted && !self.busy, classic_btn("Dismount"));
            if d_btn.clicked() {
                self.do_dismount_all();
            }

            ui.add_space(8.0);
            ui.separator();
            ui.add_space(8.0);

            let auto_btn =
                ui.add_enabled(!self.volumes.is_empty(), classic_btn("Auto-Mount Devices"));
            if auto_btn.clicked() {
                self.detail = "Auto-mount available for device-based volumes.".into();
            }
        });
    }

    fn do_mount(&mut self) {
        let target = self.volume_target_path.clone();
        self.busy = true;
        let res = core::open_volume(&target, &self.password);
        self.busy = false;
        match res {
            r if r.ok => {
                self.status = "Mounted".into();
                self.detail = r.message;
                self.password.clear();
                self.reload_volumes();
            }
            r => {
                self.status = "Mount failed".into();
                self.detail = r.message;
            }
        }
    }

    fn do_dismount_all(&mut self) {
        let to_close: Vec<Volume> = self.volumes.iter().filter(|v| v.mounted).cloned().collect();
        for vol in to_close {
            let _ = core::close_volume(&vol.path);
        }
        self.status = "Dismounted all".into();
        self.detail = String::new();
        self.reload_volumes();
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Volume list (VeraCrypt table)
// ═══════════════════════════════════════════════════════════════════════════════
impl App {
    fn draw_volume_list(&mut self, ui: &mut egui::Ui) {
        if self.volumes.is_empty() {
            egui::Frame::none()
                .fill(egui::Color32::WHITE)
                .stroke(egui::Stroke::new(
                    1.0,
                    egui::Color32::from_rgb(180, 180, 180),
                ))
                .inner_margin(6.0)
                .show(ui, |ui| {
                    ui.colored_label(egui::Color32::GRAY, "No volumes in the vault directory.");
                    ui.small("Use File → Create Volume File... to get started.");
                });
            return;
        }

        egui::Frame::none()
            .fill(egui::Color32::WHITE)
            .stroke(egui::Stroke::new(
                1.0,
                egui::Color32::from_rgb(180, 180, 180),
            ))
            .inner_margin(4.0)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Volumes").size(12.0).strong());
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.small(format!("{} volumes", self.volumes.len()));
                    });
                });
                ui.separator();

                egui::ScrollArea::vertical().max_height(210.0).show_rows(
                    ui,
                    22.0,
                    self.volumes.len(),
                    |ui, row_range| {
                        for idx in row_range {
                            self.draw_volume_row(ui, idx);
                        }
                    },
                );
            });
    }

    fn draw_volume_row(&mut self, ui: &mut egui::Ui, idx: usize) {
        let vol = &self.volumes[idx];
        let mounted_txt = if vol.mounted { "✔" } else { " " };
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new(mounted_txt)
                    .size(12.0)
                    .color(if vol.mounted {
                        egui::Color32::GREEN
                    } else {
                        egui::Color32::GRAY
                    }),
            );
            ui.add_space(4.0);
            ui.strong(&vol.name);
            ui.add_space(16.0);
            ui.small(&vol.size_str);
            ui.add_space(12.0);
            ui.small(&vol.algo);
            ui.add_space(12.0);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.small(if vol.mounted { "Open" } else { "Ready" });
            });
        });
        if idx < self.volumes.len() - 1 {
            ui.separator();
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Status bar
// ═══════════════════════════════════════════════════════════════════════════════
impl App {
    fn draw_status_bar(&mut self, ui: &mut egui::Ui) {
        egui::Frame::none()
            .fill(egui::Color32::from_rgb(236, 233, 216))
            .stroke(egui::Stroke::new(
                1.0,
                egui::Color32::from_rgb(180, 180, 180),
            ))
            .inner_margin(4.0)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    let color = if self.status.contains("fail") || self.status.contains("Error") {
                        egui::Color32::RED
                    } else if self.status == "Mounted" {
                        egui::Color32::GREEN
                    } else {
                        egui::Color32::DARK_GRAY
                    };
                    ui.colored_label(color, "●");
                    ui.small(self.status.clone());
                    ui.add_space(12.0);
                    ui.small(self.detail.clone());
                });
            });
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Welcome screen (first run)
// ═══════════════════════════════════════════════════════════════════════════════
impl App {
    fn draw_welcome(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(40.0);
            ui.label(egui::RichText::new("Soteria Aegis").size(30.0).strong());
            ui.add_space(6.0);
            ui.label(
                egui::RichText::new(
                    "Hardware-rooted encrypted storage for the modern threat landscape",
                )
                .size(13.0)
                .italics()
                .color(egui::Color32::GRAY),
            );
            ui.add_space(32.0);

            egui::Frame::none()
                .fill(egui::Color32::from_rgb(220, 220, 220))
                .stroke(egui::Stroke::new(
                    1.0,
                    egui::Color32::from_rgb(180, 180, 180),
                ))
                .inner_margin(20.0)
                .show(ui, |ui| {
                    ui.strong("Welcome! No encrypted volumes were found in the vault directory.");
                    ui.add_space(8.0);
                    ui.label("To get started:");
                    ui.horizontal(|ui| {
                        ui.label("1.");
                        ui.label(
                            "Choose File → Create Volume File... to create a new encrypted volume.",
                        );
                    });
                    ui.horizontal(|ui| {
                        ui.label("2.");
                        ui.label("Enter a strong password.");
                    });
                    ui.horizontal(|ui| {
                        ui.label("3.");
                        ui.label("Use Mount to open volumes.");
                    });
                });

            ui.add_space(16.0);
            if ui.button("Create Volume File...").clicked() {
                self.dialog = Dialog::CreateVolume;
                self.cv_step = 0;
                self.cv_error.clear();
            }
        });
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Volume Creation Wizard (exact VeraCrypt 6-step wizard)
// ═══════════════════════════════════════════════════════════════════════════════
impl App {
    fn draw_cv_wizard_ui(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.strong(format!(
                "Soteria Volume Creation Wizard — Step {}",
                self.cv_step + 1
            ));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Cancel").clicked() {
                    self.dialog = Dialog::None;
                    self.cv_step = 0;
                    self.cv_error.clear();
                }
            });
        });
        ui.separator();

        match self.cv_step {
            0 => self.cv_step_location(ui),
            1 => self.cv_step_size(ui),
            2 => self.cv_step_password(ui),
            3 => self.cv_step_format(ui),
            4 => self.cv_step_done(ui),
            _ => {}
        }
    }

    // ── Step 0: Location ─────────────────────────────────────────────
    fn cv_step_location(&mut self, ui: &mut egui::Ui) {
        ui.label("Please select where on your disk you want the new volume file to be created.");
        ui.add_space(12.0);

        ui.horizontal(|ui| {
            ui.label("Volume file:");
            ui.add_sized(
                egui::vec2(460.0, 24.0),
                egui::TextEdit::singleline(&mut self.volume_target)
                    .hint_text("C:\\path\\to\\MyVolume.sot"),
            );
            if ui.button("Select File...").clicked() {
                if let Some(path) = rfd::FileDialog::new().save_file() {
                    self.cv_last_path = Some(path.clone());
                    self.volume_target = path.display().to_string();
                    self.volume_target_path = path;
                }
            }
        });

        ui.add_space(16.0);
        ui.horizontal(|ui| {
            if ui.button("Cancel").clicked() {
                self.dialog = Dialog::None;
                self.cv_step = 0;
                self.cv_error.clear();
            }
            ui.add_space(4.0);
            if ui.button("Next >").clicked() {
                if self.cv_last_path.is_none() {
                    self.cv_error = "Please choose a file path.".into();
                } else {
                    self.cv_step = 1;
                    self.cv_error.clear();
                }
            }
        });

        if !self.cv_error.is_empty() {
            ui.colored_label(egui::Color32::RED, &self.cv_error);
        }
    }

    // ── Step 1: Size ─────────────────────────────────────────────────
    fn cv_step_size(&mut self, ui: &mut egui::Ui) {
        ui.label("Specify the size of the new volume file.");
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            ui.label("Volume size (MB):");
            ui.add_sized(
                egui::vec2(140.0, 24.0),
                egui::DragValue::new(&mut self.cv_size_mb)
                    .clamp_range(1..=16_384_000)
                    .suffix(" MB"),
            );
        });
        ui.add_space(4.0);
        ui.small(format!("{} MB will be allocated.", self.cv_size_mb));
        ui.add_space(16.0);
        ui.horizontal(|ui| {
            if ui.button("< Back").clicked() {
                self.cv_step -= 1;
                self.cv_error.clear();
            }
            ui.add_space(4.0);
            if ui.button("Next >").clicked() {
                self.cv_step = 2;
                self.cv_error.clear();
            }
        });
    }

    // ── Step 2: Password ─────────────────────────────────────────────
    fn cv_step_password(&mut self, ui: &mut egui::Ui) {
        ui.label("Enter and confirm a password for the volume. Use a strong, unique password.");
        ui.add_space(12.0);
        ui.checkbox(&mut self.cv_fast_kdf, "Use fast KDF (for testing only)");

        ui.add_space(8.0);
        ui.label("Password:");
        ui.add_sized(
            egui::vec2(340.0, 24.0),
            egui::TextEdit::singleline(&mut self.cv_pass1).password(true),
        );

        ui.add_space(6.0);
        ui.label("Confirm password:");
        ui.add_sized(
            egui::vec2(340.0, 24.0),
            egui::TextEdit::singleline(&mut self.cv_pass2).password(true),
        );

        if !self.cv_error.is_empty() {
            ui.colored_label(egui::Color32::RED, &self.cv_error);
        }
        ui.add_space(16.0);
        ui.horizontal(|ui| {
            if ui.button("< Back").clicked() {
                self.cv_step -= 1;
                self.cv_error.clear();
            }
            ui.add_space(4.0);
            if ui.button("Next >").clicked() {
                if self.cv_pass1.is_empty() {
                    self.cv_error = "Password cannot be empty.".into();
                } else if self.cv_pass1 != self.cv_pass2 {
                    self.cv_error = "Passwords do not match.".into();
                } else {
                    self.cv_step = 3;
                    self.cv_error.clear();
                }
            }
        });
    }

    // ── Step 3: Format (actual work) ────────────────────────────────
    fn cv_step_format(&mut self, ui: &mut egui::Ui) {
        ui.label("Ready to create the volume. Click Format to begin.");
        ui.add_space(12.0);
        ui.separator();
        ui.horizontal(|ui| {
            ui.label("Location:");
            ui.label(&self.volume_target);
            ui.label("Size(MB):");
            ui.label(format!("{} MB", self.cv_size_mb));
            ui.label("Encryption:");
            ui.label("AES-256-XTS + Argon2id");
        });
        ui.separator();

        if !self.cv_error.is_empty() {
            ui.colored_label(egui::Color32::RED, &self.cv_error);
        }

        ui.add_space(12.0);
        ui.horizontal(|ui| {
            if ui.button("< Back").clicked() {
                self.cv_step -= 1;
                self.cv_error.clear();
            }
            ui.add_space(4.0);
            let fmt_btn = ui.add_enabled(!self.busy, classic_btn("Format"));
            if fmt_btn.clicked() {
                if let Some(path) = self.cv_last_path.clone() {
                    self.busy = true;
                    self.cv_progress = 0.0;
                    let res = core::create_volume(
                        &path,
                        &self.cv_pass1,
                        self.cv_size_mb,
                        self.cv_fast_kdf,
                    );
                    self.busy = false;
                    if res.ok {
                        self.cv_progress = 1.0;
                        self.cv_step = 4;
                        self.status = "Created".into();
                        self.detail = res.message;
                        self.first_run = false;
                    } else {
                        self.cv_error = res.message;
                    }
                }
            }
        });

        ui.add_space(8.0);
        ui.add(
            egui::ProgressBar::new(self.cv_progress)
                .show_percentage()
                .animate(self.busy),
        );
    }

    // ── Step 4: Done ─────────────────────────────────────────────────
    fn cv_step_done(&mut self, ui: &mut egui::Ui) {
        ui.label(
            egui::RichText::new("The volume has been created successfully.")
                .color(egui::Color32::from_rgb(0, 128, 0))
                .strong(),
        );
        ui.add_space(16.0);
        ui.label("Use the main window to mount the volume — just click the file path in the Mount area or select it, enter the password, and click Mount.");
        ui.add_space(20.0);
        if ui.button("Finish").clicked() {
            if let Some(path) = self.cv_last_path.take() {
                self.volume_target = path.display().to_string();
                self.volume_target_path = path;
            }
            self.dialog = Dialog::None;
            self.cv_step = 0;
            self.cv_error.clear();
            self.reload_volumes();
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Button helper
// ═══════════════════════════════════════════════════════════════════════════════
fn classic_btn(text: &str) -> egui::Button<'static> {
    egui::Button::new(egui::RichText::new(text).size(13.0)).min_size(egui::vec2(80.0, 24.0))
}

