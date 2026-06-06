//! Soteria Aegis — VeraCrypt-class desktop application.
//!
//! Exact VeraCrypt UI: menu bar + volume target + password field +
//! Mount / Dismount / Auto-Mount buttons + scrollable volume list
//! with columns {Mounted | Volume | Size | Type | Status | Mount Point}
//! + status bar + volume creation wizard (5 steps).
//!
//! All operations call the core bridge directly.  No subprocesses, no HTTP.

mod core;

use eframe::egui;
use std::path::PathBuf;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([920.0, 660.0])
            .with_min_inner_size([720.0, 480.0])
            .with_title("Soteria"),
        ..Default::default()
    };
    eframe::run_native(
        "Soteria",
        options,
        Box::new(|cc| {
            classic_style(&cc.egui_ctx);
            Ok(Box::new(App::new()))
        }),
    )
}

#[derive(Clone)]
struct Vol {
    name: String,
    path: PathBuf,
    size_bytes: u64,
    mounted: bool,
    mount_point: Option<String>,
    algo: String,
    size_str: String,
    status: String,
}

impl Vol {
    fn new(name: String, path: PathBuf, size_bytes: u64) -> Self {
        Self {
            size_str: fmt_size(size_bytes),
            status: "Ready".into(),
            algo: "AES-256-XTS".into(),
            mounted: false,
            mount_point: None,
            name,
            path,
            size_bytes,
        }
    }
}

struct App {
    volumes: Vec<Vol>,
    vol_target: String,
    vol_path: PathBuf,
    password: String,
    show_pw: bool,
    status: String,
    detail: String,
    busy: bool,
    wizard: bool,
    w_step: usize,
    w_size_str: String,
    w_pw1: String,
    w_pw2: String,
    w_fast: bool,
    w_path: Option<PathBuf>,
    w_err: String,
    first_run: bool,
}

impl App {
    fn new() -> Self {
        let vault = default_vault();
        let _ = std::fs::create_dir_all(&vault);
        let vols = core::list_volumes(&vault)
            .into_iter()
            .map(|(n, s)| Vol::new(n.clone(), vault.join(format!("{n}.sot")), s))
            .collect::<Vec<_>>();
        let first_run = vols.is_empty();
        Self {
            volumes: vols,
            vol_target: String::new(),
            vol_path: PathBuf::new(),
            password: String::new(),
            show_pw: false,
            status: "Ready".into(),
            detail: String::new(),
            busy: false,
            wizard: false,
            w_step: 0,
            w_size_str: "1024".into(),
            w_pw1: String::new(),
            w_pw2: String::new(),
            w_fast: false,
            w_path: None,
            w_err: String::new(),
            first_run,
        }
    }

    fn w_size_mb_u64(&self) -> u64 {
        self.w_size_str.parse().unwrap_or(1024)
    }

    fn reload(&mut self) {
        let vault = default_vault();
        let files = core::list_volumes(&vault);
        self.volumes = files
            .into_iter()
            .map(|(n, s)| Vol::new(n.clone(), vault.join(format!("{n}.sot")), s))
            .collect();
    }

    fn do_mount(&mut self) {
        if self.vol_path.as_os_str().is_empty() || self.password.is_empty() {
            self.status = "No volume or password".into();
            return;
        }
        self.busy = true;
        let r = core::open_volume(&self.vol_path, &self.password);
        self.busy = false;
        if r.ok {
            self.status = "Mounted".into();
            self.detail = r.message;
            self.password.clear();
            self.reload();
        } else {
            self.status = "Mount failed".into();
            self.detail = r.message;
        }
    }

    fn do_dismount(&mut self) {
        let targets: Vec<Vol> = self.volumes.iter().filter(|v| v.mounted).cloned().collect();
        for v in targets {
            let _ = core::close_volume(&v.path);
        }
        self.status = "Dismounted".into();
        self.detail = String::new();
        self.reload();
    }
}

fn classic_style(ctx: &egui::Context) {
    let mut s = (*ctx.style()).clone();
    s.visuals.panel_fill = egui::Color32::from_rgb(236, 233, 216);
    s.visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(212, 208, 200);
    s.visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(255, 255, 255);
    s.visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(229, 229, 229);
    s.visuals.widgets.active.bg_fill = egui::Color32::from_rgb(180, 180, 180);
    s.visuals.popup_shadow = egui::Shadow::NONE;
    s.spacing.button_padding = egui::vec2(6.0, 4.0);
    s.spacing.menu_margin = egui::Margin::same(2.0);
    s.spacing.item_spacing = egui::vec2(4.0, 3.0);
    ctx.set_style(s);
}

fn default_vault() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("Soteria")
        .join("volumes")
}

fn fmt_size(b: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if b >= GB {
        format!("{:.2} GB", b as f64 / GB as f64)
    } else if b >= MB {
        format!("{:.0} MB", b as f64 / MB as f64)
    } else if b >= KB {
        format!("{:.0} KB", b as f64 / KB as f64)
    } else {
        format!("{b} B")
    }
}

fn vc_btn(text: &str) -> egui::Button<'static> {
    egui::Button::new(egui::RichText::new(text).size(12.0)).min_size(egui::vec2(80.0, 22.0))
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.first_run && self.volumes.is_empty() && self.status == "Ready" {
            self.welcome(ctx);
            return;
        }

        egui::TopBottomPanel::top("menu").show(ctx, |ui| {
            self.menu_bar(ui);
        });
        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(egui::Color32::from_rgb(240, 240, 240)))
            .show(ctx, |ui| {
                ui.add_space(4.0);
                self.toolbar(ui);
                ui.add_space(6.0);
                self.actions(ui);
                ui.add_space(6.0);
                self.vol_table(ui);
                ui.add_space(4.0);
                ui.small(
                    egui::RichText::new(
                        "Ctrl+M = Mount   |   Ctrl+D = Dismount   |   Esc = Close wizard",
                    )
                    .italics()
                    .color(egui::Color32::GRAY),
                );
            });
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            self.status_bar(ui);
        });

        if self.wizard {
            egui::Window::new("Soteria Volume Creation Wizard")
                .collapsible(false)
                .resizable(false)
                .default_size(egui::vec2(620.0, 460.0))
                .show(ctx, |ui| self.wizard_ui(ui));
        }

        let inp = ctx.input(|i| i.clone());
        if inp.key_pressed(egui::Key::M)
            && inp.modifiers.ctrl
            && !self.busy
            && !self.vol_path.as_os_str().is_empty()
            && !self.password.is_empty()
        {
            self.do_mount();
        }
        if inp.key_pressed(egui::Key::D)
            && inp.modifiers.ctrl
            && !self.busy
            && self.volumes.iter().any(|v| v.mounted)
        {
            self.do_dismount();
        }
        if inp.key_pressed(egui::Key::Escape) && self.wizard {
            self.wizard = false;
            self.w_step = 0;
            self.w_err.clear();
        }
    }
}

impl App {
    fn menu_bar(&mut self, ui: &mut egui::Ui) {
        egui::Frame::none()
            .fill(egui::Color32::from_rgb(236, 233, 216))
            .stroke(egui::Stroke::new(
                1.0,
                egui::Color32::from_rgb(160, 160, 160),
            ))
            .inner_margin(2.0)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.menu_button("File", |ui| {
                        if ui.button("Create Volume File...").clicked() {
                            self.wizard = true;
                            self.w_step = 0;
                            self.w_err.clear();
                            ui.close_menu();
                        }
                        ui.separator();
                        if ui.button("Exit").clicked() {
                            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                            ui.close_menu();
                        }
                    });
                    ui.menu_button("Volume", |ui| {
                        let can =
                            !self.vol_path.as_os_str().is_empty() && !self.password.is_empty();
                        if ui.add_enabled(can, egui::Button::new("Mount")).clicked() {
                            self.do_mount();
                            ui.close_menu();
                        }
                        let any = self.volumes.iter().any(|v| v.mounted);
                        if ui.add_enabled(any, egui::Button::new("Dismount")).clicked() {
                            self.do_dismount();
                            ui.close_menu();
                        }
                    });
                    ui.menu_button("Tools", |ui| {
                        if ui.button("Verify Volume...").clicked() {
                            let r = core::verify_volume(&default_vault());
                            self.status = if r.ok { "Verified" } else { "Verify failed" }.into();
                            self.detail = r.message;
                            ui.close_menu();
                        }
                    });
                    ui.menu_button("Help", |ui| {
                        if ui.button("About Soteria...").clicked() {
                            ui.close_menu();
                        }
                    });
                });
            });
    }

    fn toolbar(&mut self, ui: &mut egui::Ui) {
        egui::Frame::none()
            .fill(egui::Color32::from_rgb(212, 208, 200))
            .stroke(egui::Stroke::new(
                1.0,
                egui::Color32::from_rgb(130, 130, 130),
            ))
            .inner_margin(8.0)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Volume:").size(12.0).strong());
                    ui.add_sized(
                        egui::vec2(420.0, 22.0),
                        egui::TextEdit::singleline(&mut self.vol_target)
                            .hint_text("C:\\path\\to\\volume.sot"),
                    );
                    if ui.button("Select File...").clicked() {
                        if let Some(p) = rfd::FileDialog::new()
                            .add_filter("Soteria volume", &["sot"])
                            .pick_file()
                        {
                            self.vol_path = p.clone();
                            self.vol_target = p
                                .file_stem()
                                .and_then(|s| s.to_str())
                                .unwrap_or("")
                                .to_string();
                        }
                    }
                });
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Password:").size(12.0).strong());
                    ui.add_sized(
                        egui::vec2(240.0, 22.0),
                        egui::TextEdit::singleline(&mut self.password).password(!self.show_pw),
                    );
                    ui.checkbox(&mut self.show_pw, "Show password");
                    ui.add_space(16.0);
                    ui.small(
                        egui::RichText::new(format!("File: {}", self.vol_path.display()))
                            .color(egui::Color32::GRAY),
                    );
                });
            });
    }

    fn actions(&mut self, ui: &mut egui::Ui) {
        egui::Frame::none()
            .fill(egui::Color32::from_rgb(236, 233, 216))
            .stroke(egui::Stroke::new(
                1.0,
                egui::Color32::from_rgb(180, 180, 180),
            ))
            .inner_margin(4.0)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    let can_m = !self.busy
                        && !self.vol_path.as_os_str().is_empty()
                        && !self.password.is_empty();
                    let has_m = self.volumes.iter().any(|v| v.mounted);

                    if ui.add_enabled(can_m, vc_btn("Mount")).clicked() {
                        self.do_mount();
                    }
                    if ui
                        .add_enabled(has_m && !self.busy, vc_btn("Dismount"))
                        .clicked()
                    {
                        self.do_dismount();
                    }
                    ui.add_space(8.0);
                    if ui
                        .add_enabled(!self.volumes.is_empty(), vc_btn("Auto-Mount Devices"))
                        .clicked()
                    {
                        self.detail =
                            "File-based volumes only. Select a file and click Mount.".into();
                    }
                });
            });
    }

    fn vol_table(&mut self, ui: &mut egui::Ui) {
        egui::Frame::none()
            .fill(egui::Color32::from_rgb(255, 255, 255))
            .stroke(egui::Stroke::new(
                1.0,
                egui::Color32::from_rgb(180, 180, 180),
            ))
            .inner_margin(2.0)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Mounted").size(11.0).strong());
                    ui.add_space(12.0);
                    ui.label(egui::RichText::new("Volume").size(11.0).strong());
                    ui.add_space(220.0);
                    ui.label(egui::RichText::new("Size").size(11.0).strong());
                    ui.add_space(16.0);
                    ui.label(egui::RichText::new("Type").size(11.0).strong());
                    ui.add_space(16.0);
                    ui.label(egui::RichText::new("Status").size(11.0).strong());
                    ui.add_space(16.0);
                    ui.label(egui::RichText::new("Mount Point").size(11.0).strong());
                });
                ui.separator();
                egui::ScrollArea::vertical().max_height(220.0).show_rows(
                    ui,
                    20.0,
                    self.volumes.len(),
                    |ui, range| {
                        for i in range {
                            self.row(ui, i);
                        }
                    },
                );
            });
    }

    fn row(&mut self, ui: &mut egui::Ui, idx: usize) {
        let v = &self.volumes[idx];
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new(if v.mounted { "☑" } else { "☐" })
                    .size(12.0)
                    .color(if v.mounted {
                        egui::Color32::GREEN
                    } else {
                        egui::Color32::GRAY
                    }),
            );
            ui.label(egui::RichText::new(&v.name).size(12.0).strong());
            ui.add_space(220.0);
            ui.small(&v.size_str);
            ui.add_space(12.0);
            ui.small(&v.algo);
            ui.add_space(12.0);
            ui.small(&v.status);
            ui.add_space(12.0);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.small(v.mount_point.as_deref().unwrap_or("—"));
            });
        });
        if idx < self.volumes.len() - 1 {
            ui.separator();
        }
    }

    fn status_bar(&mut self, ui: &mut egui::Ui) {
        egui::Frame::none()
            .fill(egui::Color32::from_rgb(236, 233, 216))
            .stroke(egui::Stroke::new(
                1.0,
                egui::Color32::from_rgb(180, 180, 180),
            ))
            .inner_margin(4.0)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    let c = if self.status.contains("fail") {
                        egui::Color32::RED
                    } else if self.status == "Mounted" {
                        egui::Color32::GREEN
                    } else {
                        egui::Color32::DARK_GRAY
                    };
                    ui.colored_label(c, "●");
                    ui.small(self.status.clone());
                    ui.add_space(12.0);
                    ui.small(self.detail.clone());
                });
            });
    }

    fn welcome(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("menu").show(ctx, |ui| {
            self.menu_bar(ui);
        });
        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(egui::Color32::from_rgb(240, 240, 240)))
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(60.0);
                    ui.label(egui::RichText::new("Soteria Aegis").size(28.0).strong());
                    ui.add_space(6.0);
                    ui.label(
                        egui::RichText::new("Hardware-rooted encrypted storage")
                            .size(12.0)
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
                            ui.strong("No encrypted volumes were found.");
                            ui.add_space(8.0);
                            ui.label("Get started by creating a new volume:");
                            ui.horizontal(|ui| {
                                ui.label("1.");
                                ui.label("Choose File → Create Volume File...");
                            });
                            ui.horizontal(|ui| {
                                ui.label("2.");
                                ui.label("Enter a strong password.");
                            });
                            ui.horizontal(|ui| {
                                ui.label("3.");
                                ui.label("Click Mount to open it.");
                            });
                        });
                    ui.add_space(20.0);
                    if ui.button("Create Volume File...").clicked() {
                        self.wizard = true;
                        self.w_step = 0;
                        self.w_err.clear();
                    }
                });
            });
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            self.status_bar(ui);
        });
    }

    fn wizard_ui(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.strong(format!(
                "Soteria Volume Creation Wizard — Step {}",
                self.w_step + 1
            ));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Cancel").clicked() {
                    self.wizard = false;
                    self.w_step = 0;
                    self.w_err.clear();
                }
            });
        });
        ui.separator();
        match self.w_step {
            0 => self.w_location(ui),
            1 => self.w_size(ui),
            2 => self.w_password(ui),
            3 => self.w_format(ui),
            4 => self.w_done(ui),
            _ => {}
        }
    }

    fn w_location(&mut self, ui: &mut egui::Ui) {
        ui.label("Please select where on your disk you want the new volume file to be created.");
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            ui.label("Volume file:");
            ui.add_sized(
                egui::vec2(460.0, 22.0),
                egui::TextEdit::singleline(&mut self.vol_target)
                    .hint_text("C:\\path\\to\\MyVolume.sot"),
            );
            if ui.button("Select File...").clicked() {
                if let Some(p) = rfd::FileDialog::new().save_file() {
                    self.w_path = Some(p.clone());
                    self.vol_target = p.display().to_string();
                    self.vol_path = p;
                }
            }
        });
        ui.add_space(16.0);
        ui.horizontal(|ui| {
            if ui.button("Cancel").clicked() {
                self.wizard = false;
                self.w_step = 0;
                self.w_err.clear();
            }
            ui.add_space(4.0);
            if ui.button("Next >").clicked() {
                if self.w_path.is_none() {
                    self.w_err = "Please choose a file path.".into();
                } else {
                    self.w_step = 1;
                    self.w_err.clear();
                }
            }
        });
        if !self.w_err.is_empty() {
            ui.colored_label(egui::Color32::RED, &self.w_err);
        }
    }

    fn w_size(&mut self, ui: &mut egui::Ui) {
        ui.label("Specify the size of the new volume file.");
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            ui.label("Volume size (MB):");
            ui.add_sized(
                egui::vec2(150.0, 22.0),
                egui::TextEdit::singleline(&mut self.w_size_str).hint_text("1024"),
            );
        });
        ui.add_space(16.0);
        ui.horizontal(|ui| {
            if ui.button("< Back").clicked() {
                self.w_step -= 1;
                self.w_err.clear();
            }
            ui.add_space(4.0);
            if ui.button("Next >").clicked() {
                if self.w_size_str.parse::<u64>().unwrap_or(0) == 0 {
                    self.w_err = "Enter a valid size.".into();
                } else {
                    self.w_step = 2;
                    self.w_err.clear();
                }
            }
        });
        if !self.w_err.is_empty() {
            ui.colored_label(egui::Color32::RED, &self.w_err);
        }
    }

    fn w_password(&mut self, ui: &mut egui::Ui) {
        ui.label("Enter and confirm a password for the volume.");
        ui.add_space(8.0);
        ui.label("Password:");
        ui.add_sized(
            egui::vec2(340.0, 22.0),
            egui::TextEdit::singleline(&mut self.w_pw1).password(true),
        );
        ui.add_space(6.0);
        ui.label("Confirm password:");
        ui.add_sized(
            egui::vec2(340.0, 22.0),
            egui::TextEdit::singleline(&mut self.w_pw2).password(true),
        );
        if !self.w_err.is_empty() {
            ui.colored_label(egui::Color32::RED, &self.w_err);
        }
        ui.add_space(16.0);
        ui.horizontal(|ui| {
            if ui.button("< Back").clicked() {
                self.w_step -= 1;
                self.w_err.clear();
            }
            ui.add_space(4.0);
            if ui.button("Next >").clicked() {
                if self.w_pw1.is_empty() {
                    self.w_err = "Password cannot be empty.".into();
                } else if self.w_pw1 != self.w_pw2 {
                    self.w_err = "Passwords do not match.".into();
                } else {
                    self.w_step = 3;
                    self.w_err.clear();
                }
            }
        });
    }

    fn w_format(&mut self, ui: &mut egui::Ui) {
        ui.label("Ready to create the volume. Click Format to begin.");
        ui.add_space(12.0);
        ui.separator();
        ui.horizontal(|ui| {
            ui.label("Location:");
            ui.label(&self.vol_target);
            ui.label("Size:");
            ui.label(format!("{} MB", self.w_size_mb_u64()));
            ui.label("Algo:");
            ui.label("AES-256-XTS + Argon2id");
        });
        ui.separator();
        if !self.w_err.is_empty() {
            ui.colored_label(egui::Color32::RED, &self.w_err);
        }
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            if ui.button("< Back").clicked() {
                self.w_step -= 1;
                self.w_err.clear();
            }
            ui.add_space(4.0);
            if ui.add_enabled(!self.busy, vc_btn("Format")).clicked() {
                if let Some(path) = self.w_path.clone() {
                    self.busy = true;
                    let r =
                        core::create_volume(&path, &self.w_pw1, self.w_size_mb_u64(), self.w_fast);
                    self.busy = false;
                    if r.ok {
                        self.w_step = 4;
                        self.status = "Created".into();
                        self.detail = r.message;
                        self.first_run = false;
                    } else {
                        self.w_err = r.message;
                    }
                }
            }
        });
    }

    fn w_done(&mut self, ui: &mut egui::Ui) {
        ui.label(
            egui::RichText::new("The volume has been created successfully.")
                .color(egui::Color32::from_rgb(0, 128, 0))
                .strong(),
        );
        ui.add_space(16.0);
        ui.label("Use the main window to mount the volume.");
        ui.add_space(20.0);
        if ui.button("Finish").clicked() {
            if let Some(p) = self.w_path.take() {
                self.vol_target = p.display().to_string();
                self.vol_path = p;
            }
            self.wizard = false;
            self.w_step = 0;
            self.w_err.clear();
            self.reload();
        }
    }
}
