//! Soteria Aegis — Native Desktop Application
//!
//! Pure Rust, egui rendering, no browser, no web view, no localhost.
//! Old-school security tool UI with a proper setup wizard.

mod app;
mod setup;
mod dashboard;
mod style;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 750.0])
            .with_min_inner_size([900.0, 600.0])
            .with_title("Soteria Aegis"),
        ..Default::default()
    };

    eframe::run_native(
        "Soteria Aegis",
        options,
        Box::new(|cc| {
            style::setup(&cc.egui_ctx);
            Ok(Box::new(app::SoteriaApp::new()))
        }),
    )
}
