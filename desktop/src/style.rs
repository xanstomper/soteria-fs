//! Visual style — dark theme, old-school security tool look.

use egui::{Color32, Context, FontFamily, FontId, Rounding, Stroke, Vec2, Visuals};

pub const BG: Color32 = Color32::from_rgb(10, 10, 15);
pub const SURFACE: Color32 = Color32::from_rgb(18, 18, 26);
pub const ELEVATED: Color32 = Color32::from_rgb(26, 26, 36);
pub const BORDER: Color32 = Color32::from_rgb(42, 42, 58);
pub const TEXT: Color32 = Color32::from_rgb(232, 232, 237);
pub const MUTED: Color32 = Color32::from_rgb(139, 139, 158);
pub const DIM: Color32 = Color32::from_rgb(90, 90, 110);
pub const GREEN: Color32 = Color32::from_rgb(52, 211, 153);
pub const AMBER: Color32 = Color32::from_rgb(251, 191, 36);
pub const RED: Color32 = Color32::from_rgb(248, 113, 113);
pub const BLUE: Color32 = Color32::from_rgb(96, 165, 250);
pub const ACCENT: Color32 = Color32::from_rgb(99, 102, 241);

pub fn setup(ctx: &Context) {
    let mut visuals = Visuals::dark();
    visuals.window_fill = BG;
    visuals.panel_fill = SURFACE;
    visuals.extreme_bg_color = ELEVATED;
    visuals.faint_bg_color = ELEVATED;
    visuals.window_stroke = Stroke::new(1.0, BORDER);
    visuals.widgets.noninteractive.bg_fill = SURFACE;
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, MUTED);
    visuals.widgets.inactive.bg_fill = ELEVATED;
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, MUTED);
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, BORDER);
    visuals.widgets.hovered.bg_fill = ACCENT.linear_multiply(0.15);
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0, TEXT);
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, ACCENT);
    visuals.widgets.active.bg_fill = ACCENT.linear_multiply(0.25);
    visuals.widgets.active.fg_stroke = Stroke::new(1.0, TEXT);
    visuals.selection.bg_fill = ACCENT.linear_multiply(0.3);
    visuals.selection.stroke = Stroke::new(1.0, ACCENT);
    visuals.window_rounding = Rounding::same(8.0);
    visuals.window_shadow = egui::epaint::Shadow::NONE;
    ctx.set_visuals(visuals);

    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = Vec2::new(8.0, 6.0);
    style.spacing.button_padding = Vec2::new(12.0, 6.0);
    style.spacing.window_margin = egui::Margin::same(16);
    ctx.set_style(style);
}

pub fn heading_font() -> FontId {
    FontId::new(24.0, FontFamily::Proportional)
}

pub fn subheading_font() -> FontId {
    FontId::new(16.0, FontFamily::Proportional)
}

pub fn body_font() -> FontId {
    FontId::new(13.0, FontFamily::Proportional)
}

pub fn small_font() -> FontId {
    FontId::new(11.0, FontFamily::Proportional)
}

pub fn mono_font() -> FontId {
    FontId::new(12.0, FontFamily::Monospace)
}
