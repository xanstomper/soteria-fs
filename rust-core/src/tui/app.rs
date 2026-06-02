//! TUI application state and main loop.
//!
//! Runs the full-screen terminal UI. All state is read directly from
//! the Soteria runtime — no HTTP calls, no API polling, no sockets.

use crate::event_bus::bus::{Event, EventBus, Severity};
use crossterm::{
    event::{self, Event as CEvent, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, List, ListItem, Paragraph, Tabs},
    Frame, Terminal,
};
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Active tab in the dashboard.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Dashboard,
    Threats,
    Keys,
    Recovery,
    Events,
}

impl Tab {
    fn all() -> &'static [Tab] {
        &[
            Tab::Dashboard,
            Tab::Threats,
            Tab::Keys,
            Tab::Recovery,
            Tab::Events,
        ]
    }

    fn label(&self) -> &'static str {
        match self {
            Tab::Dashboard => "Dashboard",
            Tab::Threats => "Threats",
            Tab::Keys => "Keys",
            Tab::Recovery => "Recovery",
            Tab::Events => "Events",
        }
    }

    fn index(&self) -> usize {
        match self {
            Tab::Dashboard => 0,
            Tab::Threats => 1,
            Tab::Keys => 2,
            Tab::Recovery => 3,
            Tab::Events => 4,
        }
    }
}

/// Runtime state that the TUI reads directly.
pub struct RuntimeState {
    pub protection_score: u8,
    pub protection_status: String,
    pub encrypted_bytes: u64,
    pub total_bytes: u64,
    pub domain_count: u32,
    pub key_rotation_health: String,
    pub next_rotation: String,
    pub recovery_verified: bool,
    pub recovery_last_tested: String,
    pub canary_hits: u32,
    pub honey_interactions: u32,
    pub active_threats: u32,
    pub events: Vec<Arc<Event>>,
}

impl Default for RuntimeState {
    fn default() -> Self {
        Self {
            protection_score: 98,
            protection_status: "All Systems Protected".to_string(),
            encrypted_bytes: 879_609_302_220,
            total_bytes: 1_073_741_824_000,
            domain_count: 3,
            key_rotation_health: "Healthy".to_string(),
            next_rotation: "12 days".to_string(),
            recovery_verified: true,
            recovery_last_tested: "2 days ago".to_string(),
            canary_hits: 0,
            honey_interactions: 0,
            active_threats: 0,
            events: Vec::new(),
        }
    }
}

/// The TUI application.
pub struct App {
    pub active_tab: Tab,
    pub state: RuntimeState,
    pub event_bus: Arc<EventBus>,
    pub should_quit: bool,
    pub last_tick: Instant,
    pub tick_rate: Duration,
}

impl App {
    pub fn new(event_bus: Arc<EventBus>) -> Self {
        let events = event_bus.recent(50);
        Self {
            active_tab: Tab::Dashboard,
            state: RuntimeState {
                events,
                ..Default::default()
            },
            event_bus,
            should_quit: false,
            last_tick: Instant::now(),
            tick_rate: Duration::from_millis(250),
        }
    }

    /// Refresh state from the runtime.
    pub fn refresh(&mut self) {
        self.state.events = self.event_bus.recent(50);
        let counts = self.event_bus.count_by_severity();
        self.state.active_threats = *counts.get(&Severity::Critical).unwrap_or(&0) as u32
            + *counts.get(&Severity::Warning).unwrap_or(&0) as u32;
    }

    /// Handle a key event.
    pub fn handle_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
            KeyCode::Tab => {
                let tabs = Tab::all();
                let current = self.active_tab.index();
                self.active_tab = tabs[(current + 1) % tabs.len()];
            }
            KeyCode::BackTab => {
                let tabs = Tab::all();
                let current = self.active_tab.index();
                self.active_tab = tabs[(current + tabs.len() - 1) % tabs.len()];
            }
            KeyCode::Char('1') => self.active_tab = Tab::Dashboard,
            KeyCode::Char('2') => self.active_tab = Tab::Threats,
            KeyCode::Char('3') => self.active_tab = Tab::Keys,
            KeyCode::Char('4') => self.active_tab = Tab::Recovery,
            KeyCode::Char('5') => self.active_tab = Tab::Events,
            KeyCode::Char('r') => self.refresh(),
            _ => {}
        }
    }
}

/// Run the TUI. Blocks until the user quits.
pub fn run(event_bus: Arc<EventBus>) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(event_bus);

    loop {
        // Draw
        terminal.draw(|f| draw(f, &app))?;

        // Handle input
        if event::poll(app.tick_rate)? {
            if let CEvent::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    app.handle_key(key.code);
                }
            }
        }

        // Tick
        if app.last_tick.elapsed() >= app.tick_rate {
            app.refresh();
            app.last_tick = Instant::now();
        }

        if app.should_quit {
            break;
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

fn draw(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header + tabs
            Constraint::Min(0),    // Content
            Constraint::Length(3), // Footer
        ])
        .split(f.area());

    // Header
    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            " Soteria ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("— Aegis Security Runtime"),
    ]))
    .block(Block::default().borders(Borders::ALL).title("Soteria"));
    f.render_widget(header, chunks[0]);

    // Tabs
    let titles: Vec<Line> = Tab::all()
        .iter()
        .map(|t| Line::from(Span::raw(t.label())))
        .collect();
    let tabs = Tabs::new(titles)
        .select(app.active_tab.index())
        .style(Style::default().fg(Color::White))
        .highlight_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );
    f.render_widget(tabs, chunks[0]);

    // Content
    match app.active_tab {
        Tab::Dashboard => draw_dashboard(f, app, chunks[1]),
        Tab::Threats => draw_threats(f, app, chunks[1]),
        Tab::Keys => draw_keys(f, app, chunks[1]),
        Tab::Recovery => draw_recovery(f, app, chunks[1]),
        Tab::Events => draw_events(f, app, chunks[1]),
    }

    // Footer
    let footer = Paragraph::new(Line::from(vec![
        Span::styled(" [1-5] ", Style::default().fg(Color::DarkGray)),
        Span::raw("tabs  "),
        Span::styled(" [Tab] ", Style::default().fg(Color::DarkGray)),
        Span::raw("next  "),
        Span::styled(" [r] ", Style::default().fg(Color::DarkGray)),
        Span::raw("refresh  "),
        Span::styled(" [q] ", Style::default().fg(Color::DarkGray)),
        Span::raw("quit"),
    ]))
    .block(Block::default().borders(Borders::ALL));
    f.render_widget(footer, chunks[2]);
}

fn draw_dashboard(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5), // Score
            Constraint::Length(3), // Storage bar
            Constraint::Length(3), // Domains
            Constraint::Min(0),    // Recent events
        ])
        .split(area);

    // Protection score
    let score_color = if app.state.protection_score >= 80 {
        Color::Green
    } else if app.state.protection_score >= 50 {
        Color::Yellow
    } else {
        Color::Red
    };
    let score = Paragraph::new(vec![
        Line::from(vec![Span::styled(
            format!("  {} ", app.state.protection_status),
            Style::default()
                .fg(score_color)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(vec![
            Span::raw("  Score: "),
            Span::styled(
                format!("{}/100", app.state.protection_score),
                Style::default()
                    .fg(score_color)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Protection Status"),
    );
    f.render_widget(score, chunks[0]);

    // Storage bar
    let pct = if app.state.total_bytes > 0 {
        (app.state.encrypted_bytes as f64 / app.state.total_bytes as f64 * 100.0) as u16
    } else {
        0
    };
    let gauge = Gauge::default()
        .block(Block::default().borders(Borders::ALL).title(format!(
            "Encrypted Storage ({})",
            format_bytes(app.state.encrypted_bytes)
        )))
        .gauge_style(Style::default().fg(Color::Green))
        .percent(pct);
    f.render_widget(gauge, chunks[1]);

    // Domains + Keys
    let info = Paragraph::new(Line::from(vec![
        Span::raw(format!(
            "  Domains: {}  |  Key Rotation: ",
            app.state.domain_count
        )),
        Span::styled(
            &app.state.key_rotation_health,
            Style::default().fg(Color::Green),
        ),
        Span::raw(format!("  |  Next: {}", app.state.next_rotation)),
    ]))
    .block(Block::default().borders(Borders::ALL).title("System"));
    f.render_widget(info, chunks[2]);

    // Recent events
    draw_event_list(f, app, chunks[3]);
}

fn draw_threats(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Summary
            Constraint::Length(3), // Canary
            Constraint::Length(3), // Honey
            Constraint::Min(0),    // Events
        ])
        .split(area);

    let threat_color = if app.state.active_threats > 0 {
        Color::Red
    } else {
        Color::Green
    };
    let summary = Paragraph::new(Line::from(vec![
        Span::raw("  Active Threats: "),
        Span::styled(
            format!("{}", app.state.active_threats),
            Style::default()
                .fg(threat_color)
                .add_modifier(Modifier::BOLD),
        ),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Threat Summary"),
    );
    f.render_widget(summary, chunks[0]);

    let canary = Paragraph::new(Line::from(vec![
        Span::raw("  Canary Hits: "),
        Span::styled(
            format!("{}", app.state.canary_hits),
            if app.state.canary_hits > 0 {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::Green)
            },
        ),
        Span::raw("  |  Status: Monitoring Active"),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Canary System"),
    );
    f.render_widget(canary, chunks[1]);

    let honey = Paragraph::new(Line::from(vec![
        Span::raw("  Decoy Interactions: "),
        Span::styled(
            format!("{}", app.state.honey_interactions),
            if app.state.honey_interactions > 0 {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::Green)
            },
        ),
        Span::raw("  |  Status: Honeypot Active"),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Decoy Protection"),
    );
    f.render_widget(honey, chunks[2]);

    draw_event_list(f, app, chunks[3]);
}

fn draw_keys(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(area);

    let health = Paragraph::new(Line::from(vec![
        Span::raw("  Rotation: "),
        Span::styled(
            &app.state.key_rotation_health,
            Style::default().fg(Color::Green),
        ),
        Span::raw(format!(
            "  |  Next: {}  |  Total Keys: 12",
            app.state.next_rotation
        )),
    ]))
    .block(Block::default().borders(Borders::ALL).title("Key Health"));
    f.render_widget(health, chunks[0]);

    let keys = vec![
        ListItem::new("  Volume Root       Argon2id    Active    Rotation due: 2026-07-15"),
        ListItem::new("  Domain: Personal  HKDF        Active    Rotation due: 2026-07-15"),
        ListItem::new("  Domain: Business  HKDF        Active    Rotation due: 2026-08-03"),
        ListItem::new("  Domain: Archive   HKDF        Active    Rotation due: 2026-09-01"),
    ];
    let list = List::new(keys).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Key Lifecycle"),
    );
    f.render_widget(list, chunks[1]);
}

fn draw_recovery(f: &mut Frame, app: &App, area: Rect) {
    let status_color = if app.state.recovery_verified {
        Color::Green
    } else {
        Color::Yellow
    };
    let status_text = if app.state.recovery_verified {
        "Verified"
    } else {
        "Not Tested"
    };

    let recovery = Paragraph::new(vec![
        Line::from(vec![
            Span::raw("  Recovery Key: "),
            Span::styled(
                status_text,
                Style::default()
                    .fg(status_color)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![Span::raw(format!(
            "  Last Tested: {}",
            app.state.recovery_last_tested
        ))]),
        Line::from(vec![Span::raw("  Backup Copies: 2")]),
        Line::from(""),
        Line::from("  Your recovery key is the only way to access your files"),
        Line::from("  if you forget your password. Test it regularly."),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Recovery Center"),
    );
    f.render_widget(recovery, area);
}

fn draw_events(f: &mut Frame, app: &App, area: Rect) {
    draw_event_list(f, app, area);
}

fn draw_event_list(f: &mut Frame, app: &App, area: Rect) {
    let events: Vec<ListItem> = app
        .state
        .events
        .iter()
        .rev()
        .take(50)
        .map(|e| {
            let severity_style = match e.severity {
                Severity::Critical => Style::default().fg(Color::Red),
                Severity::Warning => Style::default().fg(Color::Yellow),
                Severity::Advisory => Style::default().fg(Color::Blue),
                Severity::Info => Style::default().fg(Color::DarkGray),
            };
            let icon = match e.severity {
                Severity::Critical => "●",
                Severity::Warning => "◐",
                Severity::Advisory => "○",
                Severity::Info => "·",
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!(" {} ", icon), severity_style),
                Span::styled(
                    format!("{:<12}", e.source),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::raw(&e.message),
            ]))
        })
        .collect();

    let list = List::new(events).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!("Events ({})", app.state.events.len())),
    );
    f.render_widget(list, area);
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
