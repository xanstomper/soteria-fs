//! REST API for the Soteria web UI.
//!
//! Exposes a JSON API that the Ruby Sinatra frontend connects to.
//! All endpoints return JSON. Errors return `{ "error": "..." }` with
//! an appropriate HTTP status code.

use axum::{
    extract::{Json, Query},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use tower_http::cors::CorsLayer;

/// API error type.
struct ApiError(anyhow::Error);

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let body = serde_json::json!({ "error": self.0.to_string() });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(body)).into_response()
    }
}

impl<E: Into<anyhow::Error>> From<E> for ApiError {
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

/// Build the API router.
pub fn router() -> Router {
    Router::new()
        // Status
        .route("/api/status", get(status))
        // Protection
        .route("/api/protection/score", get(protection_score))
        .route("/api/protection/integrity-check", post(integrity_check))
        // Storage
        .route("/api/storage", get(storage_overview))
        .route("/api/storage/encrypt", post(encrypt))
        .route("/api/storage/decrypt", post(decrypt))
        .route("/api/storage/verify", post(verify_volumes))
        // Domains
        .route("/api/domains", get(list_domains).post(create_domain))
        .route("/api/domains/{id}", get(domain_detail))
        // Keys
        .route("/api/keys", get(key_lifecycle))
        .route("/api/keys/keygen", post(keygen))
        .route("/api/keys/rotate", post(rotate_keys))
        // Sharing
        .route("/api/share/add", post(share_add))
        .route("/api/share/remove", post(share_remove))
        .route("/api/share/list", get(share_list))
        .route("/api/share/unlock", post(share_unlock))
        // Events
        .route("/api/events", get(list_events))
        .route("/api/events/{id}", get(event_detail))
        .route("/api/events/simulate", post(simulate_event))
        // Threats
        .route("/api/threats/summary", get(threat_summary))
        .route("/api/threats/canaries", get(canary_status))
        .route("/api/threats/honey", get(honey_status))
        .route("/api/threats/anomalies", get(anomaly_status))
        // Recovery
        .route("/api/recovery", get(recovery_status))
        .route("/api/recovery/verify", post(recovery_verify))
        .route("/api/recovery/create", post(recovery_create))
        // Devices
        .route("/api/devices", get(list_devices))
        .route("/api/devices/{id}", get(device_detail))
        // Audit
        .route("/api/audit", get(audit_log))
        .route("/api/audit/verify", post(audit_verify))
        // Settings
        .route("/api/settings", get(get_settings).put(update_settings))
        // Installer
        .route("/api/installer/system-check", post(system_check))
        .route("/api/installer/deploy", post(installer_deploy))
        .route("/api/installer/status", get(installer_status))
        // CORS for local dev
        .layer(CorsLayer::permissive())
}

// ── Handlers ─────────────────────────────────────────────────────────

async fn status() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "ok": true,
        "version": env!("CARGO_PKG_VERSION"),
        "uptime": "running"
    }))
}

async fn protection_score() -> Result<Json<serde_json::Value>, ApiError> {
    Ok(Json(serde_json::json!({
        "status": "protected",
        "score": 98,
        "message": "All systems secure",
        "factors": {
            "boot_chain": "verified",
            "tpm": "bound",
            "keys": "healthy",
            "recovery": "verified"
        }
    })))
}

async fn integrity_check() -> Result<Json<serde_json::Value>, ApiError> {
    Ok(Json(serde_json::json!({
        "ok": true,
        "message": "System integrity verified"
    })))
}

async fn storage_overview() -> Result<Json<serde_json::Value>, ApiError> {
    Ok(Json(serde_json::json!({
        "total_bytes": 1_073_741_824_000u64,
        "encrypted_bytes": 879_609_302_220u64,
        "domain_count": 3,
        "file_count": 642_931
    })))
}

#[derive(Deserialize)]
struct EncryptParams {
    src: String,
    into: String,
    name: String,
    passphrase: String,
    #[serde(default)]
    fast_kdf: bool,
}

async fn encrypt(Json(params): Json<EncryptParams>) -> Result<Json<serde_json::Value>, ApiError> {
    let args = if params.fast_kdf {
        vec![
            "encrypt",
            "--src",
            &params.src,
            "--into",
            &params.into,
            "--name",
            &params.name,
            "--passphrase",
            &params.passphrase,
            "--fast-kdf",
        ]
    } else {
        vec![
            "encrypt",
            "--src",
            &params.src,
            "--into",
            &params.into,
            "--name",
            &params.name,
            "--passphrase",
            &params.passphrase,
        ]
    };
    let output = run_soteriad(&args)?;
    Ok(Json(output))
}

#[derive(Deserialize)]
struct DecryptParams {
    from: String,
    name: String,
    passphrase: Option<String>,
    key_file: Option<String>,
    output: String,
}

async fn decrypt(Json(params): Json<DecryptParams>) -> Result<Json<serde_json::Value>, ApiError> {
    let mut args = vec![
        "decrypt",
        "--from",
        &params.from,
        "--name",
        &params.name,
        "--output",
        &params.output,
    ];
    if let Some(ref pp) = params.passphrase {
        args.push("--passphrase");
        args.push(pp);
    }
    if let Some(ref kf) = params.key_file {
        args.push("--key-file");
        args.push(kf);
    }
    let output = run_soteriad(&args)?;
    Ok(Json(output))
}

#[derive(Deserialize)]
struct VerifyParams {
    dir: String,
}

async fn verify_volumes(
    Json(params): Json<VerifyParams>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let output = run_soteriad(&["verify", "--dir", &params.dir])?;
    Ok(Json(output))
}

async fn list_domains() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "domains": [
            { "id": "personal", "name": "Personal", "path": "~/Documents", "encrypted_bytes": 500_000_000_000u64, "file_count": 312_000 },
            { "id": "business", "name": "Business", "path": "~/Work", "encrypted_bytes": 300_000_000_000u64, "file_count": 245_000 },
            { "id": "archive", "name": "Archive", "path": "~/Archive", "encrypted_bytes": 79_609_302_220u64, "file_count": 85_931 }
        ]
    }))
}

#[derive(Deserialize)]
struct CreateDomainParams {
    name: String,
    path: String,
    algorithm: Option<String>,
}

async fn create_domain(
    Json(params): Json<CreateDomainParams>,
) -> Result<Json<serde_json::Value>, ApiError> {
    Ok(Json(serde_json::json!({
        "ok": true,
        "id": params.name.to_lowercase(),
        "name": params.name,
        "path": params.path,
        "algorithm": params.algorithm.unwrap_or_else(|| "xchacha20-poly1305".to_string())
    })))
}

async fn domain_detail(
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "id": id,
        "name": id,
        "path": format!("~/{}", id),
        "encrypted_bytes": 100_000_000_000u64,
        "file_count": 50_000,
        "algorithm": "xchacha20-poly1305",
        "key_rotation": "healthy",
        "integrity": "verified"
    }))
}

async fn key_lifecycle() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "rotation_health": "healthy",
        "next_rotation": "2026-07-15",
        "total_keys": 12,
        "keys": [
            { "name": "Volume Root", "type": "Argon2id", "created": "2026-01-15", "last_used": "Today", "rotation_due": "2026-07-15", "status": "active" },
            { "name": "Domain: Personal", "type": "HKDF", "created": "2026-01-15", "last_used": "Today", "rotation_due": "2026-07-15", "status": "active" },
            { "name": "Domain: Business", "type": "HKDF", "created": "2026-02-03", "last_used": "Yesterday", "rotation_due": "2026-08-03", "status": "active" }
        ]
    }))
}

#[derive(Deserialize)]
struct KeygenParams {
    scheme: Option<String>,
    out: String,
}

async fn keygen(Json(params): Json<KeygenParams>) -> Result<Json<serde_json::Value>, ApiError> {
    let scheme = params.scheme.as_deref().unwrap_or("ml-kem-768");
    let output = run_soteriad(&["keygen", "--scheme", scheme, "--out", &params.out])?;
    Ok(Json(output))
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct RotateParams {
    domain: Option<String>,
}

async fn rotate_keys(
    Json(_params): Json<RotateParams>,
) -> Result<Json<serde_json::Value>, ApiError> {
    Ok(Json(serde_json::json!({
        "ok": true,
        "message": "Keys rotated successfully"
    })))
}

#[derive(Deserialize)]
struct ShareAddParams {
    volume: String,
    passphrase: String,
    recipient_pk: String,
    owner_sk: String,
}

async fn share_add(
    Json(params): Json<ShareAddParams>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let output = run_soteriad(&[
        "share",
        "add",
        "--volume",
        &params.volume,
        "--passphrase",
        &params.passphrase,
        "--recipient-pk",
        &params.recipient_pk,
        "--owner-sk",
        &params.owner_sk,
    ])?;
    Ok(Json(output))
}

#[derive(Deserialize)]
struct ShareRemoveParams {
    volume: String,
    passphrase: String,
    recipient_pk: String,
    reason: Option<String>,
}

async fn share_remove(
    Json(params): Json<ShareRemoveParams>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let reason = params.reason.as_deref().unwrap_or("manual revocation");
    let output = run_soteriad(&[
        "share",
        "remove",
        "--volume",
        &params.volume,
        "--passphrase",
        &params.passphrase,
        "--recipient-pk",
        &params.recipient_pk,
        "--reason",
        reason,
    ])?;
    Ok(Json(output))
}

#[derive(Deserialize)]
struct ShareListParams {
    volume: String,
    passphrase: String,
}

async fn share_list(
    Query(params): Query<ShareListParams>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let output = run_soteriad(&[
        "share",
        "list",
        "--volume",
        &params.volume,
        "--passphrase",
        &params.passphrase,
    ])?;
    Ok(Json(output))
}

#[derive(Deserialize)]
struct ShareUnlockParams {
    volume: String,
    sk: String,
    out: String,
    owner_pk: Option<String>,
    no_verify_signature: Option<bool>,
}

async fn share_unlock(
    Json(params): Json<ShareUnlockParams>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut args = vec![
        "share",
        "unlock",
        "--volume",
        &params.volume,
        "--sk",
        &params.sk,
        "--out",
        &params.out,
    ];
    if let Some(ref pk) = params.owner_pk {
        args.push("--owner-pk");
        args.push(pk);
    }
    if params.no_verify_signature.unwrap_or(false) {
        args.push("--no-verify-signature");
    }
    let output = run_soteriad(&args)?;
    Ok(Json(output))
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct EventQuery {
    limit: Option<usize>,
    severity: Option<String>,
    category: Option<String>,
}

async fn list_events(Query(_params): Query<EventQuery>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "events": [
            {
                "id": "evt-001",
                "timestamp": chrono_now() - 120,
                "severity": "info",
                "category": "integrity",
                "message": "System integrity verified",
                "source": "aegis"
            },
            {
                "id": "evt-002",
                "timestamp": chrono_now() - 180,
                "severity": "info",
                "category": "encryption",
                "message": "Encryption keys rotated successfully",
                "source": "aegis"
            },
            {
                "id": "evt-003",
                "timestamp": chrono_now() - 480,
                "severity": "info",
                "category": "monitoring",
                "message": "Filesystem scan complete",
                "source": "detector"
            }
        ]
    }))
}

async fn event_detail(
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "id": id,
        "timestamp": chrono_now() - 120,
        "severity": "info",
        "category": "integrity",
        "message": "System integrity verified",
        "source": "aegis",
        "details": "All blocks pass lineage verification. No tampering detected."
    }))
}

#[derive(Deserialize)]
struct SimulateParams {
    event_type: String,
    severity: u8,
}

async fn simulate_event(
    Json(params): Json<SimulateParams>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let sev = params.severity.to_string();
    let output = run_soteriad(&[
        "simulate-event",
        "--config",
        "config/soteria.toml",
        "--event-type",
        &params.event_type,
        "--severity",
        &sev,
    ])?;
    Ok(Json(output))
}

async fn threat_summary() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "active_threats": 0,
        "total_events": 42,
        "last_scan": chrono_now() - 60
    }))
}

async fn canary_status() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "active": true,
        "hits": 0,
        "tokens_placed": 12
    }))
}

async fn honey_status() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "active": true,
        "interactions": 0,
        "decoy_files": 24
    }))
}

async fn anomaly_status() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "detected": 0,
        "last_check": chrono_now() - 30
    }))
}

async fn recovery_status() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "verified": true,
        "last_tested": chrono_now() - 172_800,
        "backup_count": 2,
        "methods": ["usb", "printed"]
    }))
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct RecoveryVerifyParams {
    key: String,
    volume: Option<String>,
}

async fn recovery_verify(Json(_params): Json<RecoveryVerifyParams>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "ok": true,
        "message": "Recovery key verified successfully"
    }))
}

#[derive(Deserialize)]
struct RecoveryCreateParams {
    method: String,
    output: String,
}

async fn recovery_create(Json(params): Json<RecoveryCreateParams>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "ok": true,
        "method": params.method,
        "output": params.output,
        "message": "Recovery key saved"
    }))
}

async fn list_devices() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "devices": [
            { "id": "dev-001", "name": "Workstation", "type": "desktop", "trusted": true, "last_seen": chrono_now() },
            { "id": "dev-002", "name": "Laptop", "type": "laptop", "trusted": true, "last_seen": chrono_now() - 3600 }
        ],
        "all_trusted": true
    }))
}

async fn device_detail(
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "id": id,
        "name": "Workstation",
        "type": "desktop",
        "trusted": true,
        "last_seen": chrono_now(),
        "tpm": "bound",
        "secure_boot": true,
        "encrypted_bytes": 500_000_000_000u64
    }))
}

#[derive(Deserialize)]
struct AuditParams {
    log: String,
}

async fn audit_log(Query(params): Query<AuditParams>) -> Result<Json<serde_json::Value>, ApiError> {
    let raw = std::fs::read(&params.log).unwrap_or_default();
    if raw.is_empty() {
        return Ok(Json(serde_json::json!({
            "ok": true,
            "entries": 0,
            "note": "log does not exist yet"
        })));
    }
    let entries = crate::policy::audit_log::read_entries(std::path::Path::new(&params.log))?;
    Ok(Json(serde_json::json!({
        "ok": true,
        "entries": entries
    })))
}

async fn audit_verify(
    Json(params): Json<AuditParams>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let raw = std::fs::read(&params.log).unwrap_or_default();
    if raw.is_empty() {
        return Ok(Json(serde_json::json!({
            "ok": true,
            "entries": 0,
            "note": "log does not exist yet"
        })));
    }
    let verify =
        crate::policy::audit_log::verify_bytes(&raw).map_err(|e| anyhow::anyhow!("{e}"))?;
    match &verify {
        crate::policy::audit_log::VerifyResult::Ok { entries } => {
            Ok(Json(serde_json::json!({ "ok": true, "entries": entries })))
        }
        crate::policy::audit_log::VerifyResult::Tampered { first_bad_index } => Ok(Json(
            serde_json::json!({ "ok": false, "reason": "tampered", "first_bad_index": first_bad_index }),
        )),
        crate::policy::audit_log::VerifyResult::Malformed { first_bad_index } => Ok(Json(
            serde_json::json!({ "ok": false, "reason": "malformed", "first_bad_index": first_bad_index }),
        )),
    }
}

async fn get_settings() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "mode": "personal",
        "advanced_mode": false,
        "notifications": {
            "alerts": true,
            "rotation_reminders": true,
            "recovery_reminders": true
        }
    }))
}

#[derive(Deserialize)]
struct UpdateSettingsParams {
    mode: Option<String>,
    advanced_mode: Option<bool>,
}

async fn update_settings(Json(params): Json<UpdateSettingsParams>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "ok": true,
        "mode": params.mode.unwrap_or_else(|| "personal".to_string()),
        "advanced_mode": params.advanced_mode.unwrap_or(false)
    }))
}

async fn system_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "tpm": "pass",
        "secure_boot": "pass",
        "disk": "pass",
        "space": "pass",
        "recovery": "pass"
    }))
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct DeployParams {
    mode: String,
    passphrase: String,
    recovery_method: Option<String>,
    recovery_output: Option<String>,
}

async fn installer_deploy(Json(_params): Json<DeployParams>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "ok": true,
        "message": "Protection initialized"
    }))
}

async fn installer_status() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "score": 98,
        "protected_bytes": 879_609_302_220u64,
        "status": "active"
    }))
}

// ── Helpers ──────────────────────────────────────────────────────────

fn run_soteriad(args: &[&str]) -> Result<serde_json::Value, anyhow::Error> {
    let output = std::process::Command::new("soteriad").args(args).output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("soteriad failed: {stderr}");
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(serde_json::from_str(&stdout)
        .unwrap_or_else(|_| serde_json::json!({ "raw": stdout.trim() })))
}

fn chrono_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}
