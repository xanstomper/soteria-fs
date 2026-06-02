import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import {
  Shield,
  ShieldCheck,
  HardDrive,
  Key,
  LifeBuoy,
  Activity,
  CheckCircle,
  AlertTriangle,
  Clock,
} from "lucide-react";
import {
  getProtectionStatus,
  getStorageOverview,
  getKeyLifecycle,
  getRecoveryStatus,
  getEvents,
  type ProtectionStatus,
  type StorageOverview,
  type KeyLifecycle,
  type RecoveryStatus,
  type EventInfo,
} from "../lib/commands";

function formatBytes(bytes: number): string {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let val = bytes;
  for (const unit of units) {
    if (val < 1024) return `${val.toFixed(1)} ${unit}`;
    val /= 1024;
  }
  return `${val.toFixed(1)} PB`;
}

function relativeTime(unixSec: number): string {
  const diff = Math.floor(Date.now() / 1000) - unixSec;
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export default function Dashboard() {
  const [protection, setProtection] = useState<ProtectionStatus | null>(null);
  const [storage, setStorage] = useState<StorageOverview | null>(null);
  const [keys, setKeys] = useState<KeyLifecycle | null>(null);
  const [recovery, setRecovery] = useState<RecoveryStatus | null>(null);
  const [events, setEvents] = useState<EventInfo[]>([]);

  useEffect(() => {
    Promise.all([
      getProtectionStatus(),
      getStorageOverview(),
      getKeyLifecycle(),
      getRecoveryStatus(),
      getEvents(),
    ]).then(([p, s, k, r, e]) => {
      setProtection(p);
      setStorage(s);
      setKeys(k);
      setRecovery(r);
      setEvents(e);
    });
  }, []);

  const scoreColor =
    (protection?.score ?? 0) >= 80
      ? "text-soteria-green"
      : (protection?.score ?? 0) >= 50
      ? "text-soteria-amber"
      : "text-soteria-red";

  const storagePct = storage
    ? Math.round((storage.encrypted_bytes / storage.total_bytes) * 100)
    : 0;

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Protection Status Hero */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <div
              className={`w-3 h-3 rounded-full animate-pulse-glow ${
                (protection?.score ?? 0) >= 80
                  ? "bg-soteria-green"
                  : "bg-soteria-amber"
              }`}
            />
            <span className="text-lg font-semibold">
              {protection?.message ?? "Loading..."}
            </span>
          </div>
          <span className="badge-green">Protected</span>
        </div>

        <div className="flex items-center gap-10">
          {/* Score ring */}
          <div className="relative w-24 h-24">
            <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
              <circle
                cx="50"
                cy="50"
                r="42"
                fill="none"
                stroke="currentColor"
                strokeWidth="8"
                className="text-soteria-elevated"
              />
              <circle
                cx="50"
                cy="50"
                r="42"
                fill="none"
                stroke="currentColor"
                strokeWidth="8"
                strokeLinecap="round"
                className={scoreColor}
                strokeDasharray={`${2 * Math.PI * 42}`}
                strokeDashoffset={`${
                  2 * Math.PI * 42 * (1 - (protection?.score ?? 0) / 100)
                }`}
              />
            </svg>
            <div
              className={`absolute inset-0 flex items-center justify-center text-2xl font-bold ${scoreColor}`}
            >
              {protection?.score ?? 0}
            </div>
          </div>

          {/* Factor indicators */}
          <div className="grid grid-cols-4 gap-6">
            {[
              { label: "Boot Chain", value: protection?.boot_chain ?? "—" },
              { label: "TPM", value: protection?.tpm ?? "—" },
              { label: "Keys", value: protection?.keys ?? "—" },
              { label: "Recovery", value: protection?.recovery ?? "—" },
            ].map((f) => (
              <div key={f.label} className="text-center">
                <div className="text-xs text-soteria-dim mb-1">{f.label}</div>
                <div className="text-sm font-medium text-soteria-green">
                  {f.value}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-4 gap-4">
        <div className="card">
          <div className="text-xs text-soteria-dim uppercase tracking-wider mb-2">
            Encrypted Storage
          </div>
          <div className="text-2xl font-bold mb-1">
            {storage ? formatBytes(storage.encrypted_bytes) : "—"}
          </div>
          <div className="text-xs text-soteria-muted mb-3">
            of {storage ? formatBytes(storage.total_bytes) : "—"} total
          </div>
          <div className="h-2 bg-soteria-elevated rounded-full overflow-hidden">
            <motion.div
              className="h-full bg-soteria-green rounded-full"
              initial={{ width: 0 }}
              animate={{ width: `${storagePct}%` }}
              transition={{ duration: 1, ease: "easeOut" }}
            />
          </div>
        </div>

        <div className="card">
          <div className="text-xs text-soteria-dim uppercase tracking-wider mb-2">
            Security Domains
          </div>
          <div className="text-2xl font-bold">
            {storage?.domain_count ?? 0}
          </div>
          <div className="text-xs text-soteria-muted mt-1">Active domains</div>
        </div>

        <div className="card">
          <div className="text-xs text-soteria-dim uppercase tracking-wider mb-2">
            Key Rotation
          </div>
          <div className="text-lg font-semibold text-soteria-green">
            {keys?.rotation_health ?? "—"}
          </div>
          <div className="text-xs text-soteria-muted mt-1">
            Next: {keys?.next_rotation ?? "—"}
          </div>
        </div>

        <div className="card">
          <div className="text-xs text-soteria-dim uppercase tracking-wider mb-2">
            Recovery
          </div>
          <div
            className={`text-lg font-semibold ${
              recovery?.verified ? "text-soteria-green" : "text-soteria-amber"
            }`}
          >
            {recovery?.verified ? "Verified" : "Not Tested"}
          </div>
          <div className="text-xs text-soteria-muted mt-1">
            {recovery?.last_tested ?? "—"}
          </div>
        </div>
      </div>

      {/* Bottom row */}
      <div className="grid grid-cols-2 gap-6">
        {/* Recent Activity */}
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-semibold">Recent Activity</h3>
            <span className="text-xs text-soteria-dim">
              {events.length} events
            </span>
          </div>
          <div className="space-y-2">
            {events.length === 0 ? (
              <div className="text-center py-8 text-soteria-dim">
                <CheckCircle className="w-8 h-8 mx-auto mb-2 text-soteria-green" />
                <div className="text-sm">All clear</div>
              </div>
            ) : (
              events.slice(0, 5).map((e) => (
                <div
                  key={e.id}
                  className="flex items-start gap-3 p-2 rounded-lg hover:bg-soteria-elevated/50"
                >
                  <div className="mt-0.5">
                    {e.severity === "Critical" || e.severity === "Warning" ? (
                      <AlertTriangle className="w-4 h-4 text-soteria-amber" />
                    ) : (
                      <Activity className="w-4 h-4 text-soteria-dim" />
                    )}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="text-sm truncate">{e.message}</div>
                    <div className="text-xs text-soteria-dim">
                      {relativeTime(e.timestamp)}
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Recovery Center */}
        <div className="card">
          <h3 className="font-semibold mb-4">Recovery Center</h3>
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <LifeBuoy className="w-4 h-4 text-soteria-dim" />
                <span className="text-sm">Recovery Key</span>
              </div>
              <span
                className={recovery?.verified ? "badge-green" : "badge-amber"}
              >
                {recovery?.verified ? "Verified" : "Not tested"}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Clock className="w-4 h-4 text-soteria-dim" />
                <span className="text-sm">Last tested</span>
              </div>
              <span className="text-sm text-soteria-muted">
                {recovery?.last_tested ?? "Never"}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Shield className="w-4 h-4 text-soteria-dim" />
                <span className="text-sm">Backup copies</span>
              </div>
              <span className="text-sm text-soteria-muted">
                {recovery?.backup_count ?? 0}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
