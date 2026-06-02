import { useState } from "react";
import { Shield, Bell, Cpu, Eye } from "lucide-react";

export default function SettingsPage() {
  const [mode, setMode] = useState<"personal" | "professional" | "fortress">(
    "personal"
  );
  const [advanced, setAdvanced] = useState(false);

  const modes = [
    {
      id: "personal" as const,
      name: "Personal",
      desc: "Balanced protection for everyday use.",
      perf: "Negligible",
    },
    {
      id: "professional" as const,
      name: "Professional",
      desc: "Enhanced security for sensitive work.",
      perf: "Minimal",
    },
    {
      id: "fortress" as const,
      name: "Fortress",
      desc: "Maximum protection for high-risk environments.",
      perf: "Slight",
    },
  ];

  return (
    <div className="space-y-6 animate-fade-in max-w-2xl">
      {/* Security Mode */}
      <div className="card">
        <h3 className="font-semibold mb-4">Security Mode</h3>
        <div className="grid grid-cols-3 gap-3">
          {modes.map((m) => (
            <button
              key={m.id}
              onClick={() => setMode(m.id)}
              className={`p-4 rounded-card border text-left transition-all duration-150 ${
                mode === m.id
                  ? "border-soteria-accent bg-soteria-accent/5"
                  : "border-soteria-border hover:border-soteria-accent/30"
              }`}
            >
              <div className="font-medium text-sm mb-1">{m.name}</div>
              <div className="text-xs text-soteria-muted mb-2">{m.desc}</div>
              <div className="text-xs text-soteria-green">
                Performance: {m.perf}
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Notifications */}
      <div className="card">
        <h3 className="font-semibold mb-4">Notifications</h3>
        <div className="space-y-4">
          {[
            {
              label: "Security alerts",
              desc: "Notify when action is required",
              default: true,
            },
            {
              label: "Key rotation reminders",
              desc: "Remind when keys are due for rotation",
              default: true,
            },
            {
              label: "Recovery test reminders",
              desc: "Remind every 30 days to test recovery key",
              default: true,
            },
          ].map((n) => (
            <div key={n.label} className="flex items-center justify-between">
              <div>
                <div className="text-sm font-medium">{n.label}</div>
                <div className="text-xs text-soteria-dim">{n.desc}</div>
              </div>
              <Toggle defaultChecked={n.default} />
            </div>
          ))}
        </div>
      </div>

      {/* Advanced Mode */}
      <div className="card">
        <div className="flex items-center justify-between mb-3">
          <h3 className="font-semibold">Advanced Mode</h3>
          <Toggle checked={advanced} onChange={setAdvanced} />
        </div>
        <p className="text-sm text-soteria-muted">
          Shows technical details like raw audit logs, TPM diagnostics, key
          derivation parameters, and capability token viewers. Intended for
          security professionals.
        </p>
      </div>
    </div>
  );
}

function Toggle({
  defaultChecked,
  checked,
  onChange,
}: {
  defaultChecked?: boolean;
  checked?: boolean;
  onChange?: (v: boolean) => void;
}) {
  const [internal, setInternal] = useState(defaultChecked ?? false);
  const value = checked !== undefined ? checked : internal;

  const toggle = () => {
    const next = !value;
    if (onChange) onChange(next);
    else setInternal(next);
  };

  return (
    <button
      onClick={toggle}
      className={`w-10 h-5 rounded-full transition-colors duration-150 relative ${
        value ? "bg-soteria-accent" : "bg-soteria-elevated"
      }`}
    >
      <div
        className={`absolute top-0.5 w-4 h-4 rounded-full bg-white transition-transform duration-150 ${
          value ? "translate-x-5" : "translate-x-0.5"
        }`}
      />
    </button>
  );
}
