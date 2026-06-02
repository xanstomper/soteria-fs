import { useEffect, useState } from "react";
import { Shield, ShieldCheck, Cpu, Lock, Activity } from "lucide-react";
import {
  getProtectionStatus,
  getTpmStatus,
  type ProtectionStatus,
  type TpmStatus,
} from "../lib/commands";

export default function SecurityPanel() {
  const [protection, setProtection] = useState<ProtectionStatus | null>(null);
  const [tpm, setTpm] = useState<TpmStatus | null>(null);

  useEffect(() => {
    Promise.all([getProtectionStatus(), getTpmStatus()]).then(([p, t]) => {
      setProtection(p);
      setTpm(t);
    });
  }, []);

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Trust Chain */}
      <div className="card">
        <h3 className="font-semibold mb-4">Trust Chain</h3>
        <div className="space-y-3">
          {[
            { label: "Secure Boot", status: protection?.boot_chain ?? "—", icon: ShieldCheck },
            { label: "TPM Binding", status: tpm?.provider ?? "—", icon: Cpu },
            { label: "Key Engine", status: protection?.keys ?? "—", icon: Lock },
            { label: "Integrity", status: "Verified", icon: Activity },
          ].map((item) => {
            const Icon = item.icon;
            return (
              <div
                key={item.label}
                className="flex items-center justify-between p-3 rounded-lg bg-soteria-elevated"
              >
                <div className="flex items-center gap-3">
                  <Icon className="w-5 h-5 text-soteria-accent" />
                  <span className="text-sm font-medium">{item.label}</span>
                </div>
                <span className="badge-green">{item.status}</span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Security Domains */}
      <div className="card">
        <h3 className="font-semibold mb-4">Security Domains</h3>
        <div className="space-y-2">
          {[
            { name: "Personal", path: "~/Documents", status: "Protected", size: "500 GB" },
            { name: "Business", path: "~/Work", status: "Protected", size: "300 GB" },
            { name: "Archive", path: "~/Archive", status: "Protected", size: "80 GB" },
          ].map((d) => (
            <div
              key={d.name}
              className="flex items-center justify-between p-3 rounded-lg bg-soteria-elevated"
            >
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 rounded-lg bg-soteria-accent/15 flex items-center justify-center">
                  <Lock className="w-4 h-4 text-soteria-accent" />
                </div>
                <div>
                  <div className="text-sm font-medium">{d.name}</div>
                  <div className="text-xs text-soteria-dim">{d.path}</div>
                </div>
              </div>
              <div className="text-right">
                <span className="badge-green">{d.status}</span>
                <div className="text-xs text-soteria-dim mt-1">{d.size}</div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
