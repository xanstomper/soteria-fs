import { useEffect, useState } from "react";
import { LifeBuoy, CheckCircle, Clock, Shield, AlertTriangle } from "lucide-react";
import { getRecoveryStatus, type RecoveryStatus } from "../lib/commands";

export default function Recovery() {
  const [status, setStatus] = useState<RecoveryStatus | null>(null);

  useEffect(() => {
    getRecoveryStatus().then(setStatus);
  }, []);

  return (
    <div className="space-y-6 animate-fade-in max-w-2xl">
      {/* Status hero */}
      <div className="card">
        <div className="flex items-center gap-4 mb-6">
          <div
            className={`w-14 h-14 rounded-full flex items-center justify-center ${
              status?.verified
                ? "bg-soteria-green/15"
                : "bg-soteria-amber/15"
            }`}
          >
            <LifeBuoy
              className={`w-7 h-7 ${
                status?.verified ? "text-soteria-green" : "text-soteria-amber"
              }`}
            />
          </div>
          <div>
            <h2 className="text-lg font-semibold">
              {status?.verified
                ? "Recovery Key Verified"
                : "Recovery Key Not Yet Tested"}
            </h2>
            <p className="text-sm text-soteria-muted">
              {status?.verified
                ? `Last tested ${status.last_tested}. Your backup is working.`
                : "Testing verifies your backup works without unlocking your device."}
            </p>
          </div>
        </div>

        <div className="grid grid-cols-3 gap-4 mb-6">
          <div className="text-center p-3 rounded-lg bg-soteria-elevated">
            <div className="text-xs text-soteria-dim mb-1">Status</div>
            <div
              className={`text-lg font-semibold ${
                status?.verified ? "text-soteria-green" : "text-soteria-amber"
              }`}
            >
              {status?.verified ? "Ready" : "Needs testing"}
            </div>
          </div>
          <div className="text-center p-3 rounded-lg bg-soteria-elevated">
            <div className="text-xs text-soteria-dim mb-1">Last Tested</div>
            <div className="text-lg font-semibold">
              {status?.last_tested ?? "Never"}
            </div>
          </div>
          <div className="text-center p-3 rounded-lg bg-soteria-elevated">
            <div className="text-xs text-soteria-dim mb-1">Backup Copies</div>
            <div className="text-lg font-semibold">
              {status?.backup_count ?? 0}
            </div>
          </div>
        </div>

        <button className="btn-primary">
          <CheckCircle className="w-4 h-4" />
          Verify Recovery Key
        </button>
      </div>

      {/* Education */}
      <div className="card">
        <h3 className="font-semibold mb-4">About Your Recovery Key</h3>
        <div className="space-y-4 text-sm text-soteria-muted">
          <div className="flex items-start gap-3">
            <Shield className="w-5 h-5 text-soteria-accent flex-shrink-0 mt-0.5" />
            <div>
              <div className="font-medium text-soteria-text mb-1">
                What is a recovery key?
              </div>
              <p>
                A special code that unlocks your device if you forget your
                password. It is not stored on your device.
              </p>
            </div>
          </div>
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-soteria-amber flex-shrink-0 mt-0.5" />
            <div>
              <div className="font-medium text-soteria-text mb-1">
                Why is it critical?
              </div>
              <p>
                Without your recovery key and password, your files cannot be
                recovered. This is by design — it means no one else can recover
                them either.
              </p>
            </div>
          </div>
          <div className="flex items-start gap-3">
            <CheckCircle className="w-5 h-5 text-soteria-green flex-shrink-0 mt-0.5" />
            <div>
              <div className="font-medium text-soteria-text mb-1">
                How do I test it?
              </div>
              <p>
                Click "Verify Recovery Key" above. Soteria confirms your backup
                works without unlocking your device.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
