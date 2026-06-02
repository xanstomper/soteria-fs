import { useState } from "react";
import {
  HardDrive,
  Lock,
  Unlock,
  Plus,
  ShieldCheck,
  Search,
} from "lucide-react";
import { encryptFile, decryptFile } from "../lib/commands";

export default function VolumeManager() {
  const [src, setSrc] = useState("");
  const [into, setInto] = useState("");
  const [name, setName] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [result, setResult] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleEncrypt = async () => {
    setLoading(true);
    try {
      const res = await encryptFile({ src, into, name, passphrase });
      setResult(`Encrypted: ${res.path} (${res.algorithm})`);
    } catch (e) {
      setResult(`Error: ${e}`);
    }
    setLoading(false);
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Volume list */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h3 className="font-semibold">Protected Volumes</h3>
          <button className="btn-primary">
            <Plus className="w-4 h-4" />
            New Volume
          </button>
        </div>
        <div className="space-y-2">
          {[
            { name: "Documents", status: "Mounted", size: "500 GB", files: "312,000" },
            { name: "Work", status: "Mounted", size: "300 GB", files: "245,000" },
            { name: "Archive", status: "Unmounted", size: "80 GB", files: "85,931" },
          ].map((v) => (
            <div
              key={v.name}
              className="flex items-center justify-between p-3 rounded-lg bg-soteria-elevated"
            >
              <div className="flex items-center gap-3">
                <HardDrive className="w-5 h-5 text-soteria-accent" />
                <div>
                  <div className="text-sm font-medium">{v.name}</div>
                  <div className="text-xs text-soteria-dim">
                    {v.files} files · {v.size}
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <span
                  className={
                    v.status === "Mounted" ? "badge-green" : "badge-amber"
                  }
                >
                  {v.status}
                </span>
                <button className="btn-ghost text-xs">
                  {v.status === "Mounted" ? (
                    <Lock className="w-3 h-3" />
                  ) : (
                    <Unlock className="w-3 h-3" />
                  )}
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Quick encrypt */}
      <div className="card">
        <h3 className="font-semibold mb-4">Quick Encrypt</h3>
        <div className="grid grid-cols-2 gap-4 mb-4">
          <div>
            <label className="text-xs text-soteria-dim mb-1 block">
              Source file
            </label>
            <input
              className="input"
              placeholder="/path/to/file"
              value={src}
              onChange={(e) => setSrc(e.target.value)}
            />
          </div>
          <div>
            <label className="text-xs text-soteria-dim mb-1 block">
              Destination
            </label>
            <input
              className="input"
              placeholder="/path/to/vault"
              value={into}
              onChange={(e) => setInto(e.target.value)}
            />
          </div>
          <div>
            <label className="text-xs text-soteria-dim mb-1 block">Name</label>
            <input
              className="input"
              placeholder="volume-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>
          <div>
            <label className="text-xs text-soteria-dim mb-1 block">
              Passphrase
            </label>
            <input
              className="input"
              type="password"
              placeholder="••••••••"
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
            />
          </div>
        </div>
        <button
          className="btn-primary"
          onClick={handleEncrypt}
          disabled={loading || !src || !into || !name || !passphrase}
        >
          <ShieldCheck className="w-4 h-4" />
          {loading ? "Encrypting..." : "Encrypt"}
        </button>
        {result && (
          <div className="mt-3 text-sm text-soteria-muted">{result}</div>
        )}
      </div>
    </div>
  );
}
