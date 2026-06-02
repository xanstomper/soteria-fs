import { useEffect, useState } from "react";
import { Key, RefreshCw, Plus, Shield } from "lucide-react";
import {
  getKeyLifecycle,
  generateKeypair,
  type KeyLifecycle,
} from "../lib/commands";

export default function KeyManager() {
  const [lifecycle, setLifecycle] = useState<KeyLifecycle | null>(null);
  const [keygenOut, setKeygenOut] = useState("");
  const [keygenScheme, setKeygenScheme] = useState("ml-kem-768");
  const [keygenResult, setKeygenResult] = useState<string | null>(null);

  useEffect(() => {
    getKeyLifecycle().then(setLifecycle);
  }, []);

  const handleKeygen = async () => {
    try {
      const res = await generateKeypair({ scheme: keygenScheme, out: keygenOut });
      setKeygenResult(`Generated: ${res.public_key}`);
    } catch (e) {
      setKeygenResult(`Error: ${e}`);
    }
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Key Health */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h3 className="font-semibold">Key Health</h3>
          <button className="btn-secondary text-xs">
            <RefreshCw className="w-3 h-3" />
            Rotate Keys
          </button>
        </div>
        <div className="grid grid-cols-3 gap-4">
          <div>
            <div className="text-xs text-soteria-dim uppercase tracking-wider mb-1">
              Rotation Status
            </div>
            <div className="text-lg font-semibold text-soteria-green">
              {lifecycle?.rotation_health ?? "—"}
            </div>
          </div>
          <div>
            <div className="text-xs text-soteria-dim uppercase tracking-wider mb-1">
              Next Rotation
            </div>
            <div className="text-lg font-semibold">
              {lifecycle?.next_rotation ?? "—"}
            </div>
          </div>
          <div>
            <div className="text-xs text-soteria-dim uppercase tracking-wider mb-1">
              Total Keys
            </div>
            <div className="text-lg font-semibold">
              {lifecycle?.total_keys ?? 0}
            </div>
          </div>
        </div>
      </div>

      {/* Key table */}
      <div className="card">
        <h3 className="font-semibold mb-4">Key Lifecycle</h3>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-soteria-border">
              <th className="text-left py-2 text-soteria-dim font-medium">Key</th>
              <th className="text-left py-2 text-soteria-dim font-medium">Type</th>
              <th className="text-left py-2 text-soteria-dim font-medium">Status</th>
              <th className="text-left py-2 text-soteria-dim font-medium">Rotation Due</th>
            </tr>
          </thead>
          <tbody>
            {lifecycle?.keys.map((k) => (
              <tr key={k.name} className="border-b border-soteria-border/50">
                <td className="py-3 font-medium">{k.name}</td>
                <td className="py-3 text-soteria-muted">{k.key_type}</td>
                <td className="py-3">
                  <span className="badge-green">{k.status}</span>
                </td>
                <td className="py-3 text-soteria-muted">{k.rotation_due}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Generate keypair */}
      <div className="card">
        <h3 className="font-semibold mb-4">Generate Keypair</h3>
        <div className="grid grid-cols-3 gap-4 mb-4">
          <div>
            <label className="text-xs text-soteria-dim mb-1 block">Scheme</label>
            <select
              className="input"
              value={keygenScheme}
              onChange={(e) => setKeygenScheme(e.target.value)}
            >
              <option value="ml-kem-768">ML-KEM-768 (Sharing)</option>
              <option value="ml-dsa-65">ML-DSA-65 (Signing)</option>
            </select>
          </div>
          <div className="col-span-2">
            <label className="text-xs text-soteria-dim mb-1 block">
              Output prefix
            </label>
            <input
              className="input"
              placeholder="/path/to/key"
              value={keygenOut}
              onChange={(e) => setKeygenOut(e.target.value)}
            />
          </div>
        </div>
        <button
          className="btn-primary"
          onClick={handleKeygen}
          disabled={!keygenOut}
        >
          <Plus className="w-4 h-4" />
          Generate
        </button>
        {keygenResult && (
          <div className="mt-3 text-sm text-soteria-muted">{keygenResult}</div>
        )}
      </div>
    </div>
  );
}
