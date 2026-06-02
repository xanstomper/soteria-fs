import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  LayoutDashboard,
  Shield,
  HardDrive,
  Key,
  LifeBuoy,
  Settings,
  BookOpen,
  ShieldCheck,
  Menu,
  X,
} from "lucide-react";
import Dashboard from "./components/Dashboard";
import SecurityPanel from "./components/SecurityPanel";
import VolumeManager from "./components/VolumeManager";
import KeyManager from "./components/KeyManager";
import Recovery from "./components/Recovery";
import SettingsPage from "./components/SettingsPage";

type Page =
  | "dashboard"
  | "security"
  | "volumes"
  | "keys"
  | "recovery"
  | "settings";

const navItems: { id: Page; label: string; icon: React.ElementType }[] = [
  { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { id: "security", label: "Security", icon: Shield },
  { id: "volumes", label: "Volumes", icon: HardDrive },
  { id: "keys", label: "Keys", icon: Key },
  { id: "recovery", label: "Recovery", icon: LifeBuoy },
  { id: "settings", label: "Settings", icon: Settings },
];

export default function App() {
  const [page, setPage] = useState<Page>("dashboard");
  const [sidebarOpen, setSidebarOpen] = useState(true);

  const renderPage = () => {
    switch (page) {
      case "dashboard":
        return <Dashboard />;
      case "security":
        return <SecurityPanel />;
      case "volumes":
        return <VolumeManager />;
      case "keys":
        return <KeyManager />;
      case "recovery":
        return <Recovery />;
      case "settings":
        return <SettingsPage />;
    }
  };

  return (
    <div className="flex h-screen overflow-hidden">
      {/* Sidebar */}
      <AnimatePresence>
        {sidebarOpen && (
          <motion.aside
            initial={{ width: 0, opacity: 0 }}
            animate={{ width: 256, opacity: 1 }}
            exit={{ width: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="flex-shrink-0 bg-soteria-surface border-r border-soteria-border flex flex-col overflow-hidden"
          >
            {/* Logo */}
            <div className="p-5 border-b border-soteria-border">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-lg bg-soteria-accent/15 flex items-center justify-center">
                  <ShieldCheck className="w-5 h-5 text-soteria-accent" />
                </div>
                <div>
                  <div className="text-base font-semibold">Soteria</div>
                  <div className="text-xs text-soteria-dim">Aegis Runtime</div>
                </div>
              </div>
            </div>

            {/* Navigation */}
            <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
              {navItems.map((item) => {
                const Icon = item.icon;
                const active = page === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => setPage(item.id)}
                    className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium
                      transition-all duration-150
                      ${
                        active
                          ? "bg-soteria-accent/15 text-soteria-text"
                          : "text-soteria-muted hover:bg-soteria-elevated hover:text-soteria-text"
                      }`}
                  >
                    <Icon className="w-4 h-4" />
                    {item.label}
                  </button>
                );
              })}
            </nav>

            {/* Footer */}
            <div className="p-3 border-t border-soteria-border">
              <button className="w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm
                text-soteria-dim hover:text-soteria-muted hover:bg-soteria-elevated
                transition-colors duration-150">
                <BookOpen className="w-4 h-4" />
                Learning Center
              </button>
            </div>
          </motion.aside>
        )}
      </AnimatePresence>

      {/* Main content */}
      <main className="flex-1 flex flex-col overflow-hidden">
        {/* Top bar */}
        <header className="flex-shrink-0 h-14 px-5 flex items-center justify-between
          bg-soteria-bg/80 backdrop-blur-xl border-b border-soteria-border">
          <div className="flex items-center gap-3">
            <button
              onClick={() => setSidebarOpen(!sidebarOpen)}
              className="p-1.5 rounded-lg text-soteria-muted hover:text-soteria-text
                hover:bg-soteria-elevated transition-colors"
            >
              {sidebarOpen ? <X className="w-4 h-4" /> : <Menu className="w-4 h-4" />}
            </button>
            <h1 className="text-lg font-semibold capitalize">{page}</h1>
          </div>
          <div className="flex items-center gap-2">
            <div className="badge-green">Protected</div>
          </div>
        </header>

        {/* Page content */}
        <div className="flex-1 overflow-y-auto p-6">
          <AnimatePresence mode="wait">
            <motion.div
              key={page}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ duration: 0.2 }}
            >
              {renderPage()}
            </motion.div>
          </AnimatePresence>
        </div>
      </main>
    </div>
  );
}
