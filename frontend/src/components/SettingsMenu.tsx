import { useEffect, useRef, useState } from "react";
import { Globe, Folder, KeyRound, Sun, Moon, Monitor, Check, Users } from "lucide-react";
import { useTheme, type ThemeMode } from "../hooks/useTheme";
import { send, subscribe } from "../hooks/useIPC";

type Choice = "global-instructions" | "folder-instructions" | "api-keys";

export function SettingsMenu({
  anchorRef,
  onPick,
  onClose,
}: {
  anchorRef: React.RefObject<HTMLElement | null>;
  onPick: (choice: Choice) => void;
  onClose: () => void;
}) {
  const menuRef = useRef<HTMLDivElement | null>(null);
  const { mode, setMode } = useTheme();
  const [teamEnabled, setTeamEnabled] = useState<boolean | null>(null);
  const [teamDirty, setTeamDirty] = useState(false);

  useEffect(() => {
    const unsub = subscribe((msg) => {
      if (msg.type === "team_enabled" && typeof msg.enabled === "boolean") {
        setTeamEnabled(msg.enabled as boolean);
      } else if (
        msg.type === "team_enabled_result" &&
        typeof msg.enabled === "boolean"
      ) {
        setTeamEnabled(msg.enabled as boolean);
        setTeamDirty(true);
      }
    });
    send({ type: "team_enabled_get" });
    return unsub;
  }, []);

  const toggleTeam = () => {
    const next = !(teamEnabled ?? false);
    send({ type: "team_enabled_set", enabled: next });
  };

  // Close on click-outside (excluding the anchor so a second click on
  // the gear icon can also close the menu via its own toggle handler).
  useEffect(() => {
    const onDown = (e: MouseEvent) => {
      const target = e.target as Node;
      if (menuRef.current && menuRef.current.contains(target)) return;
      if (anchorRef.current && anchorRef.current.contains(target)) return;
      onClose();
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("mousedown", onDown);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("mousedown", onDown);
      window.removeEventListener("keydown", onKey);
    };
  }, [anchorRef, onClose]);

  const items: { id: Choice; icon: React.ReactNode; label: string; hint: string }[] = [
    {
      id: "global-instructions",
      icon: <Globe size={12} />,
      label: "Global instructions",
      hint: "Edit ~/.config/thclaws/AGENTS.md",
    },
    {
      id: "folder-instructions",
      icon: <Folder size={12} />,
      label: "Folder instructions",
      hint: "Edit AGENTS.md in the current directory",
    },
    {
      id: "api-keys",
      icon: <KeyRound size={12} />,
      label: "Provider API keys",
      hint: "Manage keys stored in the OS keychain",
    },
  ];

  const themeOptions: { id: ThemeMode; icon: React.ReactNode; label: string }[] = [
    { id: "light", icon: <Sun size={12} />, label: "Light" },
    { id: "dark", icon: <Moon size={12} />, label: "Dark" },
    { id: "system", icon: <Monitor size={12} />, label: "System" },
  ];

  return (
    <div
      ref={menuRef}
      className="absolute right-2 bottom-7 rounded-md shadow-2xl py-1 z-40"
      style={{
        background: "var(--bg-secondary)",
        border: "1px solid var(--border)",
        minWidth: "220px",
      }}
    >
      {items.map((item) => (
        <button
          key={item.id}
          onClick={() => {
            onPick(item.id);
            onClose();
          }}
          className="w-full text-left px-3 py-1.5 hover:bg-white/5 transition-colors flex items-center gap-2"
          style={{ color: "var(--text-primary)", fontSize: "12px" }}
        >
          <span style={{ color: "var(--text-secondary)" }}>{item.icon}</span>
          <div>
            <div>{item.label}</div>
            <div
              style={{ color: "var(--text-secondary)", fontSize: "10px" }}
            >
              {item.hint}
            </div>
          </div>
        </button>
      ))}
      <div
        className="my-1"
        style={{ borderTop: "1px solid var(--border)" }}
      />
      <div
        className="px-3 py-1 text-[10px] uppercase tracking-wider"
        style={{ color: "var(--text-secondary)" }}
      >
        Appearance
      </div>
      {themeOptions.map((opt) => {
        const active = mode === opt.id;
        return (
          <button
            key={opt.id}
            onClick={() => setMode(opt.id)}
            className="w-full text-left px-3 py-1.5 hover:bg-white/5 transition-colors flex items-center gap-2"
            style={{ color: "var(--text-primary)", fontSize: "12px" }}
          >
            <span style={{ color: "var(--text-secondary)" }}>{opt.icon}</span>
            <span className="flex-1">{opt.label}</span>
            {active && (
              <Check size={12} style={{ color: "var(--accent)" }} />
            )}
          </button>
        );
      })}
      <div
        className="my-1"
        style={{ borderTop: "1px solid var(--border)" }}
      />
      <div
        className="px-3 py-1 text-[10px] uppercase tracking-wider"
        style={{ color: "var(--text-secondary)" }}
      >
        Workspace
      </div>
      <button
        onClick={toggleTeam}
        className="w-full text-left px-3 py-1.5 hover:bg-white/5 transition-colors flex items-start gap-2"
        style={{ color: "var(--text-primary)", fontSize: "12px" }}
        disabled={teamEnabled === null}
      >
        <span style={{ color: "var(--text-secondary)", paddingTop: "1px" }}>
          <Users size={12} />
        </span>
        <div className="flex-1">
          <div className="flex items-center gap-2">
            <span>Agent Teams</span>
            <span
              style={{
                fontSize: "10px",
                padding: "1px 6px",
                borderRadius: "10px",
                background:
                  teamEnabled === true
                    ? "var(--accent-dim)"
                    : "var(--bg-tertiary)",
                color:
                  teamEnabled === true
                    ? "#fff"
                    : "var(--text-secondary)",
                border:
                  teamEnabled === true
                    ? "none"
                    : "1px solid var(--border)",
              }}
            >
              {teamEnabled === null ? "…" : teamEnabled ? "on" : "off"}
            </span>
          </div>
          <div
            style={{ color: "var(--text-secondary)", fontSize: "10px" }}
          >
            TeamCreate, SpawnTeammate, … (writes `.thclaws/settings.json`)
          </div>
          {teamDirty && (
            <div
              style={{
                color: "var(--warning)",
                fontSize: "10px",
                marginTop: "2px",
              }}
            >
              Restart the app for this to take effect.
            </div>
          )}
        </div>
      </button>
    </div>
  );
}
