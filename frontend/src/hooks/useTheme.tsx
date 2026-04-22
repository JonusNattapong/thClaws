import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import { send, subscribe } from "./useIPC";

export type ThemeMode = "light" | "dark" | "system";
export type ResolvedTheme = "light" | "dark";

type ThemeContextValue = {
  /** User's stored preference — may be "system". */
  mode: ThemeMode;
  /** Concrete theme currently applied ("light" | "dark"). */
  resolved: ResolvedTheme;
  /** Persist a new preference via backend IPC. */
  setMode: (m: ThemeMode) => void;
};

const ThemeContext = createContext<ThemeContextValue | null>(null);

function detectSystem(): ResolvedTheme {
  if (typeof window === "undefined" || !window.matchMedia) return "dark";
  return window.matchMedia("(prefers-color-scheme: light)").matches
    ? "light"
    : "dark";
}

function normalize(raw: unknown): ThemeMode {
  return raw === "light" || raw === "dark" ? raw : "system";
}

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [mode, setModeState] = useState<ThemeMode>("system");
  const [systemTheme, setSystemTheme] = useState<ResolvedTheme>(() =>
    detectSystem(),
  );

  useEffect(() => {
    const unsub = subscribe((msg) => {
      if (msg.type === "theme") {
        setModeState(normalize(msg.mode));
      }
    });
    send({ type: "theme_get" });
    return unsub;
  }, []);

  useEffect(() => {
    if (typeof window === "undefined" || !window.matchMedia) return;
    const mql = window.matchMedia("(prefers-color-scheme: light)");
    const onChange = () => setSystemTheme(mql.matches ? "light" : "dark");
    // Safari < 14 still uses addListener; guard for both.
    if (mql.addEventListener) mql.addEventListener("change", onChange);
    else mql.addListener(onChange);
    return () => {
      if (mql.removeEventListener) mql.removeEventListener("change", onChange);
      else mql.removeListener(onChange);
    };
  }, []);

  const resolved: ResolvedTheme = mode === "system" ? systemTheme : mode;

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", resolved);
  }, [resolved]);

  const setMode = useCallback((next: ThemeMode) => {
    setModeState(next);
    send({ type: "theme_set", mode: next });
  }, []);

  const value = useMemo(
    () => ({ mode, resolved, setMode }),
    [mode, resolved, setMode],
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) {
    // Render-time fallback so components can be rendered in isolation
    // (tests, storybook) without a provider wrapping them.
    return {
      mode: "system",
      resolved: detectSystem(),
      setMode: () => {},
    };
  }
  return ctx;
}
