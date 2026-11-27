"use client";

import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";

export type ThemePref = "system" | "light" | "dark";
const STORAGE_KEY = "admintwin.theme";

/** Скрипт до гидратации: применяет сохранённую тему без мигания. */
export const THEME_BOOT_SCRIPT = `(function(){try{var t=localStorage.getItem('${STORAGE_KEY}');if(t==='light'||t==='dark'){document.documentElement.setAttribute('data-theme',t);}}catch(e){}})();`;

interface ThemeCtx {
  pref: ThemePref;
  resolved: "light" | "dark";
  setPref: (p: ThemePref) => void;
  toggle: () => void;
}

const Ctx = createContext<ThemeCtx | null>(null);

function systemDark(): boolean {
  return typeof window !== "undefined" && !!window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [pref, setPrefState] = useState<ThemePref>("system");
  const [sysDark, setSysDark] = useState(false);

  useEffect(() => {
    let stored: ThemePref = "system";
    try {
      const v = window.localStorage.getItem(STORAGE_KEY);
      if (v === "light" || v === "dark") stored = v;
    } catch {
      // без хранилища — системная тема
    }
    // eslint-disable-next-line react-hooks/set-state-in-effect -- чтение внешнего состояния после гидратации
    setPrefState(stored);
    setSysDark(systemDark());
    const mq = window.matchMedia?.("(prefers-color-scheme: dark)");
    const on = (e: MediaQueryListEvent) => setSysDark(e.matches);
    mq?.addEventListener?.("change", on);
    return () => mq?.removeEventListener?.("change", on);
  }, []);

  useEffect(() => {
    const el = document.documentElement;
    if (pref === "system") el.removeAttribute("data-theme");
    else el.setAttribute("data-theme", pref);
  }, [pref]);

  const setPref = useCallback((p: ThemePref) => {
    setPrefState(p);
    try {
      if (p === "system") window.localStorage.removeItem(STORAGE_KEY);
      else window.localStorage.setItem(STORAGE_KEY, p);
    } catch {
      // не критично
    }
  }, []);

  const resolved: "light" | "dark" = pref === "system" ? (sysDark ? "dark" : "light") : pref;
  const toggle = useCallback(() => setPref(resolved === "dark" ? "light" : "dark"), [resolved, setPref]);

  return <Ctx.Provider value={{ pref, resolved, setPref, toggle }}>{children}</Ctx.Provider>;
}

export function useTheme(): ThemeCtx {
  const v = useContext(Ctx);
  if (!v) throw new Error("useTheme outside ThemeProvider");
  return v;
}
