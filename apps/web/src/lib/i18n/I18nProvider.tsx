"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { DEFAULT_LOCALE, INTL_LOCALE, isLocale, translate, translateEnum, type Locale, type MessageKey, type Vars } from "./core";

const STORAGE_KEY = "admintwin.locale";

export interface I18n {
  locale: Locale;
  setLocale: (l: Locale) => void;
  t: (key: MessageKey, vars?: Vars) => string;
  te: (prefix: string, value: string | undefined | null) => string;
  fmtDate: (iso: string | undefined | null) => string;
  fmtNumber: (n: number | undefined | null, opts?: Intl.NumberFormatOptions) => string;
}

const Ctx = createContext<I18n | null>(null);

function readStoredLocale(): Locale {
  try {
    const v = window.localStorage.getItem(STORAGE_KEY);
    if (isLocale(v)) return v;
  } catch {
    // хранилище недоступно (приватный режим) — язык по умолчанию
  }
  return DEFAULT_LOCALE;
}

export function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>(DEFAULT_LOCALE);

  useEffect(() => {
    const stored = readStoredLocale();
    // eslint-disable-next-line react-hooks/set-state-in-effect -- синхронизация с внешним хранилищем после гидратации
    if (stored !== DEFAULT_LOCALE) setLocaleState(stored);
  }, []);

  useEffect(() => {
    document.documentElement.lang = locale;
  }, [locale]);

  const setLocale = useCallback((l: Locale) => {
    setLocaleState(l);
    try {
      window.localStorage.setItem(STORAGE_KEY, l);
    } catch {
      // не критично
    }
  }, []);

  const value = useMemo<I18n>(() => {
    const intl = INTL_LOCALE[locale];
    const dtf = new Intl.DateTimeFormat(intl, { dateStyle: "short", timeStyle: "medium" });
    return {
      locale,
      setLocale,
      t: (key, vars) => translate(locale, key, vars),
      te: (prefix, v) => translateEnum(locale, prefix, v),
      fmtDate: (iso) => {
        if (!iso || iso.startsWith("0001-01-01")) return "—";
        const d = new Date(iso);
        return Number.isNaN(d.getTime()) ? iso : dtf.format(d);
      },
      fmtNumber: (n, opts) => (n === undefined || n === null ? "—" : new Intl.NumberFormat(intl, opts).format(n)),
    };
  }, [locale, setLocale]);

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useI18n(): I18n {
  const v = useContext(Ctx);
  if (!v) throw new Error("useI18n outside I18nProvider");
  return v;
}
