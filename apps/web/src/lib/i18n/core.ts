// Небольшой собственный словарь i18n: ru (по умолчанию), kk (кириллица), en.
// Название продукта «AdminTwin» не переводится и не транслитерируется (ТЗ §25).
import { ru, type MessageKey } from "./ru";
import { kk } from "./kk";
import { en } from "./en";

export type Locale = "ru" | "kk" | "en";
export const LOCALES: Locale[] = ["ru", "kk", "en"];
export const DEFAULT_LOCALE: Locale = "ru";
export type { MessageKey };

export const dictionaries: Record<Locale, Record<MessageKey, string>> = { ru, kk, en };

/** BCP 47 для Intl (kk-KZ даёт казахские названия месяцев). */
export const INTL_LOCALE: Record<Locale, string> = { ru: "ru-RU", kk: "kk-KZ", en: "en-GB" };

export type Vars = Record<string, string | number>;

export function interpolate(s: string, vars?: Vars): string {
  if (!vars) return s;
  return s.replace(/\{(\w+)\}/g, (m, k: string) => (k in vars ? String(vars[k]) : m));
}

export function translate(locale: Locale, key: MessageKey, vars?: Vars): string {
  const d = dictionaries[locale] || dictionaries[DEFAULT_LOCALE];
  return interpolate(d[key] ?? dictionaries[DEFAULT_LOCALE][key] ?? key, vars);
}

/** Перевод значения перечисления (статусы, риски): при отсутствии ключа — исходное значение. */
export function translateEnum(locale: Locale, prefix: string, value: string | undefined | null): string {
  if (!value) return "—";
  const key = `${prefix}.${value}` as MessageKey;
  const d = dictionaries[locale] || dictionaries[DEFAULT_LOCALE];
  return d[key] ?? value;
}

export function isLocale(v: unknown): v is Locale {
  return v === "ru" || v === "kk" || v === "en";
}
