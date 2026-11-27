// Генерация формы параметров runbook по его схеме (подмножество JSON Schema + allowlist + источник CMDB).
// Окончательная валидация — на сервере (runbook.ValidateParams); здесь — подсказки и типизация значений.
import type { Asset, RunbookParam } from "./api/types";

export type ParamControl = "select" | "text" | "number" | "checkbox";

export interface ParamField {
  name: string;
  control: ParamControl;
  type: string;
  required: boolean;
  options?: string[];
  pattern?: string;
  min?: number;
  max?: number;
  maxLength?: number;
  defaultValue?: unknown;
  /** Значение должно существовать в CMDB tenant для целевого актива. */
  inventoryKind?: string;
  /** Варианты ограничены объектами актива (objects[kind]). */
  fromInventory: boolean;
  /** Защищённые объекты (preflight not_in_protected_list их отклонит). */
  protectedOptions?: string[];
}

export type ParamValues = Record<string, string | boolean>;

function isRequired(p: RunbookParam): boolean {
  return p.required === undefined || p.required === true;
}

/**
 * Строит описания полей: enum → select, boolean → checkbox, integer/number → number с min/max,
 * string → text с подсказкой pattern. Для source=asset_inventory варианты берутся из объектов
 * выбранного актива (пересечение с enum, если он задан).
 */
export function buildParamFields(params: Record<string, RunbookParam> | null | undefined, asset?: Asset | null): ParamField[] {
  const names = Object.keys(params || {}).sort();
  return names.map((name) => {
    const p = (params || {})[name]!;
    const required = isRequired(p) && p.default === undefined;
    const base: ParamField = {
      name,
      control: "text",
      type: p.type,
      required,
      pattern: p.pattern,
      maxLength: p.max_length || undefined,
      defaultValue: p.default,
      inventoryKind: p.source === "asset_inventory" ? p.kind : undefined,
      fromInventory: false,
    };
    if (p.type === "boolean") return { ...base, control: "checkbox" };
    if (p.type === "integer" || p.type === "number") {
      return { ...base, control: "number", min: p.minimum ?? undefined, max: p.maximum ?? undefined };
    }
    let options = p.enum && p.enum.length > 0 ? [...p.enum] : undefined;
    let fromInventory = false;
    if (base.inventoryKind && asset) {
      const objs = asset.objects?.[base.inventoryKind];
      if (objs && objs.length > 0) {
        options = options ? options.filter((o) => objs.includes(o)) : [...objs];
        fromInventory = true;
      } else if (options) {
        // У актива нет объектов нужного вида: сервер отклонит любое значение.
        options = [];
        fromInventory = true;
      }
    }
    if (options) {
      const prot = (asset?.protected || []).filter((o) => options!.includes(o));
      return { ...base, control: "select", options, fromInventory, protectedOptions: prot.length ? prot : undefined };
    }
    return base;
  });
}

/** Начальные значения формы (default из схемы или пусто). */
export function initialParamValues(fields: ParamField[]): ParamValues {
  const v: ParamValues = {};
  for (const f of fields) {
    if (f.control === "checkbox") v[f.name] = f.defaultValue === true;
    else if (f.defaultValue !== undefined && f.defaultValue !== null) v[f.name] = String(f.defaultValue);
    else if (f.control === "select" && f.options && f.options.length === 1 && f.required) v[f.name] = f.options[0]!;
    else v[f.name] = "";
  }
  return v;
}

export type ParamErrorCode = "required" | "pattern" | "integer" | "number" | "min" | "max" | "max_length" | "enum";

export interface ParamError {
  code: ParamErrorCode;
  limit?: number | string;
}

/** Клиентская проверка (подсказка до отправки). */
export function validateParamValues(fields: ParamField[], values: ParamValues): Record<string, ParamError> {
  const errs: Record<string, ParamError> = {};
  for (const f of fields) {
    const raw = values[f.name];
    if (f.control === "checkbox") continue;
    const s = typeof raw === "string" ? raw.trim() : "";
    if (s === "") {
      if (f.required) errs[f.name] = { code: "required" };
      continue;
    }
    if (f.control === "number") {
      const n = Number(s);
      if (!Number.isFinite(n)) {
        errs[f.name] = { code: "number" };
        continue;
      }
      if (f.type === "integer" && !Number.isInteger(n)) {
        errs[f.name] = { code: "integer" };
        continue;
      }
      if (f.min !== undefined && n < f.min) errs[f.name] = { code: "min", limit: f.min };
      else if (f.max !== undefined && n > f.max) errs[f.name] = { code: "max", limit: f.max };
      continue;
    }
    if (f.control === "select" && f.options && !f.options.includes(s)) {
      errs[f.name] = { code: "enum" };
      continue;
    }
    if (f.maxLength && [...s].length > f.maxLength) {
      errs[f.name] = { code: "max_length", limit: f.maxLength };
      continue;
    }
    if (f.pattern) {
      let re: RegExp | null = null;
      try {
        re = new RegExp(f.pattern, "u");
      } catch {
        re = null; // RE2-синтаксис может не совпасть с JS — проверит сервер
      }
      if (re && !re.test(s)) errs[f.name] = { code: "pattern", limit: f.pattern };
    }
  }
  return errs;
}

/** Типизированные значения для тела запроса: пустые необязательные поля опускаются. */
export function coerceParamValues(fields: ParamField[], values: ParamValues): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const f of fields) {
    const raw = values[f.name];
    if (f.control === "checkbox") {
      out[f.name] = raw === true;
      continue;
    }
    const s = typeof raw === "string" ? raw.trim() : "";
    if (s === "") continue;
    if (f.control === "number") {
      const n = Number(s);
      out[f.name] = Number.isFinite(n) ? n : s;
    } else out[f.name] = s;
  }
  return out;
}

/** Стабильный ключ полезной нагрузки — Idempotency-Key обновляется при её изменении. */
export function payloadFingerprint(v: unknown): string {
  const stable = (x: unknown): unknown => {
    if (Array.isArray(x)) return x.map(stable);
    if (x && typeof x === "object") {
      return Object.keys(x as Record<string, unknown>)
        .sort()
        .reduce<Record<string, unknown>>((acc, k) => {
          acc[k] = stable((x as Record<string, unknown>)[k]);
          return acc;
        }, {});
    }
    return x;
  };
  return JSON.stringify(stable(v));
}
