import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { dictionaries, interpolate, LOCALES, translate, translateEnum } from "./core";
import { ru } from "./ru";
import { CHANGE_STATUSES, INCIDENT_STATUSES, SEVERITIES, ALL_ROLES } from "../api/types";

const ruKeys = Object.keys(ru).sort();
const placeholders = (s: string) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();

describe("i18n completeness", () => {
  for (const l of LOCALES) {
    it(`${l}: has exactly the same keys as ru, all non-empty`, () => {
      const d = dictionaries[l];
      expect(Object.keys(d).sort()).toEqual(ruKeys);
      for (const k of ruKeys) expect(d[k as keyof typeof d].trim(), `${l}:${k}`).not.toBe("");
    });
    it(`${l}: keeps the same {placeholders}`, () => {
      const d = dictionaries[l];
      for (const k of ruKeys) expect(placeholders(d[k as keyof typeof d]), `${l}:${k}`).toEqual(placeholders(ru[k as keyof typeof ru]));
    });
  }

  it("kk is written in Kazakh Cyrillic", () => {
    const text = Object.values(dictionaries.kk).join(" ");
    expect(text).toMatch(/[әғқңөұүһі]/);
    // большинство строк, содержащих буквы, — кириллические
    const withLetters = Object.values(dictionaries.kk).filter((s) => /\p{L}/u.test(s));
    const cyr = withLetters.filter((s) => /[Ѐ-ӿ]/.test(s));
    expect(cyr.length / withLetters.length).toBeGreaterThan(0.75);
  });

  it("never transliterates the product name AdminTwin (§25)", () => {
    for (const l of LOCALES) {
      for (const v of Object.values(dictionaries[l])) expect(v).not.toMatch(/Админ\s?Твин|Әдмин/i);
    }
    expect(dictionaries.kk["auth.title"]).toContain("AdminTwin");
    expect(dictionaries.ru["auth.title"]).toContain("AdminTwin");
  });

  it("covers every status/severity/role enum value", () => {
    for (const s of CHANGE_STATUSES) expect(ru).toHaveProperty(`st.change.${s}`);
    for (const s of INCIDENT_STATUSES) expect(ru).toHaveProperty(`st.incident.${s}`);
    for (const s of SEVERITIES) expect(ru).toHaveProperty(`st.severity.${s}`);
    for (const r of ALL_ROLES) expect(ru).toHaveProperty(`role.${r}`);
  });

  it("every literal t(\"...\") key used in the sources exists", () => {
    const root = join(__dirname, "..", "..");
    const files: string[] = [];
    const walk = (d: string) => {
      for (const f of readdirSync(d)) {
        const p = join(d, f);
        if (statSync(p).isDirectory()) walk(p);
        else if (/\.tsx?$/.test(f) && !f.endsWith(".test.ts")) files.push(p);
      }
    };
    walk(root);
    const missing: string[] = [];
    for (const f of files) {
      const src = readFileSync(f, "utf8");
      for (const m of src.matchAll(/\bt\("([a-zA-Z0-9_.-]+)"/g)) if (!(m[1]! in ru)) missing.push(`${f}: ${m[1]}`);
      for (const m of src.matchAll(/"([a-z]+(?:\.[a-zA-Z0-9_-]+)+)" as MessageKey/g)) if (!(m[1]! in ru)) missing.push(`${f}: ${m[1]}`);
    }
    expect(missing).toEqual([]);
  });
});

describe("helpers", () => {
  it("interpolates and falls back", () => {
    expect(interpolate("{a} of {b}", { a: 1, b: 2 })).toBe("1 of 2");
    expect(interpolate("{a} {missing}", { a: "x" })).toBe("x {missing}");
    expect(translate("en", "approval.progress", { n: 1, required: 2 })).toBe("Approvals: 1 of 2");
    expect(translateEnum("ru", "st.change", "waiting_approval")).toBe("ждёт согласования");
    expect(translateEnum("kk", "st.change", "brand_new_state")).toBe("brand_new_state");
  });
});
