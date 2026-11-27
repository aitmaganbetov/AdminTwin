import { describe, expect, it } from "vitest";
import type { Asset, RunbookParam } from "./api/types";
import { buildParamFields, coerceParamValues, initialParamValues, payloadFingerprint, validateParamValues } from "./params";

// Схемы параметров из runbooks/catalog (как их отдаёт GET /api/v1/runbooks).
const dockerRestart: Record<string, RunbookParam> = {
  container_id: { type: "string", pattern: "^[a-f0-9]{12,64}$", source: "asset_inventory", kind: "container" },
};
const logsCleanup: Record<string, RunbookParam> = {
  directory: { type: "string", enum: ["/var/log/nginx", "/var/log/app", "/var/log/journal-archive"], source: "asset_inventory", kind: "log_directory" },
  older_than_days: { type: "integer", minimum: 3, maximum: 365, default: 14 },
  dry_run: { type: "boolean", default: false },
};

const dockerHost = {
  id: "a2",
  objects: { container: ["3f2a9c1b7d4e", "9b8c7d6e5f4a", "0a1b2c3d4e5f"] },
  protected: ["0a1b2c3d4e5f"],
} as unknown as Asset;
const linuxHost = { id: "a3", objects: { log_directory: ["/var/log/nginx", "/var/log/app"] } } as unknown as Asset;

describe("buildParamFields", () => {
  it("maps enum → select, integer → number with min/max, boolean → checkbox", () => {
    const f = buildParamFields(logsCleanup);
    const by = Object.fromEntries(f.map((x) => [x.name, x]));
    expect(by.directory!.control).toBe("select");
    expect(by.directory!.options).toEqual(["/var/log/nginx", "/var/log/app", "/var/log/journal-archive"]);
    expect(by.older_than_days!.control).toBe("number");
    expect(by.older_than_days!.min).toBe(3);
    expect(by.older_than_days!.max).toBe(365);
    expect(by.older_than_days!.required).toBe(false); // есть default
    expect(by.dry_run!.control).toBe("checkbox");
  });

  it("keeps a pattern hint for free-text strings", () => {
    const [f] = buildParamFields(dockerRestart);
    expect(f!.control).toBe("text");
    expect(f!.pattern).toBe("^[a-f0-9]{12,64}$");
    expect(f!.required).toBe(true);
    expect(f!.inventoryKind).toBe("container");
  });

  it("narrows inventory-sourced values to the selected asset's objects", () => {
    const [c] = buildParamFields(dockerRestart, dockerHost);
    expect(c!.control).toBe("select");
    expect(c!.options).toEqual(["3f2a9c1b7d4e", "9b8c7d6e5f4a", "0a1b2c3d4e5f"]);
    expect(c!.protectedOptions).toEqual(["0a1b2c3d4e5f"]);
    const dir = buildParamFields(logsCleanup, linuxHost).find((x) => x.name === "directory")!;
    expect(dir.options).toEqual(["/var/log/nginx", "/var/log/app"]); // enum ∩ objects
    const none = buildParamFields(logsCleanup, { id: "x", objects: {} } as unknown as Asset).find((x) => x.name === "directory")!;
    expect(none.options).toEqual([]);
  });
});

describe("values", () => {
  it("fills defaults and coerces types for the request body", () => {
    const fields = buildParamFields(logsCleanup, linuxHost);
    const v = initialParamValues(fields);
    expect(v).toEqual({ directory: "", dry_run: false, older_than_days: "14" });
    v.directory = "/var/log/nginx";
    expect(coerceParamValues(fields, v)).toEqual({ directory: "/var/log/nginx", dry_run: false, older_than_days: 14 });
  });

  it("omits empty optional values", () => {
    const fields = buildParamFields({ note: { type: "string", required: false } });
    expect(coerceParamValues(fields, { note: "  " })).toEqual({});
  });

  it("validates required, pattern, integer and range", () => {
    const fields = [...buildParamFields(dockerRestart), ...buildParamFields(logsCleanup)];
    expect(validateParamValues(fields, { container_id: "", directory: "/var/log/app", older_than_days: "14", dry_run: false })).toEqual({
      container_id: { code: "required" },
    });
    const e = validateParamValues(fields, { container_id: "ZZZ", directory: "/etc", older_than_days: "2.5", dry_run: false });
    expect(e.container_id!.code).toBe("pattern");
    expect(e.directory!.code).toBe("enum");
    expect(e.older_than_days!.code).toBe("integer");
    expect(validateParamValues(fields, { container_id: "3f2a9c1b7d4e", directory: "/var/log/app", older_than_days: "1", dry_run: true }).older_than_days).toEqual({ code: "min", limit: 3 });
    expect(validateParamValues(fields, { container_id: "3f2a9c1b7d4e", directory: "/var/log/app", older_than_days: "400", dry_run: true }).older_than_days).toEqual({ code: "max", limit: 365 });
  });
});

describe("payloadFingerprint", () => {
  it("is stable regardless of key order", () => {
    expect(payloadFingerprint({ a: 1, b: { y: 2, x: 1 } })).toBe(payloadFingerprint({ b: { x: 1, y: 2 }, a: 1 }));
    expect(payloadFingerprint({ a: 1 })).not.toBe(payloadFingerprint({ a: 2 }));
  });
});
