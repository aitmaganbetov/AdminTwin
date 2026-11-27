import { describe, expect, it, vi } from "vitest";
import { devHeaders } from "../auth/dev";
import { ApiClient, buildUrl } from "./client";
import { buildTaskTree, endpoints, taskId, taskList } from "./endpoints";
import { ApiError } from "./problem";

function mockFetch(status: number, body: unknown, headers: Record<string, string> = {}) {
  return vi.fn(async (_url: string | URL | Request, _init?: RequestInit) => {
    const text = typeof body === "string" ? body : JSON.stringify(body);
    return new Response(status === 204 ? null : text, { status, headers });
  });
}

describe("buildUrl", () => {
  it("keeps calls on /api/v1 and drops empty query values", () => {
    expect(buildUrl("", "/api/v1/changes", { status: "waiting_approval", x: "", y: undefined })).toBe("/api/v1/changes?status=waiting_approval");
    expect(buildUrl("http://core:8080/", "/api/v1/assets")).toBe("http://core:8080/api/v1/assets");
  });
  it("rejects paths outside /api/v1", () => {
    expect(() => buildUrl("", "/admin")).toThrow();
  });
});

describe("ApiClient", () => {
  it("sends DEV identity headers, a request id and JSON body", async () => {
    const f = mockFetch(202, { id: "c1", status: "waiting_approval" }, { "Content-Type": "application/json", "X-Request-ID": "srv-rid" });
    const id = { tenantId: "11111111-1111-4111-8111-111111111111", actorId: "alice", roles: ["tenant_admin" as const, "engineer" as const], scopes: ["sysadmin"] };
    const c = new ApiClient({ getHeaders: () => devHeaders(id), fetchImpl: f as unknown as typeof fetch, newRequestId: () => "rid-1" });
    const api = endpoints(c);
    const res = await api.createChange({ runbook_id: "docker.container.restart", asset_id: "a", params: { container_id: "3f2a9c1b7d4e" }, reason: "r" }, "idem-1");
    expect(res.status).toBe(202);
    expect(res.data.status).toBe("waiting_approval");
    expect(res.requestId).toBe("srv-rid");
    const [url, init] = f.mock.calls[0]!;
    expect(url).toBe("/api/v1/changes");
    const h = init!.headers as Record<string, string>;
    expect(h["X-AdminTwin-Tenant"]).toBe(id.tenantId);
    expect(h["X-AdminTwin-Actor"]).toBe("alice");
    expect(h["X-AdminTwin-Actor-Kind"]).toBe("user");
    expect(h["X-AdminTwin-Roles"]).toBe("tenant_admin,engineer");
    expect(h["X-AdminTwin-Scopes"]).toBe("sysadmin");
    expect(h["Idempotency-Key"]).toBe("idem-1");
    expect(h["X-Request-ID"]).toBe("rid1");
    expect(h["Content-Type"]).toBe("application/json");
    expect(JSON.parse(init!.body as string).params.container_id).toBe("3f2a9c1b7d4e");
  });

  it("sends a Bearer token in OIDC mode", async () => {
    const f = mockFetch(200, { items: [] }, { "Content-Type": "application/json" });
    const c = new ApiClient({ getHeaders: () => ({ Authorization: "Bearer tok" }), fetchImpl: f as unknown as typeof fetch });
    await endpoints(c).assets();
    expect((f.mock.calls[0]![1]!.headers as Record<string, string>).Authorization).toBe("Bearer tok");
  });

  it("throws ApiError with the parsed problem (separation-of-duties)", async () => {
    const f = mockFetch(
      403,
      { type: "https://errors.admintwin.io/separation-of-duties", title: "Separation of duties violated", status: 403, detail: "approver cannot be the author of the request", change_id: "c1", request_id: "r9" },
      { "Content-Type": "application/problem+json" },
    );
    const c = new ApiClient({ getHeaders: () => ({}), fetchImpl: f as unknown as typeof fetch });
    const err = await endpoints(c).decide("c1", "approve").catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err.kind).toBe("problem");
    expect(err.code).toBe("separation-of-duties");
    expect(err.requestId).toBe("r9");
    expect(err.problem.change_id).toBe("c1");
    expect(JSON.parse(f.mock.calls[0]![1]!.body as string)).toEqual({ decision: "approve" });
  });

  it("reports module-unavailable for an unregistered route", async () => {
    const f = mockFetch(404, "404 page not found", { "Content-Type": "text/plain; charset=utf-8" });
    const c = new ApiClient({ getHeaders: () => ({}), fetchImpl: f as unknown as typeof fetch });
    const err = await endpoints(c).incidents().catch((e) => e);
    expect(err.kind).toBe("module-unavailable");
  });

  it("calls onUnauthenticated on 401 problem", async () => {
    const f = mockFetch(401, { type: "https://errors.admintwin.io/unauthenticated", title: "Unauthenticated", status: 401 }, { "Content-Type": "application/problem+json" });
    const onUnauth = vi.fn();
    const c = new ApiClient({ getHeaders: () => ({}), fetchImpl: f as unknown as typeof fetch, onUnauthenticated: onUnauth });
    await endpoints(c).assets().catch(() => undefined);
    expect(onUnauth).toHaveBeenCalledOnce();
  });

  it("wraps fetch failures as network errors", async () => {
    const f = vi.fn(async () => {
      throw new TypeError("Failed to fetch");
    });
    const c = new ApiClient({ getHeaders: () => ({}), fetchImpl: f as unknown as typeof fetch });
    const err = await endpoints(c).health().catch((e) => e);
    expect(err.kind).toBe("network");
    expect(err.status).toBe(0);
  });

  it("encodes the kill switch body per OpenAPI", async () => {
    const f = mockFetch(200, { tenant: { active: true }, platform: { active: false } }, { "Content-Type": "application/json" });
    const c = new ApiClient({ getHeaders: () => ({}), fetchImpl: f as unknown as typeof fetch });
    await endpoints(c).setKillSwitch(true, "drill");
    expect(JSON.parse(f.mock.calls[0]![1]!.body as string)).toEqual({ scope: "tenant", active: true, reason: "drill" });
  });
});

describe("task tree", () => {
  it("normalizes list shapes and builds a tree from parent ids and nested children", () => {
    const flat = taskList({ tasks: [{ task_id: "root", status: "running" }, { task_id: "c1", parent_task_id: "root", status: "running" }] });
    expect(flat).toHaveLength(2);
    const tree = buildTaskTree([...flat, { id: "x", status: "completed", children: [{ id: "y", status: "running" }] }]);
    expect(tree.map((n) => taskId(n.task))).toEqual(["root", "x"]);
    expect(tree[0]!.children.map((n) => taskId(n.task))).toEqual(["c1"]);
    expect(tree[1]!.children.map((n) => taskId(n.task))).toEqual(["y"]);
  });
});
