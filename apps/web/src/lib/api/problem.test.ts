import { describe, expect, it } from "vitest";
import { ApiError, paramFieldErrors, parseProblemResponse, problemCode } from "./problem";

describe("problemCode", () => {
  it("takes the last segment of an errors.admintwin.io type", () => {
    expect(problemCode({ type: "https://errors.admintwin.io/separation-of-duties", status: 403 })).toBe("separation-of-duties");
    expect(problemCode({ type: "https://errors.admintwin.io/kill-switch-active/", status: 409 })).toBe("kill-switch-active");
  });
  it("falls back to HTTP status for about:blank", () => {
    expect(problemCode({ type: "about:blank", status: 404 })).toBe("not-found");
    expect(problemCode({ type: "", status: 422 })).toBe("invalid-params");
    expect(problemCode({ type: "about:blank", status: 503 })).toBe("internal");
  });
});

describe("parseProblemResponse", () => {
  it("parses an RFC 9457 body from the core (policy-denied with ids)", () => {
    const body = JSON.stringify({
      type: "https://errors.admintwin.io/policy-denied",
      title: "Policy denied",
      status: 403,
      detail: "Runbook 'x' is not permitted in mode 'advisor'",
      policy_id: "p-1",
      change_id: "c-1",
      request_id: "r-1",
    });
    const { kind, problem } = parseProblemResponse(403, "application/problem+json", body, "hdr");
    expect(kind).toBe("problem");
    expect(problem.title).toBe("Policy denied");
    expect(problem.detail).toContain("advisor");
    expect(problem.policy_id).toBe("p-1");
    expect(problem.change_id).toBe("c-1");
    expect(problem.request_id).toBe("r-1");
  });

  it("uses the X-Request-ID header when the body has no request_id", () => {
    const { problem } = parseProblemResponse(409, "application/problem+json", JSON.stringify({ type: "https://errors.admintwin.io/legal-hold", title: "Legal hold", status: 409 }), "abc");
    expect(problem.request_id).toBe("abc");
  });

  it("normalizes invalid-params field errors", () => {
    const body = JSON.stringify({
      type: "https://errors.admintwin.io/invalid-params",
      title: "Invalid parameters",
      status: 422,
      errors: [{ field: "params.container_id", reason: "does not match pattern" }, { field: "params.x", reason: "unknown parameter" }],
    });
    const { problem } = parseProblemResponse(422, "application/problem+json", body);
    const err = new ApiError("problem", problem);
    expect(err.code).toBe("invalid-params");
    expect(err.fieldErrors).toHaveLength(2);
    expect(paramFieldErrors(err.fieldErrors)).toEqual({ container_id: "does not match pattern", x: "unknown parameter" });
  });

  it("treats text/plain 404 from the Go mux as module-unavailable", () => {
    const { kind, problem } = parseProblemResponse(404, "text/plain; charset=utf-8", "404 page not found\n", "rid");
    expect(kind).toBe("module-unavailable");
    expect(problem.status).toBe(404);
    expect(problem.request_id).toBe("rid");
  });

  it("keeps a problem+json 404 (object not found) as a regular problem", () => {
    const { kind } = parseProblemResponse(404, "application/problem+json", JSON.stringify({ type: "https://errors.admintwin.io/not-found", title: "Not found", status: 404 }));
    expect(kind).toBe("problem");
  });

  it("classifies proxy failures as upstream-unavailable", () => {
    expect(parseProblemResponse(502, "text/html", "<html>Bad gateway</html>").kind).toBe("upstream-unavailable");
    expect(parseProblemResponse(503, "application/problem+json", JSON.stringify({ type: "about:blank", title: "Unavailable", status: 503 })).kind).toBe("upstream-unavailable");
  });

  it("survives malformed JSON", () => {
    const { kind, problem } = parseProblemResponse(500, "application/problem+json", "{not json");
    expect(kind).toBe("http");
    expect(problem.title).toBe("Internal error");
  });
});
