import { describe, expect, it } from "vitest";
import type { Change, Dependency } from "./api/types";
import { rcaUncertain, transitionRequirements } from "./incidents";
import { approvalEligibility, can, type Identity } from "./permissions";
import { computeLayers, hotEdges } from "./topology";

const change = (over: Partial<Change> = {}): Change =>
  ({
    id: "c1",
    status: "waiting_approval",
    author_id: "alice",
    author_kind: "user",
    decisions: [],
    policy: {
      policy_id: "p",
      outcome: "requires_approval",
      required_approvals: 1,
      approver_roles: ["tenant_admin", "it_manager", "engineer"],
      engineer_scope: "sysadmin",
      requires_maintenance_window: false,
      preflight_mandatory: false,
      break_glass: false,
      reasons: [],
    },
    ...over,
  }) as Change;

const who = (actorId: string, roles: Identity["roles"], scopes: string[] = []): Identity => ({ actorId, tenantId: "t", roles, scopes });

describe("approvalEligibility (§2.2, §11.4)", () => {
  it("lets an eligible non-author decide", () => {
    expect(approvalEligibility(who("bob", ["it_manager"]), change())).toEqual({ canDecide: true, block: null, isAuthor: false });
  });
  it("flags the author but leaves the decision to the server (SoD 403)", () => {
    const e = approvalEligibility(who("alice", ["tenant_admin"]), change());
    expect(e.canDecide).toBe(true);
    expect(e.isAuthor).toBe(true);
  });
  it("hides approval for roles that cannot approve", () => {
    expect(approvalEligibility(who("v", ["viewer"]), change()).block).toBe("no-role");
    expect(approvalEligibility(who("o", ["operator"]), change()).block).toBe("no-role");
    expect(approvalEligibility(who("au", ["auditor"]), change()).canDecide).toBe(false);
  });
  it("restricts engineers to their scope", () => {
    expect(approvalEligibility(who("e", ["engineer"], ["network"]), change()).block).toBe("scope");
    expect(approvalEligibility(who("e", ["engineer"], ["sysadmin"]), change()).canDecide).toBe(true);
  });
  it("blocks repeated votes and non-waiting changes", () => {
    const decided = change({ decisions: [{ actor_id: "bob", roles: [], verdict: "approve", at: "" }] });
    expect(approvalEligibility(who("bob", ["it_manager"]), decided).block).toBe("already-decided");
    expect(approvalEligibility(who("bob", ["it_manager"]), change({ status: "closed" })).block).toBe("not-waiting");
  });
});

describe("can", () => {
  it("follows the role × action matrix", () => {
    expect(can.killSwitch(who("o", ["operator"]))).toBe(true);
    expect(can.killSwitch(who("e", ["engineer"]))).toBe(false);
    expect(can.readAudit(who("a", ["auditor"]))).toBe(true);
    expect(can.readAudit(who("o", ["operator"]))).toBe(false);
    expect(can.proposeChange(who("v", ["viewer"]))).toBe(false);
    expect(can.breakGlass(who("e", ["engineer"]))).toBe(false);
    expect(can.breakGlass(who("m", ["it_manager"]))).toBe(true);
  });
});

describe("incident rules (C.7)", () => {
  it("requires evidence for mitigated and a postmortem for high+ resolved", () => {
    expect(transitionRequirements({ severity: "low", postmortem: null }, "mitigated").evidenceRequired).toBe(true);
    expect(transitionRequirements({ severity: "high", postmortem: null }, "resolved").postmortemRequired).toBe(true);
    expect(transitionRequirements({ severity: "medium", postmortem: null }, "resolved").postmortemRequired).toBe(false);
    expect(transitionRequirements({ severity: "critical", postmortem: { summary: "s", root_cause: "r", corrective_actions: [] } }, "resolved").postmortemRequired).toBe(false);
  });
  it("detects RCA uncertainty", () => {
    expect(rcaUncertain("uncertain", [])).toBe(true);
    expect(rcaUncertain("completed", [{ cause: "a", confidence: 0.8 }, { cause: "b", confidence: 0.75 }])).toBe(true);
    expect(rcaUncertain("completed", [{ cause: "a", confidence: 0.85 }, { cause: "b", confidence: 0.3 }])).toBe(false);
  });
});

describe("topology layout", () => {
  const e = (source: string, target: string) => ({ source, target }) as Dependency;
  it("layers consumers before their dependencies and survives cycles", () => {
    const l = computeLayers(["fw", "app", "docker", "pg"], [e("docker", "pg"), e("app", "docker"), e("fw", "app")]);
    expect([l.get("fw"), l.get("app"), l.get("docker"), l.get("pg")]).toEqual([0, 1, 2, 3]);
    const c = computeLayers(["a", "b"], [e("a", "b"), e("b", "a")]);
    expect(c.size).toBe(2);
  });
  it("highlights edges on the impact path", () => {
    const edges = [e("docker", "pg"), e("app", "docker"), e("fw", "app")];
    expect([...hotEdges(edges, "docker", new Set(["app", "fw"]))].sort()).toEqual([1, 2]);
  });
});
