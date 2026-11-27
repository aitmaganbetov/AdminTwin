import { describe, expect, it } from "vitest";
import type { AgentTask } from "./api/types";
import { taskAgentRows } from "./taskAgents";

describe("taskAgentRows", () => {
  const registry = [
    { id: "devops-engineer", name: "DevOps Engineer", model_profile: "claude-primary" },
    { id: "linux-admin", name: "Linux Admin", model_profile: "claude-primary" },
  ];

  it("maps orchestrator string agents to rows with child status and registry profile", () => {
    const task = {
      agents: ["devops-engineer", "linux-admin"],
      children: [
        { agent_id: "devops-engineer", status: "completed" },
        { agent_id: "linux-admin", status: "running" },
      ],
    } as unknown as AgentTask;
    const rows = taskAgentRows(task, registry);
    expect(rows).toEqual([
      { agent_id: "devops-engineer", status: "completed", name: "DevOps Engineer", model_profile: "claude-primary" },
      { agent_id: "linux-admin", status: "running", name: "Linux Admin", model_profile: "claude-primary" },
    ]);
  });

  it("keeps object agents and adds child agents not listed", () => {
    const task = {
      agents: [{ agent_id: "dba-engineer", status: "completed", model_profile: "local" }],
      children: [{ agent_id: "network-engineer", status: "failed" }],
    } as unknown as AgentTask;
    const rows = taskAgentRows(task);
    expect(rows.map((r) => [r.agent_id, r.status, r.model_profile])).toEqual([
      ["dba-engineer", "completed", "local"],
      ["network-engineer", "failed", undefined],
    ]);
  });
});
