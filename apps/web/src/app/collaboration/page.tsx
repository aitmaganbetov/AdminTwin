"use client";

import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { Suspense, useMemo, useState, type FormEvent } from "react";
import { Icon } from "@/components/Icon";
import { Badge, DataState, Dialog, ModuleUnavailable, Notice, PageHeader, ProblemView, StatusBadge, TableWrap } from "@/components/ui";
import { buildTaskTree, taskId, taskList, type TaskNode } from "@/lib/api/endpoints";
import { isApiError, type ApiError } from "@/lib/api/problem";
import type { StreamState } from "@/lib/api/sse";
import { TERMINAL_TASK_STATUSES, type AgentTask, type StreamEvent } from "@/lib/api/types";
import { useApi, useAuth } from "@/lib/auth/AuthProvider";
import type { MessageKey } from "@/lib/i18n/core";
import { useI18n } from "@/lib/i18n/I18nProvider";
import { can } from "@/lib/permissions";
import { costByProvider, eventCategory, useEventStream, type EventCategory } from "@/lib/stream";
import { useResource } from "@/lib/useResource";

export default function CollaborationPage() {
  return (
    <Suspense>
      <Collaboration />
    </Suspense>
  );
}

function Collaboration() {
  const { t } = useI18n();
  const api = useApi();
  const search = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const selected = search.get("task");
  const tasks = useResource(() => api.agentTasks(), [api], { intervalMs: 5000 });
  const tree = useMemo(() => buildTaskTree(taskList(tasks.data)), [tasks.data]);
  const select = (id: string) => router.replace(`${pathname}?task=${encodeURIComponent(id)}`, { scroll: false });

  return (
    <>
      <PageHeader title={t("nav.collaboration")} subtitle={t("collab.subtitle")} />
      <Notice tone="info" title={t("collab.policy.title")}>
        <p className="small">{t("collab.policy.text")}</p>
      </Notice>
      {tasks.error?.kind === "module-unavailable" ? (
        <section className="card">
          <ModuleUnavailable name={t("nav.collaboration")} />
        </section>
      ) : (
        <div className="grid collab-grid">
          <div className="stack">
            <NewTask onCreated={(id) => { tasks.reload(); select(id); }} />
            <section className="card" aria-labelledby="collab-tree">
              <h2 id="collab-tree">{t("collab.taskTree")}</h2>
              <DataState res={tasks} moduleName={t("nav.collaboration")} isEmpty={() => tree.length === 0} emptyText={t("collab.noTasks")}>
                {() => <TaskTree nodes={tree} selected={selected} onSelect={select} />}
              </DataState>
            </section>
            <AgentsCard />
          </div>
          <div className="stack">
            {selected ? <TaskDetail id={selected} /> : <section className="card"><p className="muted">{t("collab.pickTask")}</p></section>}
            <ChatSessions />
          </div>
        </div>
      )}
    </>
  );
}

function TaskTree({ nodes, selected, onSelect }: { nodes: TaskNode[]; selected: string | null; onSelect: (id: string) => void }) {
  const { te } = useI18n();
  return (
    <ul className="tree" role="tree">
      {nodes.map((n) => {
        const id = taskId(n.task);
        return (
          <li key={id} role="treeitem" aria-selected={id === selected} aria-expanded={n.children.length ? true : undefined}>
            <button type="button" className="tree-item" aria-current={id === selected ? "true" : undefined} onClick={() => onSelect(id)}>
              <StatusBadge kind="task" value={n.task.status} />
              <span>
                {n.task.kind ? <code>{te("taskKind", n.task.kind)}</code> : null} {n.task.objective || n.task.agent || id.slice(0, 8)}
              </span>
            </button>
            {n.children.length ? <TaskTree nodes={n.children} selected={selected} onSelect={onSelect} /> : null}
          </li>
        );
      })}
    </ul>
  );
}

function NewTask({ onCreated }: { onCreated: (id: string) => void }) {
  const { t, te } = useI18n();
  const api = useApi();
  const { identity } = useAuth();
  const [kind, setKind] = useState<"diagnose" | "rca" | "chat">("diagnose");
  const [objective, setObjective] = useState("");
  const [incident, setIncident] = useState("");
  const [err, setErr] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  if (!can.createAiTask(identity)) return null;
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!objective.trim()) return;
    setBusy(true);
    setErr(null);
    try {
      const r = await api.createAgentTask({ kind, objective: objective.trim(), ...(incident.trim() ? { incident_id: incident.trim() } : {}) });
      setObjective("");
      onCreated(r.task_id);
    } catch (x) {
      if (isApiError(x)) setErr(x);
      else throw x;
    } finally {
      setBusy(false);
    }
  };
  return (
    <section className="card" aria-labelledby="collab-new">
      <h2 id="collab-new">{t("collab.newTask")}</h2>
      <form onSubmit={submit}>
        <div className="field">
          <label htmlFor="nt-kind">{t("collab.kind")}</label>
          <select id="nt-kind" value={kind} onChange={(e) => setKind(e.target.value as typeof kind)}>
            {(["diagnose", "rca", "chat"] as const).map((k) => (
              <option key={k} value={k}>
                {te("taskKind", k)}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="nt-obj">
            {t("collab.objective")} <span className="req" aria-hidden="true">*</span>
          </label>
          <textarea id="nt-obj" value={objective} onChange={(e) => setObjective(e.target.value)} required maxLength={4000} />
        </div>
        <div className="field">
          <label htmlFor="nt-inc">{t("change.incident")}</label>
          <input id="nt-inc" value={incident} onChange={(e) => setIncident(e.target.value)} placeholder="uuid" />
        </div>
        {err ? <ProblemView error={err} /> : null}
        <button type="submit" className="btn btn-primary" disabled={busy || !objective.trim()}>
          {t("collab.start")}
        </button>
      </form>
    </section>
  );
}

function AgentsCard() {
  const { t } = useI18n();
  const api = useApi();
  const agents = useResource(() => api.agents(), [api]);
  return (
    <section className="card" aria-labelledby="collab-agents">
      <h2 id="collab-agents">{t("agents.registry")}</h2>
      <DataState res={agents} moduleName={t("agents.registry")} isEmpty={(d) => (d.items || []).length === 0}>
        {(d) => (
          <ul className="steps">
            {(d.items || []).map((a) => (
              <li key={a.id}>
                <Icon name="agents" />
                <div className="small">
                  <strong>{a.name || a.id}</strong> <code>{a.id}</code>
                  <div className="muted">
                    {t("agents.modelProfile")}: <code>{a.model_profile || "—"}</code>
                    {a.fallback_model_profile ? (
                      <>
                        {" "}
                        → <code>{a.fallback_model_profile}</code>
                      </>
                    ) : null}
                  </div>
                </div>
              </li>
            ))}
          </ul>
        )}
      </DataState>
    </section>
  );
}

const CATEGORIES: EventCategory[] = ["message", "tool", "fact", "hypothesis", "cost", "change"];

function StreamStatus({ state }: { state: StreamState }) {
  const { t } = useI18n();
  const tone = state === "open" ? "success" : state === "reconnecting" ? "warning" : state === "unavailable" ? "neutral" : "info";
  return (
    <span role="status" aria-live="polite">
      <Badge tone={tone}>{t(`stream.${state}` as MessageKey)}</Badge>
    </span>
  );
}

function summarize(e: StreamEvent): string {
  const d = e.data;
  if (typeof d === "string") return d;
  if (!d || typeof d !== "object") return String(d ?? "");
  const o = d as Record<string, unknown>;
  for (const k of ["text", "message", "statement", "fact", "cause", "objective", "summary"]) {
    if (typeof o[k] === "string") return o[k] as string;
  }
  if (e.event === "tool_call") return `${String(o.tool ?? o.name ?? "")}(${o.input ? JSON.stringify(o.input) : ""})`;
  return JSON.stringify(o);
}

function StreamLog({ events, label }: { events: StreamEvent[]; label: string }) {
  const { t } = useI18n();
  const [show, setShow] = useState<Record<EventCategory, boolean>>({ message: true, tool: true, fact: true, hypothesis: true, cost: true, change: true });
  const visible = events.filter((e) => show[eventCategory(e.event)]);
  return (
    <div>
      <fieldset>
        <legend>{t("stream.filter")}</legend>
        <div className="chips">
          {CATEGORIES.map((c) => (
            <label key={c} className="check">
              <input type="checkbox" checked={show[c]} onChange={(e) => setShow({ ...show, [c]: e.target.checked })} />
              {t(`stream.cat.${c}` as MessageKey)}
            </label>
          ))}
        </div>
      </fieldset>
      {visible.length === 0 ? (
        <p className="muted small">{t("stream.empty")}</p>
      ) : (
        <ol className="stream" aria-label={label} aria-live="polite" aria-relevant="additions">
          {visible.map((e, i) => {
            const d = e.data && typeof e.data === "object" ? (e.data as Record<string, unknown>) : null;
            return (
              <li key={`${e.id ?? ""}-${i}`}>
                <div className="ev-head">
                  <Badge tone={eventCategory(e.event) === "tool" ? "info" : eventCategory(e.event) === "hypothesis" ? "warning" : eventCategory(e.event) === "cost" ? "neutral" : "outline"}>
                    {e.event}
                  </Badge>
                  {d?.from_agent || d?.agent ? <code className="small">{String(d.from_agent ?? d.agent)}</code> : null}
                  {d?.model_profile ? <span className="small muted">{String(d.model_profile)}</span> : null}
                  {typeof d?.confidence === "number" ? <span className="small">{Math.round((d.confidence as number) * 100)}%</span> : null}
                  <span className="small muted">{new Date(e.receivedAt).toLocaleTimeString()}</span>
                </div>
                <div>{summarize(e)}</div>
              </li>
            );
          })}
        </ol>
      )}
    </div>
  );
}

function TaskDetail({ id }: { id: string }) {
  const { t, te, fmtNumber, fmtDate } = useI18n();
  const api = useApi();
  const { identity } = useAuth();
  const task = useResource(() => api.agentTask(id), [api, id], {
    intervalMs: 3000,
    poll: (d) => !!d && !TERMINAL_TASK_STATUSES.includes(d.status as never),
  });
  const stream = useEventStream(api.agentTaskEventsUrl(id));
  const costs = useMemo(() => costByProvider(stream.events, task.data?.cost_by_provider), [stream.events, task.data?.cost_by_provider]);
  const [answer, setAnswer] = useState("");
  const [instruction, setInstruction] = useState("");
  const [err, setErr] = useState<ApiError | null>(null);
  const [ok, setOk] = useState<string | null>(null);
  const [stopOpen, setStopOpen] = useState(false);
  const [session, setSession] = useState<string | null>(null);
  const tk: AgentTask | undefined = task.data;
  const terminal = !!tk && TERMINAL_TASK_STATUSES.includes(tk.status as never);
  const allowed = can.createAiTask(identity);

  const act = async (fn: () => Promise<unknown>, msg: string) => {
    setErr(null);
    setOk(null);
    try {
      await fn();
      setOk(msg);
      task.reload();
    } catch (x) {
      if (isApiError(x)) setErr(x);
      else throw x;
    }
  };
  // Поручения и запрос альтернативной гипотезы идут через чат-сессию, привязанную к инциденту задачи.
  const sendChat = async (text: string) => {
    let sid = session;
    if (!sid) {
      sid = (await api.createChatSession(tk?.incident_id || undefined)).session_id;
      setSession(sid);
    }
    await api.chatMessage(sid, text);
  };

  return (
    <section className="card" aria-labelledby="task-h" data-testid="task-detail">
      <div className="card-title">
        <h2 id="task-h">
          {t("collab.task")} <code className="small">{id.slice(0, 8)}</code>
        </h2>
        <StreamStatus state={stream.state} />
      </div>
      {task.error ? (
        <ProblemView error={task.error} onRetry={task.reload} />
      ) : !tk ? (
        <p className="muted">{t("common.loading")}</p>
      ) : (
        <>
          <dl className="kv">
            <dt>{t("change.status")}</dt>
            <dd>
              <StatusBadge kind="task" value={tk.status} />
            </dd>
            <dt>{t("collab.kind")}</dt>
            <dd>{te("taskKind", tk.kind)}</dd>
            <dt>{t("collab.objective")}</dt>
            <dd>{tk.objective || "—"}</dd>
            {tk.incident_id ? (
              <>
                <dt>{t("change.incident")}</dt>
                <dd>
                  <Link href={`/incidents/${tk.incident_id}`}>{tk.incident_id}</Link>
                </dd>
              </>
            ) : null}
            <dt>{t("common.created")}</dt>
            <dd>{fmtDate(tk.created_at)}</dd>
          </dl>

          <h3 style={{ marginTop: 12 }}>{t("collab.activeAgents")}</h3>
          {(tk.agents || []).length === 0 ? (
            <p className="muted small">—</p>
          ) : (
            <TableWrap label={t("collab.activeAgents")}>
              <table>
                <thead>
                  <tr>
                    <th scope="col">{t("agents.name")}</th>
                    <th scope="col">{t("change.status")}</th>
                    <th scope="col">{t("agents.modelProfile")}</th>
                    <th scope="col">{t("ai.model")}</th>
                  </tr>
                </thead>
                <tbody>
                  {(tk.agents || []).map((a, i) => (
                    <tr key={i}>
                      <td>
                        <code>{a.agent_id || a.id || a.name}</code>
                      </td>
                      <td>{a.status ? <StatusBadge kind="task" value={a.status} /> : "—"}</td>
                      <td>
                        <code>{a.model_profile || "—"}</code>
                      </td>
                      <td className="small">{[a.provider, a.model].filter(Boolean).join(" / ") || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          )}

          <h3 style={{ marginTop: 12 }}>{t("collab.costByProvider")}</h3>
          {Object.keys(costs).length === 0 ? (
            <p className="muted small">—</p>
          ) : (
            <ul className="small">
              {Object.entries(costs).map(([p, v]) => (
                <li key={p}>
                  <code>{p}</code>: {fmtNumber(v, { style: "currency", currency: "USD", maximumFractionDigits: 4 })}
                </li>
              ))}
            </ul>
          )}
          {tk.cost_usd !== undefined ? (
            <p className="small">
              {t("collab.costTotal")}: {fmtNumber(tk.cost_usd, { style: "currency", currency: "USD", maximumFractionDigits: 4 })}
            </p>
          ) : null}

          {(tk.facts || []).length > 0 ? (
            <>
              <h3 style={{ marginTop: 12 }}>{t("collab.facts")}</h3>
              <ul className="small">
                {(tk.facts || []).map((f, i) => (
                  <li key={i}>
                    {f.statement || f.fact} {f.evidence_id ? <code>{f.evidence_id}</code> : null}
                  </li>
                ))}
              </ul>
            </>
          ) : null}

          {allowed && !terminal ? (
            <div className="stack" style={{ marginTop: 12 }}>
              {tk.status === "waiting_input" ? (
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    if (answer.trim()) void act(() => api.agentTaskInput(id, answer.trim()), t("collab.answerSent")).then(() => setAnswer(""));
                  }}
                >
                  <Notice tone="warning" title={t("collab.waitingInput")}>
                    <p className="small">{tk.waiting_input?.question || tk.waiting_input?.prompt || tk.question || ""}</p>
                  </Notice>
                  <div className="field">
                    <label htmlFor="task-answer">{t("collab.answer")}</label>
                    <textarea id="task-answer" value={answer} onChange={(e) => setAnswer(e.target.value)} />
                  </div>
                  <button type="submit" className="btn btn-primary" disabled={!answer.trim()}>
                    {t("collab.sendAnswer")}
                  </button>
                </form>
              ) : null}
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  if (instruction.trim()) void act(() => sendChat(instruction.trim()), t("collab.instructionSent")).then(() => setInstruction(""));
                }}
              >
                <div className="field">
                  <label htmlFor="task-instr">{t("collab.instruction")}</label>
                  <textarea id="task-instr" value={instruction} onChange={(e) => setInstruction(e.target.value)} aria-describedby="task-instr-hint" />
                  <span id="task-instr-hint" className="hint">
                    {t("collab.instructionHint")}
                  </span>
                </div>
                <div className="row">
                  <button type="submit" className="btn" disabled={!instruction.trim()}>
                    {t("collab.addInstruction")}
                  </button>
                  <button
                    type="button"
                    className="btn"
                    onClick={() => void act(() => sendChat(t("collab.altHypothesisText")), t("collab.instructionSent"))}
                  >
                    {t("collab.altHypothesis")}
                  </button>
                  <button type="button" className="btn btn-danger" onClick={() => setStopOpen(true)}>
                    <Icon name="stop" /> {t("collab.stop")}
                  </button>
                </div>
              </form>
            </div>
          ) : null}
          {ok ? (
            <p role="status" className="small">
              {ok}
            </p>
          ) : null}
          {err ? <ProblemView error={err} /> : null}
        </>
      )}

      <h3 style={{ marginTop: 16 }}>{t("collab.stream")}</h3>
      {stream.state === "unavailable" ? <ModuleUnavailable name={t("collab.stream")} /> : <StreamLog events={stream.events} label={t("collab.stream")} />}

      <Dialog
        open={stopOpen}
        title={t("collab.stopTitle")}
        onClose={() => setStopOpen(false)}
        actions={
          <>
            <button type="button" className="btn" onClick={() => setStopOpen(false)}>
              {t("common.cancel")}
            </button>
            <button
              type="button"
              className="btn btn-danger"
              onClick={() => {
                setStopOpen(false);
                void act(() => api.cancelAgentTask(id), t("collab.stopped"));
              }}
            >
              {t("collab.stop")}
            </button>
          </>
        }
      >
        <p className="small">{t("collab.stopText")}</p>
      </Dialog>
    </section>
  );
}

function ChatSessions() {
  const { t } = useI18n();
  const api = useApi();
  const { identity } = useAuth();
  const [sessions, setSessions] = useState<string[]>([]);
  const [current, setCurrent] = useState<string | null>(null);
  const [incident, setIncident] = useState("");
  const [text, setText] = useState("");
  const [err, setErr] = useState<ApiError | null>(null);
  const stream = useEventStream(current ? api.chatEventsUrl(current) : null);
  if (!can.createAiTask(identity)) return null;

  const start = async () => {
    setErr(null);
    try {
      const r = await api.createChatSession(incident.trim() || undefined);
      setSessions((s) => [...s, r.session_id]);
      setCurrent(r.session_id);
    } catch (x) {
      if (isApiError(x)) setErr(x);
      else throw x;
    }
  };
  const send = async (e: FormEvent) => {
    e.preventDefault();
    if (!current || !text.trim()) return;
    setErr(null);
    try {
      await api.chatMessage(current, text.trim());
      setText("");
    } catch (x) {
      if (isApiError(x)) setErr(x);
      else throw x;
    }
  };

  return (
    <section className="card" aria-labelledby="chat-h">
      <div className="card-title">
        <h2 id="chat-h">{t("chat.title")}</h2>
        {current ? <StreamStatus state={stream.state} /> : null}
      </div>
      <div className="toolbar">
        <div className="field">
          <label htmlFor="chat-inc">{t("change.incident")}</label>
          <input id="chat-inc" value={incident} onChange={(e) => setIncident(e.target.value)} placeholder="uuid" />
        </div>
        <button type="button" className="btn" onClick={start}>
          <Icon name="plus" /> {t("chat.start")}
        </button>
        {sessions.length > 0 ? (
          <div className="field">
            <label htmlFor="chat-sel">{t("chat.session")}</label>
            <select id="chat-sel" value={current || ""} onChange={(e) => setCurrent(e.target.value)}>
              {sessions.map((s) => (
                <option key={s} value={s}>
                  {s.slice(0, 8)}
                </option>
              ))}
            </select>
          </div>
        ) : null}
      </div>
      {err ? (err.kind === "module-unavailable" ? <ModuleUnavailable name={t("chat.title")} /> : <ProblemView error={err} />) : null}
      {current ? (
        <>
          <StreamLog events={stream.events} label={t("chat.title")} />
          <form onSubmit={send} style={{ marginTop: 12 }}>
            <div className="field">
              <label htmlFor="chat-text">{t("chat.message")}</label>
              <textarea id="chat-text" value={text} onChange={(e) => setText(e.target.value)} />
            </div>
            <button type="submit" className="btn btn-primary" disabled={!text.trim()}>
              {t("chat.send")}
            </button>
          </form>
        </>
      ) : (
        <p className="muted small">{t("chat.none")}</p>
      )}
    </section>
  );
}
