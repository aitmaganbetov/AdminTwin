"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useState, type FormEvent } from "react";
import { Icon } from "@/components/Icon";
import { Badge, ConfidenceBar, DataState, Notice, PageHeader, ProblemView, StatusBadge, TableWrap } from "@/components/ui";
import { isApiError, type ApiError } from "@/lib/api/problem";
import type { Hypothesis, HypothesisFact, Incident, IncidentStatus, TelemetryEvent } from "@/lib/api/types";
import { useApi, useAuth } from "@/lib/auth/AuthProvider";
import { useAssets } from "@/lib/hooks";
import { INCIDENT_TRANSITIONS, rcaUncertain, transitionRequirements } from "@/lib/incidents";
import { useI18n } from "@/lib/i18n/I18nProvider";
import { can } from "@/lib/permissions";
import { useResource } from "@/lib/useResource";

export default function IncidentDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { t } = useI18n();
  const api = useApi();
  const res = useResource(() => api.incident(id), [api, id], {
    intervalMs: 5000,
    poll: (d) => !!d && (d.rca?.status === "running" || d.status !== "closed"),
  });
  return (
    <DataState res={res} moduleName={t("nav.incidents")}>
      {(inc) => <IncidentView inc={inc} reload={res.reload} />}
    </DataState>
  );
}

function IncidentView({ inc, reload }: { inc: Incident; reload: () => void }) {
  const { t, fmtDate } = useI18n();
  const assets = useAssets();
  return (
    <>
      <PageHeader
        title={inc.title}
        subtitle={
          <span className="row">
            <StatusBadge kind="severity" value={inc.severity} />
            <StatusBadge kind="incident" value={inc.status} />
            <span className="small muted">{fmtDate(inc.created_at)}</span>
          </span>
        }
        actions={
          <Link className="btn" href="/incidents">
            {t("common.back")}
          </Link>
        }
      />
      <div className="stack">
        <div className="grid grid-2">
          <section className="card" aria-labelledby="inc-sum">
            <h2 id="inc-sum">{t("incident.summary")}</h2>
            <dl className="kv">
              <dt>{t("incident.owner")}</dt>
              <dd>{inc.owner || "—"}</dd>
              <dt>{t("incident.assets")}</dt>
              <dd>
                {(inc.asset_ids || []).length === 0
                  ? "—"
                  : inc.asset_ids.map((a, i) => (
                      <span key={a}>
                        {i > 0 ? ", " : ""}
                        <Link href={`/topology?asset=${a}`}>{assets.byId.get(a)?.name || a}</Link>
                      </span>
                    ))}
              </dd>
              {inc.description ? (
                <>
                  <dt>{t("incident.description")}</dt>
                  <dd>{inc.description}</dd>
                </>
              ) : null}
              <dt>{t("incident.triagedAt")}</dt>
              <dd>{fmtDate(inc.triaged_at)}</dd>
              <dt>{t("incident.fingerprint")}</dt>
              <dd>
                <code>{inc.fingerprint || "—"}</code>
              </dd>
              <dt>{t("incident.slo")}</dt>
              <dd>{inc.slo_impact ? <code>{JSON.stringify(inc.slo_impact)}</code> : "—"}</dd>
            </dl>
          </section>
          <TransitionPanel inc={inc} reload={reload} />
        </div>

        <RcaPanel inc={inc} reload={reload} />

        <div className="grid grid-2">
          <section className="card" aria-labelledby="inc-tl">
            <h2 id="inc-tl">{t("incident.timeline")}</h2>
            {(inc.timeline || []).length === 0 ? (
              <p className="muted">{t("common.empty")}</p>
            ) : (
              <ol className="timeline">
                {(inc.timeline || []).map((e, i) => (
                  <li key={i}>
                    <div className="t-head">
                      <Badge tone="outline">{e.kind}</Badge>
                      <span className="small muted">{fmtDate(e.at)}</span>
                      <code className="small">{e.actor}</code>
                    </div>
                    <div className="small">
                      {e.text}
                      {e.ref ? (
                        <>
                          {" "}
                          · <code>{e.ref}</code>
                        </>
                      ) : null}
                    </div>
                  </li>
                ))}
              </ol>
            )}
          </section>
          <EventsPanel inc={inc} />
        </div>

        {inc.postmortem ? (
          <section className="card" aria-labelledby="inc-pm">
            <h2 id="inc-pm">{t("incident.postmortem")}</h2>
            <dl className="kv">
              <dt>{t("postmortem.summary")}</dt>
              <dd>{inc.postmortem.summary}</dd>
              <dt>{t("postmortem.rootCause")}</dt>
              <dd>{inc.postmortem.root_cause}</dd>
              <dt>{t("postmortem.actions")}</dt>
              <dd>
                <ul style={{ margin: 0, paddingLeft: 18 }}>
                  {inc.postmortem.corrective_actions.map((a, i) => (
                    <li key={i}>{a}</li>
                  ))}
                </ul>
              </dd>
            </dl>
          </section>
        ) : null}

        <FeedbackPanel inc={inc} reload={reload} />
      </div>
    </>
  );
}

function TransitionPanel({ inc, reload }: { inc: Incident; reload: () => void }) {
  const { t, te } = useI18n();
  const api = useApi();
  const { identity } = useAuth();
  const options = INCIDENT_TRANSITIONS[inc.status] || [];
  const [to, setTo] = useState<IncidentStatus | "">(options[0] || "");
  const [reason, setReason] = useState("");
  const [evidence, setEvidence] = useState("");
  const [pm, setPm] = useState({ summary: "", root_cause: "", actions: "" });
  const [err, setErr] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  const [missing, setMissing] = useState<string[]>([]);
  const target = (to || options[0]) as IncidentStatus | undefined;
  const req = target ? transitionRequirements(inc, target) : { evidenceRequired: false, postmortemRequired: false };

  if (!can.manageIncidents(identity)) {
    return (
      <section className="card">
        <h2>{t("incident.transition")}</h2>
        <p className="muted small">{t("perm.incidents")}</p>
      </section>
    );
  }

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!target) return;
    const miss: string[] = [];
    if (!reason.trim()) miss.push("reason");
    if (req.evidenceRequired && !evidence.trim()) miss.push("evidence");
    if (req.postmortemRequired && (!pm.summary.trim() || !pm.root_cause.trim())) miss.push("postmortem");
    setMissing(miss);
    if (miss.length) return;
    setBusy(true);
    setErr(null);
    try {
      if (req.postmortemRequired) {
        await api.incidentPostmortem(inc.id, {
          summary: pm.summary.trim(),
          root_cause: pm.root_cause.trim(),
          corrective_actions: pm.actions.split("\n").map((s) => s.trim()).filter(Boolean),
        });
      }
      await api.incidentTransition(inc.id, { to: target, reason: reason.trim(), ...(evidence.trim() ? { evidence_ref: evidence.trim() } : {}) });
      setReason("");
      setEvidence("");
      reload();
    } catch (x) {
      if (isApiError(x)) setErr(x);
      else throw x;
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="card" aria-labelledby="inc-tr">
      <h2 id="inc-tr">{t("incident.transition")}</h2>
      {options.length === 0 ? (
        <p className="muted">{t("incident.noTransitions")}</p>
      ) : (
        <form onSubmit={submit} noValidate>
          <div className="field">
            <label htmlFor="tr-to">{t("incident.transitionTo")}</label>
            <select id="tr-to" value={target} onChange={(e) => setTo(e.target.value as IncidentStatus)}>
              {options.map((o) => (
                <option key={o} value={o}>
                  {te("st.incident", o)}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor="tr-reason">
              {t("change.reason")} <span className="req" aria-hidden="true">*</span>
            </label>
            <textarea id="tr-reason" value={reason} onChange={(e) => setReason(e.target.value)} aria-invalid={missing.includes("reason") || undefined} />
          </div>
          <div className="field">
            <label htmlFor="tr-ev">
              evidence_ref {req.evidenceRequired ? <span className="req" aria-hidden="true">*</span> : null}
            </label>
            <input
              id="tr-ev"
              value={evidence}
              onChange={(e) => setEvidence(e.target.value)}
              placeholder="evidence://…"
              aria-invalid={missing.includes("evidence") || undefined}
              aria-describedby="tr-ev-hint"
            />
            <span id="tr-ev-hint" className="hint">
              {req.evidenceRequired ? t("incident.evidenceRequired") : t("incident.evidenceOptional")}
            </span>
          </div>
          {req.postmortemRequired ? (
            <fieldset>
              <legend>{t("incident.postmortemRequired")}</legend>
              <div className="field">
                <label htmlFor="pm-sum">{t("postmortem.summary")}</label>
                <textarea id="pm-sum" value={pm.summary} onChange={(e) => setPm({ ...pm, summary: e.target.value })} aria-invalid={missing.includes("postmortem") || undefined} />
              </div>
              <div className="field">
                <label htmlFor="pm-rc">{t("postmortem.rootCause")}</label>
                <textarea id="pm-rc" value={pm.root_cause} onChange={(e) => setPm({ ...pm, root_cause: e.target.value })} aria-invalid={missing.includes("postmortem") || undefined} />
              </div>
              <div className="field">
                <label htmlFor="pm-act">{t("postmortem.actions")}</label>
                <textarea id="pm-act" value={pm.actions} onChange={(e) => setPm({ ...pm, actions: e.target.value })} aria-describedby="pm-act-hint" />
                <span id="pm-act-hint" className="hint">
                  {t("postmortem.actionsHint")}
                </span>
              </div>
            </fieldset>
          ) : null}
          {missing.length ? <p className="error-text" role="alert">{t("form.fillRequired")}</p> : null}
          {err ? <ProblemView error={err} /> : null}
          <button type="submit" className="btn btn-primary" disabled={busy}>
            {t("incident.applyTransition")}
          </button>
        </form>
      )}
    </section>
  );
}

function FactList({ items }: { items: HypothesisFact[] | null | undefined }) {
  if (!items || items.length === 0) return <>—</>;
  return (
    <ul className="small" style={{ margin: 0, paddingLeft: 16 }}>
      {items.map((f, i) => (
        <li key={i}>
          {f.fact}
          {f.evidence_id ? (
            <>
              {" "}
              <code>{f.evidence_id.slice(0, 12)}</code>
            </>
          ) : null}
        </li>
      ))}
    </ul>
  );
}

function checkText(c: NonNullable<Hypothesis["next_checks"]>[number]): string {
  if (typeof c === "string") return c;
  return [c.name, c.tool, c.description].filter(Boolean).join(" — ") || JSON.stringify(c);
}

function RcaPanel({ inc, reload }: { inc: Incident; reload: () => void }) {
  const { t, te, fmtNumber } = useI18n();
  const api = useApi();
  const { identity } = useAuth();
  const rca = inc.rca;
  const hyps = [...(rca?.hypotheses || [])].sort((a, b) => b.confidence - a.confidence);
  const uncertain = rcaUncertain(rca?.status, hyps);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<ApiError | null>(null);
  const [taskId, setTaskId] = useState<string | null>(null);

  const analyze = async () => {
    setBusy(true);
    setErr(null);
    try {
      const r = await api.analyzeIncident(inc.id);
      setTaskId(r.task_id);
      reload();
    } catch (x) {
      if (isApiError(x)) setErr(x);
      else throw x;
    } finally {
      setBusy(false);
    }
  };

  const uc = rca?.uncertainty_check;
  return (
    <section className="card" aria-labelledby="inc-rca">
      <div className="card-title">
        <h2 id="inc-rca">{t("incident.rca")}</h2>
        <div className="row">
          <Badge tone={rca?.status === "completed" ? "success" : rca?.status === "uncertain" ? "warning" : rca?.status === "failed" ? "danger" : "info"}>
            {te("rca", rca?.status || "not_started")}
          </Badge>
          {can.createAiTask(identity) ? (
            <button type="button" className="btn btn-primary btn-sm" onClick={analyze} disabled={busy || rca?.status === "running"}>
              <Icon name="agents" size={14} /> {t("incident.analyze")}
            </button>
          ) : null}
        </div>
      </div>
      {err ? <ProblemView error={err} /> : null}
      {taskId || rca?.task_id ? (
        <p className="small">
          {t("incident.rcaTask")}: <Link href={`/collaboration?task=${taskId || rca?.task_id}`}>{taskId || rca?.task_id}</Link>
        </p>
      ) : null}
      <Notice tone={uncertain ? "warning" : "info"} title={uncertain ? t("rca.uncertain.title") : t("rca.notice.title")}>
        <p className="small">{t("rca.notice.text")}</p>
        {uc ? <p className="small">{typeof uc === "string" ? uc : JSON.stringify(uc)}</p> : null}
      </Notice>
      {hyps.length === 0 ? (
        <p className="muted">{t("rca.noHypotheses")}</p>
      ) : (
        <TableWrap label={t("rca.hypotheses")}>
          <table data-testid="hypotheses-table">
            <caption className="visually-hidden">{t("rca.hypotheses")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("rca.cause")}</th>
                <th scope="col">{t("rca.confidence")}</th>
                <th scope="col">{t("rca.supporting")}</th>
                <th scope="col">{t("rca.refuting")}</th>
                <th scope="col">{t("rca.nextChecks")}</th>
              </tr>
            </thead>
            <tbody>
              {hyps.map((h, i) => (
                <tr key={i}>
                  <th scope="row">{h.cause}</th>
                  <td>
                    <ConfidenceBar value={h.confidence} label={t("rca.confidence")} />
                  </td>
                  <td>
                    <FactList items={h.supporting} />
                  </td>
                  <td>
                    <FactList items={h.refuting} />
                  </td>
                  <td>
                    {(h.next_checks || []).length === 0 ? (
                      "—"
                    ) : (
                      <ul className="small" style={{ margin: 0, paddingLeft: 16 }}>
                        {(h.next_checks || []).map((c, j) => (
                          <li key={j}>{checkText(c)}</li>
                        ))}
                      </ul>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
      {rca?.conclusion ? (
        <p style={{ marginTop: 12 }}>
          <strong>{t("rca.conclusion")}:</strong> {rca.conclusion}
        </p>
      ) : null}
      <p className="small muted">
        {rca?.agents?.length ? `${t("rca.agents")}: ${rca.agents.join(", ")} · ` : ""}
        {rca?.cost_usd !== undefined ? `${t("ai.cost")}: ${fmtNumber(rca.cost_usd, { style: "currency", currency: "USD", maximumFractionDigits: 4 })}` : ""}
      </p>
      {rca?.proposed_changes?.length ? (
        <p className="small">
          {t("rca.proposedChanges")}:{" "}
          {rca.proposed_changes.map((c) => (
            <Link key={c} href={`/changes/${c}`} className="mono" style={{ marginRight: 8 }}>
              {c.slice(0, 8)}…
            </Link>
          ))}
        </p>
      ) : null}
      {can.proposeChange(identity) ? (
        <p className="small">
          <Link href={`/changes/new?incident=${inc.id}${inc.asset_ids?.[0] ? `&asset=${inc.asset_ids[0]}` : ""}`}>{t("rca.proposeFix")}</Link>
        </p>
      ) : null}
    </section>
  );
}

function EventsPanel({ inc }: { inc: Incident }) {
  const { t, fmtDate } = useI18n();
  const api = useApi();
  const ids = (inc.asset_ids || []).slice(0, 5);
  const res = useResource<TelemetryEvent[]>(
    async () => {
      const lists = await Promise.all(ids.map((a) => api.events({ asset_id: a, window: "24h", limit: 50 })));
      const all = lists.flatMap((l) => l.events || []);
      const wanted = new Set(inc.event_ids || []);
      const filtered = wanted.size ? all.filter((e) => wanted.has(e.id)) : all;
      return filtered.sort((a, b) => b.at.localeCompare(a.at));
    },
    [api, ids.join(","), (inc.event_ids || []).join(",")],
  );
  return (
    <section className="card" aria-labelledby="inc-ev">
      <h2 id="inc-ev">{t("incident.events")}</h2>
      {ids.length === 0 ? (
        <p className="muted">{t("common.empty")}</p>
      ) : (
        <DataState res={res} moduleName={t("health.module.telemetry")} isEmpty={(d) => d.length === 0}>
          {(evs) => (
            <ul className="steps">
              {evs.map((e) => (
                <li key={e.id}>
                  <StatusBadge kind="severity" value={e.severity} />
                  <div className="small">
                    <strong>{e.title}</strong> <code>{e.kind}</code>
                    <div className="muted">
                      {fmtDate(e.at)}
                      {e.value !== undefined ? ` · ${e.value}` : ""}
                    </div>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </DataState>
      )}
    </section>
  );
}

function FeedbackPanel({ inc, reload }: { inc: Incident; reload: () => void }) {
  const { t } = useI18n();
  const api = useApi();
  const [correct, setCorrect] = useState<"yes" | "no" | "">("");
  const [actual, setActual] = useState("");
  const [rating, setRating] = useState(4);
  const [comment, setComment] = useState("");
  const [err, setErr] = useState<ApiError | null>(null);
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!correct) return;
    setBusy(true);
    setErr(null);
    try {
      await api.incidentFeedback(inc.id, {
        correct: correct === "yes",
        rating,
        ...(actual.trim() ? { actual_cause: actual.trim() } : {}),
        ...(comment.trim() ? { comment: comment.trim() } : {}),
      });
      setDone(true);
      reload();
    } catch (x) {
      if (isApiError(x)) setErr(x);
      else throw x;
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="card" aria-labelledby="inc-fb">
      <h2 id="inc-fb">{t("feedback.title")}</h2>
      <p className="small muted">{t("feedback.hint")}</p>
      {inc.feedback ? (
        <Notice tone="success" title={t("feedback.recorded")}>
          <p className="small">
            {inc.feedback.correct ? t("feedback.correct") : t("feedback.incorrect")} · {t("feedback.rating")}: {inc.feedback.rating}/5
            {inc.feedback.actual_cause ? ` · ${inc.feedback.actual_cause}` : ""}
          </p>
        </Notice>
      ) : null}
      {done ? (
        <p role="status" className="small">
          {t("feedback.thanks")}
        </p>
      ) : null}
      <form onSubmit={submit}>
        <fieldset>
          <legend>{t("feedback.question")}</legend>
          <label className="check" style={{ marginRight: 16 }}>
            <input type="radio" name="fb-correct" value="yes" checked={correct === "yes"} onChange={() => setCorrect("yes")} />
            {t("feedback.correct")}
          </label>
          <label className="check">
            <input type="radio" name="fb-correct" value="no" checked={correct === "no"} onChange={() => setCorrect("no")} />
            {t("feedback.incorrect")}
          </label>
        </fieldset>
        <div className="grid grid-2">
          <div className="field">
            <label htmlFor="fb-actual">{t("feedback.actualCause")}</label>
            <input id="fb-actual" value={actual} onChange={(e) => setActual(e.target.value)} />
          </div>
          <div className="field">
            <label htmlFor="fb-rating">{t("feedback.rating")}</label>
            <select id="fb-rating" value={rating} onChange={(e) => setRating(Number(e.target.value))}>
              {[1, 2, 3, 4, 5].map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
          </div>
        </div>
        <div className="field">
          <label htmlFor="fb-comment">{t("approval.comment")}</label>
          <textarea id="fb-comment" value={comment} onChange={(e) => setComment(e.target.value)} />
        </div>
        {err ? <ProblemView error={err} /> : null}
        <button type="submit" className="btn" disabled={busy || !correct}>
          {t("feedback.submit")}
        </button>
      </form>
    </section>
  );
}
