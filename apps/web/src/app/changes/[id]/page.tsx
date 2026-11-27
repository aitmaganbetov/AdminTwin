"use client";

import Link from "next/link";
import { useParams, useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";
import { Icon } from "@/components/Icon";
import {
  Badge,
  ConfidenceBar,
  DataState,
  Dialog,
  Notice,
  PageHeader,
  ProblemView,
  StatusBadge,
  TableWrap,
  YesNo,
} from "@/components/ui";
import { isApiError, type ApiError } from "@/lib/api/problem";
import type { Change, Execution, StepResult } from "@/lib/api/types";
import { useApi, useAuth } from "@/lib/auth/AuthProvider";
import { useAssets } from "@/lib/hooks";
import type { MessageKey } from "@/lib/i18n/core";
import { useI18n } from "@/lib/i18n/I18nProvider";
import { approvalEligibility, can, CANCELLABLE } from "@/lib/permissions";
import { useResource } from "@/lib/useResource";

const POLL_STATUSES = [
  "draft",
  "impact_assessed",
  "risk_assessed",
  "waiting_approval",
  "approved",
  "scheduled",
  "executing",
  "verified",
  "rolled_back",
  "compensated",
  "cancellation_pending",
  "unknown",
];

export default function ChangeDetailPage() {
  return (
    <Suspense>
      <ChangeDetail />
    </Suspense>
  );
}

function ChangeDetail() {
  const { id } = useParams<{ id: string }>();
  const search = useSearchParams();
  const created = search.get("created");
  const { t } = useI18n();
  const api = useApi();
  const res = useResource(() => api.change(id), [api, id], { intervalMs: 2000, poll: (d) => !!d && POLL_STATUSES.includes(d.status) });

  return (
    <DataState res={res}>
      {(ch) => (
        <>
          <PageHeader
            title={`${t("change.title")} · ${ch.runbook_id}`}
            subtitle={
              <span className="row">
                <StatusBadge kind="change" value={ch.status} />
                <code data-testid="change-status" className="visually-hidden">
                  {ch.status}
                </code>
                <span className="mono small">{ch.id}</span>
              </span>
            }
            actions={
              <Link className="btn" href="/changes">
                {t("common.back")}
              </Link>
            }
          />
          {created ? (
            <Notice tone={created === "202" ? "info" : "success"} title={t(created === "202" ? "change.created.202" : "change.created.201")}>
              <p className="small">HTTP {created}</p>
            </Notice>
          ) : null}
          <ChangeBody ch={ch} reload={res.reload} />
        </>
      )}
    </DataState>
  );
}

function ChangeBody({ ch, reload }: { ch: Change; reload: () => void }) {
  const { t, te, fmtDate } = useI18n();
  const assets = useAssets();
  const asset = assets.byId.get(ch.asset_id);
  return (
    <div className="stack">
      {ch.status === "manual_review" || ch.status === "unknown" ? (
        <Notice tone="danger" title={t("change.unknownOutcome")}>
          <p>{t("change.unknownOutcome.text")}</p>
        </Notice>
      ) : null}
      {ch.status === "cancellation_pending" ? (
        <Notice tone="warning" title={te("st.change", "cancellation_pending")}>
          <p>{t("change.cancellationPending.text")}</p>
        </Notice>
      ) : null}
      {ch.status === "proposed" ? (
        <Notice tone="info" title={te("st.change", "proposed")}>
          <p>{t("change.proposed.text")}</p>
        </Notice>
      ) : null}

      <div className="grid grid-2">
        <section className="card" aria-labelledby="ch-summary">
          <h2 id="ch-summary">{t("change.summary")}</h2>
          <dl className="kv">
            <dt>{t("change.runbook")}</dt>
            <dd>
              <code>
                {ch.runbook_id}@{ch.runbook_version}
              </code>
              <br />
              <span className="mono small muted">{ch.runbook_digest}</span>
            </dd>
            <dt>{t("change.risk")}</dt>
            <dd>
              <StatusBadge kind="risk" value={ch.risk} />
            </dd>
            <dt>{t("change.type")}</dt>
            <dd>{te("changeType", ch.type)}</dd>
            <dt>{t("change.asset")}</dt>
            <dd>
              {asset ? (
                <Link href={`/topology?asset=${ch.asset_id}`}>{asset.name}</Link>
              ) : (
                <code>{ch.asset_id}</code>
              )}
              {asset?.legal_hold ? (
                <>
                  {" "}
                  <Badge tone="danger">{t("asset.legalHold")}</Badge>
                </>
              ) : null}
            </dd>
            <dt>{t("change.params")}</dt>
            <dd>
              {Object.keys(ch.params || {}).length === 0 ? (
                "—"
              ) : (
                <ul className="small" style={{ margin: 0, paddingLeft: 18 }}>
                  {Object.entries(ch.params).map(([k, v]) => (
                    <li key={k}>
                      <code>{k}</code> = <code>{JSON.stringify(v)}</code>
                    </li>
                  ))}
                </ul>
              )}
            </dd>
            <dt>{t("change.reason")}</dt>
            <dd>{ch.reason}</dd>
            <dt>{t("change.dryRun")}</dt>
            <dd>
              <YesNo v={ch.dry_run} />
            </dd>
            <dt>{t("change.author")}</dt>
            <dd>
              {ch.author_id} <span className="muted small">({te("actorKind", ch.author_kind)})</span>
            </dd>
            {ch.incident_id ? (
              <>
                <dt>{t("change.incident")}</dt>
                <dd>
                  <Link href={`/incidents/${ch.incident_id}`}>{ch.incident_id}</Link>
                </dd>
              </>
            ) : null}
            <dt>{t("change.pir")}</dt>
            <dd>
              <YesNo v={ch.pir_required} />
              {ch.pir_due_at ? ` · ${t("change.pirDue", { at: fmtDate(ch.pir_due_at) })}` : ""}
            </dd>
            <dt>{t("common.created")}</dt>
            <dd>{fmtDate(ch.created_at)}</dd>
            <dt>{t("common.updated")}</dt>
            <dd>{fmtDate(ch.updated_at)}</dd>
          </dl>
        </section>

        <ApprovalPanel ch={ch} reload={reload} />
      </div>

      <div className="grid grid-2">
        <PolicyPanel ch={ch} />
        <ImpactPanel ch={ch} />
      </div>

      <section className="card" aria-labelledby="ch-exec">
        <h2 id="ch-exec">{t("change.executions")}</h2>
        {ch.executions.length === 0 ? (
          <p className="muted">{t("change.noExecutions")}</p>
        ) : (
          ch.executions.map((ex) => <ExecutionView key={ex.id} ex={ex} />)
        )}
      </section>

      {ch.follow_up_proposals && ch.follow_up_proposals.length > 0 ? (
        <section className="card" aria-labelledby="ch-fu">
          <h2 id="ch-fu">{t("change.followUps")}</h2>
          <p className="small muted">{t("change.followUps.hint")}</p>
          <ul>
            {ch.follow_up_proposals.map((p, i) => (
              <li key={i}>
                <code>{p}</code>{" "}
                <Link className="small" href={`/changes/new?runbook=${encodeURIComponent(p)}&asset=${ch.asset_id}`}>
                  {t("change.followUps.create")}
                </Link>
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      <section className="card" aria-labelledby="ch-trans">
        <h2 id="ch-trans">{t("change.transitions")}</h2>
        <ol className="timeline" data-testid="transitions">
          {ch.transitions.map((tr, i) => (
            <li key={i}>
              <div className="t-head">
                <StatusBadge kind="change" value={tr.from} />
                <span aria-hidden="true">→</span>
                <span className="visually-hidden">{t("common.to")}</span>
                <StatusBadge kind="change" value={tr.to} />
                <span className="small muted">{fmtDate(tr.at)}</span>
              </div>
              <div className="small">
                <code>{tr.actor}</code> — {tr.reason}
                {tr.evidence_ref ? (
                  <>
                    {" "}
                    · {t("change.evidence")}: <code>{tr.evidence_ref}</code>
                  </>
                ) : null}
              </div>
            </li>
          ))}
        </ol>
        <p className="small" style={{ marginTop: 12 }}>
          <Link href={`/audit?object=${ch.id}`}>{t("change.openAudit")}</Link>
        </p>
      </section>
    </div>
  );
}

function ApprovalPanel({ ch, reload }: { ch: Change; reload: () => void }) {
  const { t, te, fmtDate } = useI18n();
  const api = useApi();
  const { identity } = useAuth();
  const [comment, setComment] = useState("");
  const [busy, setBusy] = useState<"approve" | "reject" | "cancel" | null>(null);
  const [err, setErr] = useState<ApiError | null>(null);
  const [ok, setOk] = useState<string | null>(null);
  const [cancelOpen, setCancelOpen] = useState(false);
  const [cancelReason, setCancelReason] = useState("");
  const elig = approvalEligibility(identity, ch);
  const approvals = ch.decisions.filter((d) => d.verdict === "approve").length;
  const required = ch.policy?.required_approvals ?? 0;

  const decide = async (v: "approve" | "reject") => {
    setBusy(v);
    setErr(null);
    setOk(null);
    try {
      await api.decide(ch.id, v, comment.trim() || undefined);
      setOk(v === "approve" ? t("approval.done.approve") : t("approval.done.reject"));
      setComment("");
      reload();
    } catch (e) {
      if (isApiError(e)) setErr(e);
      else throw e;
    } finally {
      setBusy(null);
    }
  };

  const cancel = async () => {
    setBusy("cancel");
    setErr(null);
    try {
      await api.cancelChange(ch.id, cancelReason.trim() || undefined);
      setOk(t("change.cancel.done"));
      setCancelOpen(false);
      setCancelReason("");
      reload();
    } catch (e) {
      if (isApiError(e)) {
        setErr(e);
        setCancelOpen(false);
      } else throw e;
    } finally {
      setBusy(null);
    }
  };

  return (
    <section className="card" aria-labelledby="ch-approval" data-testid="approval-panel">
      <h2 id="ch-approval">{t("approval.title")}</h2>
      {ch.policy?.outcome === "requires_approval" ? (
        <p>
          {t("approval.progress", { n: approvals, required })}
          {ch.policy.approver_roles?.length ? (
            <>
              <br />
              <span className="small muted">
                {t("approval.roles")}: {ch.policy.approver_roles.map((r) => t(`role.${r}` as MessageKey)).join(", ")}
                {ch.policy.engineer_scope ? ` · ${t("approval.engineerScope", { scope: ch.policy.engineer_scope })}` : ""}
              </span>
            </>
          ) : null}
        </p>
      ) : (
        <p className="muted small">{t("approval.notRequired", { outcome: te("outcome", ch.policy?.outcome) })}</p>
      )}

      {ch.decisions.length > 0 ? (
        <ul className="steps" aria-label={t("approval.decisions")}>
          {ch.decisions.map((d, i) => (
            <li key={i}>
              <span className={d.verdict === "approve" ? "step-ok" : "step-fail"}>
                <Icon name={d.verdict === "approve" ? "check" : "x"} label={te("verdict", d.verdict)} />
              </span>
              <div className="small">
                <strong>{d.actor_id}</strong> · {te("verdict", d.verdict)} · {fmtDate(d.at)}
                {d.comment ? <div>«{d.comment}»</div> : null}
              </div>
            </li>
          ))}
        </ul>
      ) : null}

      {ch.status === "waiting_approval" ? (
        elig.canDecide ? (
          <div style={{ marginTop: 12 }}>
            {elig.isAuthor ? (
              <Notice tone="warning" title={t("approval.authorWarning.title")}>
                <p className="small">{t("approval.authorWarning")}</p>
              </Notice>
            ) : null}
            <div className="field">
              <label htmlFor="approval-comment">{t("approval.comment")}</label>
              <textarea id="approval-comment" value={comment} onChange={(e) => setComment(e.target.value)} data-testid="approval-comment" />
            </div>
            <div className="row">
              <button type="button" className="btn btn-primary" disabled={!!busy} onClick={() => decide("approve")} data-testid="approve">
                <Icon name="check" /> {t("approval.approve")}
              </button>
              <button type="button" className="btn btn-danger" disabled={!!busy} onClick={() => decide("reject")} data-testid="reject">
                <Icon name="x" /> {t("approval.reject")}
              </button>
            </div>
          </div>
        ) : (
          <Notice tone="info" title={t("approval.cannotDecide")}>
            <p className="small">{t(`approval.block.${elig.block ?? "no-role"}` as MessageKey)}</p>
          </Notice>
        )
      ) : null}

      {ok ? (
        <div role="status" className="notice tone-success" style={{ marginTop: 12 }}>
          <Icon name="check" />
          <div className="notice-body">{ok}</div>
        </div>
      ) : null}
      {err ? (
        <div style={{ marginTop: 12 }} data-testid="approval-error">
          <ProblemView error={err} />
        </div>
      ) : null}

      {can.cancelChange(identity) && CANCELLABLE.includes(ch.status) ? (
        <div style={{ marginTop: 12 }}>
          <button type="button" className="btn" onClick={() => setCancelOpen(true)} data-testid="cancel-change">
            <Icon name="stop" /> {ch.status === "executing" ? t("change.cancel.executing") : t("change.cancel")}
          </button>
        </div>
      ) : null}
      <Dialog
        open={cancelOpen}
        title={t("change.cancel.title")}
        onClose={() => setCancelOpen(false)}
        actions={
          <>
            <button type="button" className="btn" onClick={() => setCancelOpen(false)}>
              {t("common.close")}
            </button>
            <button type="button" className="btn btn-danger" disabled={busy === "cancel"} onClick={cancel} data-testid="cancel-confirm">
              {t("change.cancel.confirm")}
            </button>
          </>
        }
      >
        <p className="small">{ch.status === "executing" ? t("change.cancel.executingHint") : t("change.cancel.hint")}</p>
        <div className="field">
          <label htmlFor="cancel-reason">{t("change.cancel.reason")}</label>
          <textarea id="cancel-reason" value={cancelReason} onChange={(e) => setCancelReason(e.target.value)} />
        </div>
      </Dialog>
    </section>
  );
}

function PolicyPanel({ ch }: { ch: Change }) {
  const { t, te } = useI18n();
  const p = ch.policy;
  return (
    <section className="card" aria-labelledby="ch-policy">
      <h2 id="ch-policy">{t("policy.title")}</h2>
      {!p ? (
        <p className="muted">—</p>
      ) : (
        <>
          <dl className="kv">
            <dt>{t("policy.outcome")}</dt>
            <dd>
              <Badge tone={p.outcome === "auto_approved" ? "success" : p.outcome === "requires_approval" ? "warning" : "info"}>
                {te("outcome", p.outcome)}
              </Badge>
            </dd>
            <dt>{t("policy.requiredApprovals")}</dt>
            <dd>{p.required_approvals}</dd>
            <dt>{t("policy.maintenanceWindow")}</dt>
            <dd>
              <YesNo v={p.requires_maintenance_window} />
            </dd>
            <dt>{t("policy.preflightMandatory")}</dt>
            <dd>
              <YesNo v={p.preflight_mandatory} />
            </dd>
            <dt>{t("policy.breakGlass")}</dt>
            <dd>
              <YesNo v={p.break_glass} />
            </dd>
            <dt>{t("policy.id")}</dt>
            <dd>
              <code>{p.policy_id}</code>
            </dd>
          </dl>
          <h3 style={{ marginTop: 12 }}>{t("policy.reasons")}</h3>
          <ol className="small">
            {(p.reasons || []).map((r, i) => (
              <li key={i}>{r}</li>
            ))}
          </ol>
        </>
      )}
    </section>
  );
}

function ImpactPanel({ ch }: { ch: Change }) {
  const { t } = useI18n();
  const imp = ch.impact;
  const br = imp?.blast_radius || [];
  return (
    <section className="card" aria-labelledby="ch-impact">
      <h2 id="ch-impact">{t("impact.title")}</h2>
      {!imp ? (
        <p className="muted">—</p>
      ) : (
        <>
          <dl className="kv">
            <dt>{t("impact.tiers")}</dt>
            <dd>{(imp.affected_service_tiers || []).map((x) => `tier ${x}`).join(", ") || "—"}</dd>
            <dt>{t("impact.maxCriticality")}</dt>
            <dd>{imp.max_criticality || "—"}</dd>
            <dt>{t("impact.inWindow")}</dt>
            <dd>
              <YesNo v={imp.in_maintenance_window} />
            </dd>
          </dl>
          <h3 style={{ marginTop: 12 }}>{t("impact.blastRadius", { n: br.length })}</h3>
          {br.length === 0 ? (
            <p className="muted small">{t("impact.none")}</p>
          ) : (
            <TableWrap label={t("impact.blastRadius", { n: br.length })}>
              <table>
                <thead>
                  <tr>
                    <th scope="col">{t("asset.name")}</th>
                    <th scope="col">{t("impact.depth")}</th>
                    <th scope="col">{t("asset.tier")}</th>
                    <th scope="col">{t("asset.criticality")}</th>
                    <th scope="col">{t("topology.confidence")}</th>
                  </tr>
                </thead>
                <tbody>
                  {br.map((b) => (
                    <tr key={b.asset_id}>
                      <td className="nowrap">
                        <Link href={`/topology?asset=${b.asset_id}`}>{b.name}</Link>
                      </td>
                      <td>{b.depth}</td>
                      <td>{b.service_tier ?? "—"}</td>
                      <td>{b.criticality}</td>
                      <td>
                        <ConfidenceBar value={b.confidence} label={t("topology.confidence")} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          )}
        </>
      )}
    </section>
  );
}

const PHASES = ["preflight", "execute", "post_check", "compensation"];

function ExecutionView({ ex }: { ex: Execution }) {
  const { t, te, fmtDate } = useI18n();
  const { identity } = useAuth();
  const r = ex.result;
  const steps = r?.steps || [];
  const [evOpen, setEvOpen] = useState(false);
  return (
    <article className="card" style={{ boxShadow: "none" }} aria-label={`${t("change.execution")} ${ex.id}`}>
      <div className="card-title">
        <h3>
          {t("change.execution")} <code className="small">{ex.id.slice(0, 8)}</code>
        </h3>
        <StatusBadge kind="execution" value={ex.status} />
      </div>
      <p className="small muted">
        {t("common.started")}: {fmtDate(ex.started_at)}
        {r?.finished_at ? ` · ${t("common.finished")}: ${fmtDate(r.finished_at)}` : ""}
        {r ? ` · exit ${r.exit_code}` : ""}
      </p>
      <div className="grid grid-2">
        {PHASES.map((ph) => {
          const ps = steps.filter((s) => s.phase === ph);
          if (ps.length === 0) return null;
          return (
            <div key={ph}>
              <h4 style={{ margin: "4px 0" }}>{te("phase", ph)}</h4>
              <ul className="steps">
                {ps.map((s, i) => (
                  <StepRow key={i} s={s} />
                ))}
              </ul>
            </div>
          );
        })}
      </div>
      {r?.compensation?.length ? (
        <p className="small">
          {t("runbook.compensation")}: {r.compensation.map((c) => <code key={c}>{c} </code>)}
        </p>
      ) : null}
      {r?.stdout ? (
        <details>
          <summary>stdout</summary>
          <pre className="code">{r.stdout}</pre>
        </details>
      ) : null}
      {r?.stderr ? (
        <details>
          <summary>stderr</summary>
          <pre className="code">{r.stderr}</pre>
        </details>
      ) : null}
      {r?.evidence_id ? (
        <p className="small" style={{ marginTop: 8 }}>
          {t("change.evidence")}: <code data-testid="evidence-id">{r.evidence_id}</code>
          {r.digest ? (
            <>
              {" "}
              · <span className="mono">{r.digest}</span>
            </>
          ) : null}
          {can.viewEvidence(identity) ? (
            <>
              {" "}
              <button type="button" className="btn btn-sm" onClick={() => setEvOpen(true)}>
                {t("evidence.open")}
              </button>
            </>
          ) : null}
        </p>
      ) : null}
      {evOpen && r?.evidence_id ? <EvidenceDialog id={r.evidence_id} onClose={() => setEvOpen(false)} /> : null}
    </article>
  );
}

function StepRow({ s }: { s: StepResult }) {
  const { t } = useI18n();
  const cls = s.skipped ? "step-skip" : s.ok ? "step-ok" : "step-fail";
  const label = s.skipped ? t("step.skipped") : s.ok ? t("step.ok") : t("step.failed");
  return (
    <li>
      <span className={cls}>
        <Icon name={s.skipped ? "minus" : s.ok ? "check" : "x"} label={label} />
      </span>
      <div className="small">
        <code>{s.name}</code>
        {s.detail ? <span className="muted"> — {s.detail}</span> : null}
      </div>
    </li>
  );
}

function EvidenceDialog({ id, onClose }: { id: string; onClose: () => void }) {
  const { t } = useI18n();
  const api = useApi();
  const [purpose, setPurpose] = useState("");
  const [data, setData] = useState<unknown>(null);
  const [err, setErr] = useState<ApiError | null>(null);
  const load = async () => {
    setErr(null);
    try {
      setData(await api.evidence(id, purpose.trim()));
    } catch (e) {
      if (isApiError(e)) setErr(e);
      else throw e;
    }
  };
  return (
    <Dialog
      open
      title={t("evidence.title")}
      onClose={onClose}
      actions={
        <>
          <button type="button" className="btn" onClick={onClose}>
            {t("common.close")}
          </button>
          <button type="button" className="btn btn-primary" disabled={!purpose.trim()} onClick={load}>
            {t("evidence.load")}
          </button>
        </>
      }
    >
      <p className="small">{t("evidence.purposeHint")}</p>
      <div className="field">
        <label htmlFor="ev-purpose">
          {t("evidence.purpose")} <span className="req" aria-hidden="true">*</span>
        </label>
        <input id="ev-purpose" value={purpose} onChange={(e) => setPurpose(e.target.value)} required />
      </div>
      {err ? <ProblemView error={err} /> : null}
      {data ? <pre className="code">{JSON.stringify(data, null, 2)}</pre> : null}
    </Dialog>
  );
}
