"use client";

import Link from "next/link";
import { useMemo } from "react";
import { useKillSwitch } from "@/components/AppShell";
import { Icon } from "@/components/Icon";
import { Badge, DataState, Empty, PageHeader, ShortId, StatusBadge, TableWrap } from "@/components/ui";
import { SEVERITIES, type Change, type Execution } from "@/lib/api/types";
import { useApi, useAuth } from "@/lib/auth/AuthProvider";
import { useAssets } from "@/lib/hooks";
import type { MessageKey } from "@/lib/i18n/core";
import { useI18n } from "@/lib/i18n/I18nProvider";
import { can } from "@/lib/permissions";
import { useResource } from "@/lib/useResource";

const OPEN_INCIDENT = ["new", "triaged", "investigating", "mitigated", "reopened"];
const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const ONBOARDING: MessageKey[] = [
  "onboarding.tenant",
  "onboarding.sso",
  "onboarding.ai",
  "onboarding.dataPolicy",
  "onboarding.compliance",
  "onboarding.scope",
  "onboarding.vault",
  "onboarding.discovery",
  "onboarding.confirm",
  "onboarding.mode",
  "onboarding.demo",
];

/** Командный центр: сначала то, что требует внимания (kill switch, согласования, инциденты), затем история. */
export default function CommandCenterPage() {
  const { t, fmtDate } = useI18n();
  const api = useApi();
  const { identity } = useAuth();
  const kill = useKillSwitch();
  const assets = useAssets();
  const changes = useResource(() => api.changes(), [api], { intervalMs: 10000 });
  const incidents = useResource(() => api.incidents(), [api], { intervalMs: 20000 });
  const health = useResource(() => api.health(), [api]);

  const waiting = useMemo(() => (changes.data?.items || []).filter((c) => c.status === "waiting_approval"), [changes.data]);
  const recentExec = useMemo(() => {
    const out: { ex: Execution; ch: Change }[] = [];
    for (const ch of changes.data?.items || []) for (const ex of ch.executions || []) out.push({ ex, ch });
    return out.sort((a, b) => b.ex.started_at.localeCompare(a.ex.started_at)).slice(0, 8);
  }, [changes.data]);
  const openIncidents = useMemo(
    () =>
      (incidents.data?.items || [])
        .filter((i) => OPEN_INCIDENT.includes(i.status))
        .sort((a, b) => (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9) || b.created_at.localeCompare(a.created_at)),
    [incidents.data],
  );
  const bySeverity = useMemo(() => {
    const m: Record<string, number> = {};
    for (const i of openIncidents) m[i.severity] = (m[i.severity] || 0) + 1;
    return m;
  }, [openIncidents]);

  const ks = kill?.data;
  const killActive = !!ks && (ks.tenant.active || ks.platform.active);
  const healthOk = health.data?.status === "ok";

  return (
    <>
      <PageHeader
        title={t("nav.commandCenter")}
        subtitle={t("cc.subtitle", { actor: identity?.actorId || "" })}
        actions={
          can.proposeChange(identity) ? (
            <Link href="/changes/new" className="btn btn-primary">
              {t("changes.new")} <Icon name="plus" />
            </Link>
          ) : null
        }
      />

      <div className="grid grid-4" style={{ marginBottom: 16 }}>
        <Link href="/settings" className={`card kpi${killActive ? " card-attention" : ""}`} data-testid="cc-kill-tile">
          <h2 id="cc-kill" className="stat-label">
            {t("cc.killSwitch")}
          </h2>
          {kill?.error ? (
            <p className="error-text">{kill.error.problem.title || t("problem.network")}</p>
          ) : ks ? (
            <>
              <p className="stat" data-testid="cc-kill-state">
                {killActive ? t("kill.state.active") : t("kill.state.inactive")}
              </p>
              <div className="kpi-foot small">
                <Badge tone={killActive ? "critical" : "success"} withIcon>
                  {ks.platform.active ? t("kill.scope.platform") : t("kill.scope.tenant")}
                </Badge>
                {ks.tenant.active && ks.tenant.reason ? <span>{ks.tenant.reason}</span> : null}
              </div>
            </>
          ) : (
            <p className="stat">…</p>
          )}
        </Link>
        <Link href="/changes?status=waiting_approval" className={`card kpi${waiting.length > 0 ? " card-attention" : ""}`}>
          <h2 id="cc-wait" className="stat-label">
            {t("cc.waitingApproval")}
          </h2>
          <p className="stat">{changes.data ? waiting.length : "…"}</p>
          <p className="kpi-foot small">{t("cc.openApprovals")}</p>
        </Link>
        <Link href="/incidents" className={`card kpi${openIncidents.length > 0 ? " card-attention" : ""}`}>
          <h2 id="cc-inc" className="stat-label">
            {t("cc.openIncidents")}
          </h2>
          {incidents.error?.kind === "module-unavailable" ? (
            <p className="small muted">{t("module.unavailable.title")}</p>
          ) : (
            <>
              <p className="stat">{incidents.data ? openIncidents.length : "…"}</p>
              <div className="kpi-foot small">
                {SEVERITIES.filter((s) => bySeverity[s]).map((s) => (
                  <span key={s} className="row" style={{ gap: 4 }}>
                    <StatusBadge kind="severity" value={s} /> {bySeverity[s]}
                  </span>
                ))}
                {incidents.data && openIncidents.length === 0 ? t("cc.noOpenIncidents") : null}
              </div>
            </>
          )}
        </Link>
        <Link href="/health" className="card kpi">
          <h2 id="cc-health" className="stat-label">
            {t("nav.health")}
          </h2>
          <p className="stat">{health.data ? (healthOk ? t("health.overall.ok") : t("health.overall.degraded")) : "…"}</p>
          <div className="kpi-foot small">
            {health.data ? (
              <Badge tone={healthOk ? "success" : "danger"} withIcon>
                {health.data.status}
              </Badge>
            ) : null}
            <span>
              {t("cc.assets")}: {assets.data ? assets.list.length : "…"}
            </span>
          </div>
        </Link>
      </div>

      <div className="grid grid-2">
        <section className="card" aria-labelledby="cc-incidents">
          <div className="card-title">
            <h2 id="cc-incidents">{t("cc.openIncidents")}</h2>
            <Link href="/incidents">{t("common.viewAll")}</Link>
          </div>
          <DataState res={incidents} moduleName={t("nav.incidents")}>
            {() =>
              openIncidents.length === 0 ? (
                <Empty text={t("cc.noOpenIncidents")} />
              ) : (
                <TableWrap label={t("cc.openIncidents")}>
                  <table data-testid="cc-incidents">
                    <thead>
                      <tr>
                        <th scope="col" className="col-main">
                          {t("incident.title")}
                        </th>
                        <th scope="col">{t("incident.severity")}</th>
                        <th scope="col">{t("incident.status")}</th>
                        <th scope="col">{t("incident.owner")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {openIncidents.slice(0, 6).map((i) => (
                        <tr key={i.id}>
                          <td>
                            <Link href={`/incidents/${i.id}`}>{i.title}</Link>
                            <span className="cell-sub">{fmtDate(i.created_at)}</span>
                          </td>
                          <td>
                            <StatusBadge kind="severity" value={i.severity} />
                          </td>
                          <td>
                            <StatusBadge kind="incident" value={i.status} />
                          </td>
                          <td>{i.owner || "—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </TableWrap>
              )
            }
          </DataState>
        </section>

        <section className="card" aria-labelledby="cc-approvals">
          <div className="card-title">
            <h2 id="cc-approvals">{t("cc.waitingApproval")}</h2>
            <Link href="/changes?status=waiting_approval">{t("common.viewAll")}</Link>
          </div>
          <DataState res={changes} isEmpty={() => waiting.length === 0} emptyText={t("cc.noWaiting")}>
            {() => (
              <TableWrap label={t("cc.waitingApproval")}>
                <table data-testid="cc-approvals">
                  <thead>
                    <tr>
                      <th scope="col">{t("change.runbook")}</th>
                      <th scope="col">{t("change.risk")}</th>
                      <th scope="col">{t("change.author")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {waiting.slice(0, 6).map((c) => (
                      <tr key={c.id}>
                        <td>
                          <Link href={`/changes/${c.id}`}>{c.runbook_id}</Link>
                          <span className="cell-sub">{assets.byId.get(c.asset_id)?.name || c.asset_id}</span>
                        </td>
                        <td>
                          <StatusBadge kind="risk" value={c.risk} />
                        </td>
                        <td>
                          {c.author_id}
                          <span className="cell-sub">{fmtDate(c.created_at)}</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </TableWrap>
            )}
          </DataState>
        </section>
      </div>

      <section className="card" aria-labelledby="cc-exec" style={{ marginTop: 16 }}>
        <div className="card-title">
          <h2 id="cc-exec">{t("cc.recentExecutions")}</h2>
          <Link href="/changes">{t("common.viewAll")}</Link>
        </div>
        <DataState res={changes} isEmpty={() => recentExec.length === 0} emptyText={t("cc.noExecutions")}>
          {() => (
            <TableWrap label={t("cc.recentExecutions")}>
              <table>
                <thead>
                  <tr>
                    <th scope="col">{t("common.time")}</th>
                    <th scope="col">{t("change.runbook")}</th>
                    <th scope="col">{t("change.asset")}</th>
                    <th scope="col">{t("change.execution")}</th>
                    <th scope="col">{t("change.status")}</th>
                    <th scope="col">{t("change.evidence")}</th>
                  </tr>
                </thead>
                <tbody>
                  {recentExec.map(({ ex, ch }) => (
                    <tr key={ex.id}>
                      <td className="nowrap">{fmtDate(ex.started_at)}</td>
                      <td>
                        <Link href={`/changes/${ch.id}`}>{ex.runbook_id}</Link>
                      </td>
                      <td>{assets.byId.get(ex.asset_id)?.name || ex.asset_id}</td>
                      <td>
                        <StatusBadge kind="execution" value={ex.status} />
                      </td>
                      <td>
                        <StatusBadge kind="change" value={ch.status} />
                      </td>
                      <td>
                        <ShortId id={ex.result?.evidence_id} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          )}
        </DataState>
      </section>

      <details className="card" style={{ marginTop: 16 }} data-testid="cc-onboarding">
        <summary>
          {t("onboarding.title")} <span className="small muted">— {t("onboarding.goal")}</span>
        </summary>
        <ol className="checklist" style={{ marginTop: 8 }}>
          {ONBOARDING.map((k, n) => (
            <li key={k}>
              <span className="n">{n + 1}</span>
              <span>{t(k)}</span>
            </li>
          ))}
        </ol>
      </details>
    </>
  );
}
