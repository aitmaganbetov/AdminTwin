"use client";

import Link from "next/link";
import { useMemo } from "react";
import { useKillSwitch } from "@/components/AppShell";
import { Badge, DataState, Empty, PageHeader, ProblemView, StatusBadge, TableWrap } from "@/components/ui";
import { SEVERITIES, type Change, type Execution } from "@/lib/api/types";
import { useApi, useAuth } from "@/lib/auth/AuthProvider";
import { useAssets } from "@/lib/hooks";
import type { MessageKey } from "@/lib/i18n/core";
import { useI18n } from "@/lib/i18n/I18nProvider";
import { useResource } from "@/lib/useResource";

const OPEN_INCIDENT = ["new", "triaged", "investigating", "mitigated", "reopened"];

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
  const bySeverity = useMemo(() => {
    const m: Record<string, number> = {};
    for (const i of incidents.data?.items || []) if (OPEN_INCIDENT.includes(i.status)) m[i.severity] = (m[i.severity] || 0) + 1;
    return m;
  }, [incidents.data]);

  const ks = kill?.data;
  return (
    <>
      <PageHeader title={t("nav.commandCenter")} subtitle={t("cc.subtitle", { actor: identity?.actorId || "" })} />

      <div className="grid grid-4" style={{ marginBottom: 16 }}>
        <section className="card" aria-labelledby="cc-kill">
          <h2 id="cc-kill" className="stat-label">
            {t("cc.killSwitch")}
          </h2>
          {kill?.error ? (
            <ProblemView error={kill.error} />
          ) : ks ? (
            <>
              <p className="stat" data-testid="cc-kill-state">
                {ks.tenant.active || ks.platform.active ? t("kill.state.active") : t("kill.state.inactive")}
              </p>
              <p className="small muted">
                {ks.platform.active ? t("kill.scope.platform") : t("kill.scope.tenant")}
                {ks.tenant.active && ks.tenant.reason ? ` — ${ks.tenant.reason}` : ""}
              </p>
              <Link href="/settings" className="small">
                {t("kill.banner.manage")}
              </Link>
            </>
          ) : (
            <p className="muted">{t("common.loading")}</p>
          )}
        </section>
        <section className="card" aria-labelledby="cc-wait">
          <h2 id="cc-wait" className="stat-label">
            {t("cc.waitingApproval")}
          </h2>
          <p className="stat">{changes.data ? waiting.length : "…"}</p>
          <Link href="/changes?status=waiting_approval" className="small">
            {t("cc.openApprovals")}
          </Link>
        </section>
        <section className="card" aria-labelledby="cc-inc">
          <h2 id="cc-inc" className="stat-label">
            {t("cc.openIncidents")}
          </h2>
          {incidents.error?.kind === "module-unavailable" ? (
            <p className="small muted">{t("module.unavailable.title")}</p>
          ) : (
            <>
              <p className="stat">{incidents.data ? Object.values(bySeverity).reduce((a, b) => a + b, 0) : "…"}</p>
              <div className="row">
                {SEVERITIES.filter((s) => bySeverity[s]).map((s) => (
                  <span key={s} className="row" style={{ gap: 4 }}>
                    <StatusBadge kind="severity" value={s} /> <span className="small">{bySeverity[s]}</span>
                  </span>
                ))}
              </div>
            </>
          )}
        </section>
        <section className="card" aria-labelledby="cc-health">
          <h2 id="cc-health" className="stat-label">
            {t("nav.health")}
          </h2>
          <p className="stat">{health.data ? <Badge tone={health.data.status === "ok" ? "success" : "danger"}>{health.data.status}</Badge> : "…"}</p>
          <p className="small muted">
            {t("cc.assets")}: {assets.data ? assets.list.length : "…"}
          </p>
        </section>
      </div>

      <div className="grid grid-2">
        <section className="card" aria-labelledby="cc-incidents">
          <div className="card-title">
            <h2 id="cc-incidents">{t("cc.incidentsBySeverity")}</h2>
            <Link href="/incidents" className="small">
              {t("common.viewAll")}
            </Link>
          </div>
          <DataState res={incidents} moduleName={t("nav.incidents")}>
            {(d) => {
              const open = d.items.filter((i) => OPEN_INCIDENT.includes(i.status));
              if (open.length === 0) return <Empty text={t("cc.noOpenIncidents")} />;
              return (
                <TableWrap label={t("cc.incidentsBySeverity")}>
                  <table>
                    <thead>
                      <tr>
                        <th scope="col">{t("incident.severity")}</th>
                        {SEVERITIES.map((s) => (
                          <th scope="col" key={s}>
                            {t(`st.severity.${s}` as MessageKey)}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      <tr>
                        <th scope="row">{t("cc.open")}</th>
                        {SEVERITIES.map((s) => (
                          <td key={s}>{bySeverity[s] || 0}</td>
                        ))}
                      </tr>
                    </tbody>
                  </table>
                </TableWrap>
              );
            }}
          </DataState>
        </section>

        <section className="card" aria-labelledby="cc-approvals">
          <div className="card-title">
            <h2 id="cc-approvals">{t("cc.waitingApproval")}</h2>
            <Link href="/changes?status=waiting_approval" className="small">
              {t("common.viewAll")}
            </Link>
          </div>
          <DataState res={changes} isEmpty={() => waiting.length === 0} emptyText={t("cc.noWaiting")}>
            {() => (
              <ul className="steps steps-wide">
                {waiting.slice(0, 6).map((c) => (
                  <li key={c.id}>
                    <StatusBadge kind="risk" value={c.risk} />
                    <div>
                      <Link href={`/changes/${c.id}`}>{c.runbook_id}</Link>{" "}
                      <span className="muted small">
                        {assets.byId.get(c.asset_id)?.name || c.asset_id} · {c.author_id} · {fmtDate(c.created_at)}
                      </span>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </DataState>
        </section>
      </div>

      <section className="card" aria-labelledby="cc-exec" style={{ marginTop: 16 }}>
        <div className="card-title">
          <h2 id="cc-exec">{t("cc.recentExecutions")}</h2>
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
                      <td>{ex.result?.evidence_id ? <code>{ex.result.evidence_id.slice(0, 8)}…</code> : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          )}
        </DataState>
      </section>

      <section className="card" aria-labelledby="cc-onb" style={{ marginTop: 16 }}>
        <div className="card-title">
          <h2 id="cc-onb">{t("onboarding.title")}</h2>
          <span className="small muted">{t("onboarding.goal")}</span>
        </div>
        <ol className="small">
          {(
            [
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
            ] as MessageKey[]
          ).map((k) => (
            <li key={k}>{t(k)}</li>
          ))}
        </ol>
      </section>
    </>
  );
}
