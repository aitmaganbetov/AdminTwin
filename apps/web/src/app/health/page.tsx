"use client";

import { Icon } from "@/components/Icon";
import { Badge, DataState, PageHeader, TableWrap } from "@/components/ui";
import { isApiError } from "@/lib/api/problem";
import { useApi } from "@/lib/auth/AuthProvider";
import type { MessageKey } from "@/lib/i18n/core";
import { useI18n } from "@/lib/i18n/I18nProvider";
import { useResource } from "@/lib/useResource";

type Probe = { key: MessageKey; path: string; run: () => Promise<unknown> };
type ProbeResult = { key: MessageKey; path: string; state: "ok" | "unavailable" | "error"; detail?: string };

export default function HealthPage() {
  const { t, fmtNumber } = useI18n();
  const api = useApi();
  const health = useResource(() => api.health(), [api], { intervalMs: 15000 });

  const probes: Probe[] = [
    { key: "nav.incidents", path: "/api/v1/incidents", run: () => api.incidents() },
    { key: "health.module.telemetry", path: "/api/v1/events", run: () => api.events({ window: "15m", limit: 1 }) },
    { key: "health.module.discovery", path: "/api/v1/discovery/scopes", run: () => api.discoveryScopes() },
    { key: "health.module.agents", path: "/api/v1/agents", run: () => api.agents() },
    { key: "health.module.agentTasks", path: "/api/v1/agent-tasks", run: () => api.agentTasks() },
    { key: "health.module.ai", path: "/api/v1/ai/providers", run: () => api.aiProviders() },
  ];
  const modules = useResource<ProbeResult[]>(
    () =>
      Promise.all(
        probes.map(async (p): Promise<ProbeResult> => {
          try {
            await p.run();
            return { key: p.key, path: p.path, state: "ok" };
          } catch (e) {
            if (isApiError(e) && e.kind === "module-unavailable") return { key: p.key, path: p.path, state: "unavailable" };
            return { key: p.key, path: p.path, state: "error", detail: isApiError(e) ? `${e.status} ${e.problem.title}` : String(e) };
          }
        }),
      ),
    [api],
  );

  return (
    <>
      <PageHeader
        title={t("nav.health")}
        subtitle={t("health.subtitle")}
        actions={
          <button type="button" className="btn" onClick={() => { health.reload(); modules.reload(); }}>
            <Icon name="refresh" /> {t("common.refresh")}
          </button>
        }
      />
      <div className="grid grid-2">
        <section className="card" aria-labelledby="h-core">
          <h2 id="h-core">{t("health.core")}</h2>
          <DataState res={health}>
            {(h) => (
              <>
                <dl className="kv">
                  <dt>{t("change.status")}</dt>
                  <dd>
                    <Badge tone={h.status === "ok" ? "success" : "danger"}>{h.status}</Badge>
                  </dd>
                  <dt>{t("health.version")}</dt>
                  <dd>
                    <code>{h.version || "—"}</code>
                  </dd>
                  <dt>{t("health.uptime")}</dt>
                  <dd>{h.uptime_s !== undefined ? t("health.uptimeValue", { s: fmtNumber(h.uptime_s) }) : "—"}</dd>
                </dl>
                <h3 style={{ marginTop: 12 }}>{t("health.components")}</h3>
                <TableWrap label={t("health.components")}>
                  <table>
                    <tbody>
                      {Object.entries(h.components || {}).map(([k, v]) => (
                        <tr key={k}>
                          <th scope="row">
                            <code>{k}</code>
                          </th>
                          <td>
                            <Badge tone={v === "ok" ? "success" : v === "simulator" ? "warning" : "info"}>{String(v)}</Badge>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </TableWrap>
                {h.components?.execution_backend === "simulator" ? (
                  <p className="small muted" style={{ marginTop: 8 }}>
                    {t("health.simulator")}
                  </p>
                ) : null}
              </>
            )}
          </DataState>
        </section>
        <section className="card" aria-labelledby="h-mod">
          <h2 id="h-mod">{t("health.modules")}</h2>
          <DataState res={modules}>
            {(list) => (
              <TableWrap label={t("health.modules")}>
                <table data-testid="modules-table">
                  <thead>
                    <tr>
                      <th scope="col">{t("health.module")}</th>
                      <th scope="col">{t("health.endpoint")}</th>
                      <th scope="col">{t("change.status")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {list.map((m) => (
                      <tr key={m.path}>
                        <th scope="row">{t(m.key)}</th>
                        <td>
                          <code>{m.path}</code>
                        </td>
                        <td>
                          <Badge tone={m.state === "ok" ? "success" : m.state === "unavailable" ? "neutral" : "danger"}>
                            {t(`health.state.${m.state}` as MessageKey)}
                          </Badge>
                          {m.detail ? <span className="small muted"> {m.detail}</span> : null}
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
    </>
  );
}
