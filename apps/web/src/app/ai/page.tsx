"use client";

import { Badge, DataState, Notice, PageHeader, TableWrap } from "@/components/ui";
import { useApi } from "@/lib/auth/AuthProvider";
import { useI18n } from "@/lib/i18n/I18nProvider";
import { useResource } from "@/lib/useResource";

function str(v: unknown): string {
  if (v === undefined || v === null || v === "") return "—";
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}

export default function AiPage() {
  const { t, fmtNumber } = useI18n();
  const api = useApi();
  const providers = useResource(() => api.aiProviders(), [api]);
  const profiles = useResource(() => api.modelProfiles(), [api]);
  const usage = useResource(() => api.aiUsage(), [api]);
  const agents = useResource(() => api.agents(), [api]);

  return (
    <>
      <PageHeader title={t("nav.ai")} subtitle={t("ai.subtitle")} />
      <Notice tone="info" title={t("ai.readonly.title")}>
        <p className="small">{t("ai.readonly.text")}</p>
      </Notice>
      <div className="grid grid-2">
        <section className="card" aria-labelledby="ai-prov">
          <h2 id="ai-prov">{t("ai.providers")}</h2>
          <DataState res={providers} moduleName={t("ai.providers")} isEmpty={(d) => (d.items || []).length === 0}>
            {(d) => (
              <TableWrap label={t("ai.providers")}>
                <table>
                  <thead>
                    <tr>
                      <th scope="col">ID</th>
                      <th scope="col">{t("ai.kind")}</th>
                      <th scope="col">{t("ai.mode")}</th>
                      <th scope="col">{t("change.status")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(d.items || []).map((p, i) => (
                      <tr key={i}>
                        <td>
                          <code>{str(p.id ?? p.name)}</code>
                        </td>
                        <td>{str(p.kind)}</td>
                        <td>{str(p.mode)}</td>
                        <td>{p.status ? <Badge tone={p.status === "ok" || p.status === "healthy" ? "success" : "warning"}>{p.status}</Badge> : "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </TableWrap>
            )}
          </DataState>
        </section>
        <section className="card" aria-labelledby="ai-prof">
          <h2 id="ai-prof">{t("ai.profiles")}</h2>
          <DataState res={profiles} moduleName={t("ai.profiles")} isEmpty={(d) => (d.items || []).length === 0}>
            {(d) => (
              <TableWrap label={t("ai.profiles")}>
                <table>
                  <thead>
                    <tr>
                      <th scope="col">ID</th>
                      <th scope="col">{t("ai.provider")}</th>
                      <th scope="col">{t("ai.model")}</th>
                      <th scope="col">{t("ai.capabilities")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(d.items || []).map((p, i) => (
                      <tr key={i}>
                        <td>
                          <code>{str(p.id ?? p.name)}</code>
                        </td>
                        <td>{str(p.provider)}</td>
                        <td>
                          <code>{str(p.model)}</code>
                        </td>
                        <td className="small">{Array.isArray(p.capabilities) ? p.capabilities.join(", ") : str(p.capabilities)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </TableWrap>
            )}
          </DataState>
        </section>
      </div>

      <section className="card" aria-labelledby="ai-usage">
        <h2 id="ai-usage">{t("ai.usage")}</h2>
        <DataState res={usage} moduleName={t("ai.usage")}>
          {(d) => (
            <div className="grid grid-2">
              <TableWrap label={t("ai.usage")}>
                <table>
                  <thead>
                    <tr>
                      <th scope="col">{t("ai.provider")}</th>
                      <th scope="col">{t("ai.profile")}</th>
                      <th scope="col">{t("ai.tokens")}</th>
                      <th scope="col">{t("ai.cost")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(d.items || []).map((u, i) => (
                      <tr key={i}>
                        <td>{str(u.provider)}</td>
                        <td>{str(u.model_profile)}</td>
                        <td>{fmtNumber(u.tokens)}</td>
                        <td>{fmtNumber(u.cost_usd, { style: "currency", currency: "USD", maximumFractionDigits: 4 })}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </TableWrap>
              <TableWrap label={t("ai.budgets")}>
                <table>
                  <thead>
                    <tr>
                      <th scope="col">{t("ai.budgetScope")}</th>
                      <th scope="col">{t("ai.utilization")}</th>
                      <th scope="col">{t("change.status")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(d.budgets || []).map((b, i) => (
                      <tr key={i}>
                        <td>{str(b.scope ?? b.level)}</td>
                        <td>{b.utilization !== undefined ? `${Math.round(Number(b.utilization) * 100)}%` : "—"}</td>
                        <td>{b.state ? <Badge tone={b.state === "ok" ? "success" : b.state === "soft" ? "warning" : "danger"}>{b.state}</Badge> : "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </TableWrap>
            </div>
          )}
        </DataState>
      </section>

      <section className="card" aria-labelledby="ai-agents">
        <h2 id="ai-agents">{t("agents.registry")}</h2>
        <DataState res={agents} moduleName={t("agents.registry")} isEmpty={(d) => (d.items || []).length === 0}>
          {(d) => (
            <TableWrap label={t("agents.registry")}>
              <table>
                <thead>
                  <tr>
                    <th scope="col">ID</th>
                    <th scope="col">{t("agents.name")}</th>
                    <th scope="col">{t("agents.modelProfile")}</th>
                    <th scope="col">{t("agents.fallback")}</th>
                    <th scope="col">{t("agents.sensitivity")}</th>
                    <th scope="col">{t("change.status")}</th>
                  </tr>
                </thead>
                <tbody>
                  {(d.items || []).map((a) => (
                    <tr key={a.id}>
                      <td>
                        <code>{a.id}</code>
                      </td>
                      <td>{a.name || "—"}</td>
                      <td>
                        <code>{a.model_profile || "—"}</code>
                      </td>
                      <td>
                        <code>{a.fallback_model_profile || "—"}</code>
                      </td>
                      <td>{a.data_sensitivity_max || "—"}</td>
                      <td>{a.status || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          )}
        </DataState>
      </section>
    </>
  );
}
