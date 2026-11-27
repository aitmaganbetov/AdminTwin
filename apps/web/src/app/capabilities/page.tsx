"use client";

import { useState } from "react";
import { Badge, DataState, Notice, PageHeader, TableWrap } from "@/components/ui";
import { useApi } from "@/lib/auth/AuthProvider";
import { useI18n } from "@/lib/i18n/I18nProvider";
import { useResource } from "@/lib/useResource";

const TIERS = ["", "MVP", "P1a", "P1b", "P2"];

export default function CapabilitiesPage() {
  const { t, te } = useI18n();
  const api = useApi();
  const [tier, setTier] = useState("");
  const caps = useResource(() => api.capabilities(tier || undefined), [api, tier]);
  const stds = useResource(() => api.standards(), [api]);

  return (
    <>
      <PageHeader title={t("nav.capabilities")} subtitle={t("capabilities.subtitle")} />
      <Notice tone="warning" title={t("standards.notice.title")}>
        <p>{t("standards.notice.text")}</p>
        {stds.data?.notice ? (
          <p className="small muted" lang="en">
            {stds.data.notice}
          </p>
        ) : null}
      </Notice>

      <section className="card" aria-labelledby="caps-h">
        <div className="card-title">
          <h2 id="caps-h">{t("capabilities.title")}</h2>
          <div className="switcher" role="group" aria-label={t("capabilities.tier")}>
            {TIERS.map((x) => (
              <button key={x || "all"} type="button" className="switcher-btn" aria-pressed={tier === x} onClick={() => setTier(x)}>
                {x || t("common.all")}
              </button>
            ))}
          </div>
        </div>
        <DataState res={caps} isEmpty={(d) => (d.items || []).length === 0} emptyText={t("capabilities.empty")}>
          {(d) => (
            <TableWrap label={t("capabilities.title")}>
              <table data-testid="capabilities-table">
                <thead>
                  <tr>
                    <th scope="col">ID</th>
                    <th scope="col">{t("capabilities.name")}</th>
                    <th scope="col">{t("capabilities.domain")}</th>
                    <th scope="col">{t("capabilities.tier")}</th>
                    <th scope="col">{t("change.risk")}</th>
                    <th scope="col">{t("capabilities.ownerAgent")}</th>
                    <th scope="col">{t("capabilities.autonomy")}</th>
                    <th scope="col">{t("capabilities.approval")}</th>
                    <th scope="col">{t("capabilities.operations")}</th>
                    <th scope="col">{t("capabilities.standards")}</th>
                    <th scope="col">{t("capabilities.lifecycle")}</th>
                  </tr>
                </thead>
                <tbody>
                  {(d.items || []).map((c) => (
                    <tr key={c.capability_id}>
                      <th scope="row">
                        <code>{c.capability_id}</code>
                      </th>
                      <td>{c.name}</td>
                      <td>{c.domain}</td>
                      <td>
                        <Badge tone={c.tier === "MVP" ? "info" : "outline"}>{c.tier}</Badge>
                      </td>
                      <td>{te("st.risk", c.risk)}</td>
                      <td>
                        <code>{c.owner_agent}</code>
                      </td>
                      <td>{te("mode", c.autonomy_ceiling)}</td>
                      <td>
                        <code>{c.approval_policy}</code>
                      </td>
                      <td className="small">
                        {(c.operations || []).map((o, i) => (
                          <div key={i}>
                            {o.level}: <code>{o.tool || o.runbook}</code>
                          </div>
                        ))}
                      </td>
                      <td>{(c.standards || []).join(", ") || "—"}</td>
                      <td>{c.lifecycle_state}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          )}
        </DataState>
      </section>

      <section className="card" aria-labelledby="stds-h">
        <h2 id="stds-h">{t("standards.title")}</h2>
        <DataState res={stds} isEmpty={(d) => (d.items || []).length === 0}>
          {(d) => (
            <TableWrap label={t("standards.title")}>
              <table data-testid="standards-table">
                <thead>
                  <tr>
                    <th scope="col">ID</th>
                    <th scope="col">{t("standards.name")}</th>
                    <th scope="col">{t("standards.edition")}</th>
                    <th scope="col">{t("standards.area")}</th>
                    <th scope="col">{t("standards.evidence")}</th>
                    <th scope="col">{t("standards.modules")}</th>
                    <th scope="col">{t("standards.applicability")}</th>
                    <th scope="col">{t("standards.review")}</th>
                  </tr>
                </thead>
                <tbody>
                  {(d.items || []).map((s) => (
                    <tr key={s.standard_id}>
                      <th scope="row">
                        <code>{s.standard_id}</code>
                      </th>
                      <td>{s.title}</td>
                      <td>{s.edition}</td>
                      <td>{s.area}</td>
                      <td className="small">{s.required_evidence}</td>
                      <td>{(s.modules || []).join(", ")}</td>
                      <td>{(s.applicability || []).join(", ")}</td>
                      <td className="small">{s.next_review_at || t("standards.notReviewed")}</td>
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
