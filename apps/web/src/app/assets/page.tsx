"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { Icon } from "@/components/Icon";
import { Badge, DataState, Notice, PageHeader, TableWrap } from "@/components/ui";
import { useAuth } from "@/lib/auth/AuthProvider";
import { missingClassification, useAssets } from "@/lib/hooks";
import type { MessageKey } from "@/lib/i18n/core";
import { useI18n } from "@/lib/i18n/I18nProvider";
import { can } from "@/lib/permissions";

const DATA_CLASS_TONE: Record<string, "neutral" | "info" | "warning" | "danger" | "critical"> = {
  public: "neutral",
  internal: "info",
  confidential: "warning",
  pii: "danger",
  secret: "critical",
};

export default function AssetsPage() {
  const { t, te } = useI18n();
  const { identity } = useAuth();
  const assets = useAssets();
  const [q, setQ] = useState("");
  const [env, setEnv] = useState("");

  const filtered = useMemo(() => {
    const s = q.trim().toLowerCase();
    return assets.list.filter(
      (a) =>
        (!env || a.environment === env) &&
        (!s || [a.name, a.type, a.owner, a.id].some((x) => (x || "").toLowerCase().includes(s))),
    );
  }, [assets.list, q, env]);
  const envs = useMemo(() => [...new Set(assets.list.map((a) => a.environment).filter(Boolean))].sort(), [assets.list]);
  const incomplete = assets.list.filter((a) => missingClassification(a).length > 0).length;

  return (
    <>
      <PageHeader title={t("nav.assets")} subtitle={t("assets.subtitle")} />
      {incomplete > 0 ? (
        <Notice tone="warning" title={t("assets.incomplete.title")}>
          <p>{t("assets.incomplete.text", { n: incomplete })}</p>
        </Notice>
      ) : null}
      <div className="toolbar">
        <div className="field">
          <label htmlFor="asset-q">{t("common.search")}</label>
          <input id="asset-q" type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder={t("assets.searchPlaceholder")} />
        </div>
        <div className="field">
          <label htmlFor="asset-env">{t("asset.environment")}</label>
          <select id="asset-env" value={env} onChange={(e) => setEnv(e.target.value)}>
            <option value="">{t("common.all")}</option>
            {envs.map((e) => (
              <option key={e} value={e}>
                {te("env", e)}
              </option>
            ))}
          </select>
        </div>
      </div>
      <DataState res={assets} isEmpty={() => filtered.length === 0} emptyText={t("assets.empty")}>
        {() => (
          <TableWrap label={t("nav.assets")}>
            <table data-testid="assets-table">
              <thead>
                <tr>
                  <th scope="col">{t("asset.name")}</th>
                  <th scope="col">{t("asset.type")}</th>
                  <th scope="col">{t("asset.environment")}</th>
                  <th scope="col">{t("asset.ring")}</th>
                  <th scope="col">{t("asset.tier")}</th>
                  <th scope="col">{t("asset.criticality")}</th>
                  <th scope="col">{t("asset.dataClass")}</th>
                  <th scope="col">{t("asset.owner")}</th>
                  <th scope="col">{t("asset.flags")}</th>
                  <th scope="col">
                    <span className="visually-hidden">{t("common.actions")}</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((a) => {
                  const miss = missingClassification(a);
                  return (
                    <tr key={a.id}>
                      <th scope="row">
                        <span>{a.name}</span>
                        <br />
                        <span className="mono small muted">{a.id}</span>
                      </th>
                      <td>
                        <code>{a.type}</code>
                      </td>
                      <td>{te("env", a.environment)}</td>
                      <td>{a.ring || "—"}</td>
                      <td>{a.service_tier ?? "—"}</td>
                      <td>{te("st.risk", a.criticality)}</td>
                      <td>
                        <Badge tone={DATA_CLASS_TONE[a.data_class] ?? "neutral"}>{te("dataClass", a.data_class)}</Badge>
                      </td>
                      <td>{a.owner || "—"}</td>
                      <td>
                        <div className="row" style={{ gap: 4 }}>
                          {a.legal_hold ? (
                            <Badge tone="danger" title={t("asset.legalHold.hint")}>
                              <Icon name="lock" size={12} /> {t("asset.legalHold")}
                            </Badge>
                          ) : null}
                          {a.active_investigation ? <Badge tone="warning">{t("asset.investigation")}</Badge> : null}
                          {a.verified ? <Badge tone="success">{t("asset.verified")}</Badge> : <Badge tone="warning">{t("asset.unverified")}</Badge>}
                          {miss.length > 0 ? (
                            <Badge tone="warning" title={miss.map((m) => t(`asset.field.${m}` as MessageKey)).join(", ")}>
                              <Icon name="warning" size={12} /> {t("assets.incomplete.badge")}
                            </Badge>
                          ) : null}
                        </div>
                      </td>
                      <td>
                        <div className="row" style={{ gap: 4 }}>
                          <Link className="btn btn-sm" href={`/topology?asset=${a.id}`}>
                            {t("assets.blastRadius")}
                          </Link>
                          {can.proposeChange(identity) ? (
                            <Link className="btn btn-sm" href={`/changes/new?asset=${a.id}`}>
                              {t("assets.change")}
                            </Link>
                          ) : null}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </TableWrap>
        )}
      </DataState>
    </>
  );
}
