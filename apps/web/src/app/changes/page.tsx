"use client";

import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { Suspense } from "react";
import { Icon } from "@/components/Icon";
import { DataState, PageHeader, StatusBadge, TableWrap } from "@/components/ui";
import { CHANGE_STATUSES } from "@/lib/api/types";
import { useApi, useAuth } from "@/lib/auth/AuthProvider";
import { useAssets } from "@/lib/hooks";
import type { MessageKey } from "@/lib/i18n/core";
import { useI18n } from "@/lib/i18n/I18nProvider";
import { can } from "@/lib/permissions";
import { useResource } from "@/lib/useResource";

export default function ChangesPage() {
  return (
    <Suspense>
      <Changes />
    </Suspense>
  );
}

const QUICK: { key: MessageKey; status: string }[] = [
  { key: "changes.filter.all", status: "" },
  { key: "st.change.waiting_approval", status: "waiting_approval" },
  { key: "st.change.executing", status: "executing" },
  { key: "st.change.manual_review", status: "manual_review" },
  { key: "st.change.closed", status: "closed" },
];

function Changes() {
  const { t, te, fmtDate } = useI18n();
  const api = useApi();
  const { identity } = useAuth();
  const search = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const status = search.get("status") || "";
  const assets = useAssets();
  const res = useResource(() => api.changes(status || undefined), [api, status], { intervalMs: 5000 });

  const setStatus = (s: string) => router.replace(s ? `${pathname}?status=${encodeURIComponent(s)}` : pathname);

  return (
    <>
      <PageHeader
        title={t("nav.changes")}
        subtitle={t("changes.subtitle")}
        actions={
          can.proposeChange(identity) ? (
            <Link href="/changes/new" className="btn btn-primary" data-testid="new-change">
              {t("changes.new")} <Icon name="plus" />
            </Link>
          ) : null
        }
      />
      <div className="toolbar">
        <div className="field">
          <label htmlFor="status-filter">{t("changes.filter.status")}</label>
          <select id="status-filter" value={status} onChange={(e) => setStatus(e.target.value)} data-testid="status-filter">
            <option value="">{t("changes.filter.all")}</option>
            {CHANGE_STATUSES.map((s) => (
              <option key={s} value={s}>
                {te("st.change", s)}
              </option>
            ))}
          </select>
        </div>
        <div className="switcher" role="group" aria-label={t("changes.filter.quick")}>
          {QUICK.map((q) => (
            <button
              key={q.status || "all"}
              type="button"
              className="switcher-btn"
              aria-pressed={status === q.status}
              onClick={() => setStatus(q.status)}
            >
              {t(q.key)}
            </button>
          ))}
        </div>
      </div>
      <DataState
        res={res}
        isEmpty={(d) => d.items.length === 0}
        emptyText={t("changes.empty")}
        filtered={!!status}
        onResetFilters={() => setStatus("")}
      >
        {(d) => (
          <TableWrap label={t("nav.changes")}>
            <table data-testid="changes-table">
              <thead>
                <tr>
                  <th scope="col">{t("common.created")}</th>
                  <th scope="col">{t("change.runbook")}</th>
                  <th scope="col">{t("change.asset")}</th>
                  <th scope="col">{t("change.risk")}</th>
                  <th scope="col">{t("change.type")}</th>
                  <th scope="col">{t("change.status")}</th>
                  <th scope="col">{t("change.author")}</th>
                </tr>
              </thead>
              <tbody>
                {d.items.map((c) => (
                  <tr key={c.id}>
                    <td className="nowrap">{fmtDate(c.created_at)}</td>
                    <td>
                      <Link href={`/changes/${c.id}`} className="mono">
                        {c.runbook_id}
                      </Link>
                      <span className="muted small">@{c.runbook_version}</span>
                      {c.dry_run ? (
                        <>
                          {" "}
                          <span className="badge tone-outline">{t("change.dryRun")}</span>
                        </>
                      ) : null}
                    </td>
                    <td>{assets.byId.get(c.asset_id)?.name || c.asset_id}</td>
                    <td>
                      <StatusBadge kind="risk" value={c.risk} />
                    </td>
                    <td>{te("changeType", c.type)}</td>
                    <td>
                      <StatusBadge kind="change" value={c.status} />
                    </td>
                    <td>{c.author_id}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        )}
      </DataState>
    </>
  );
}
