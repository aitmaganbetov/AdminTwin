"use client";

import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { Suspense, useState, type FormEvent } from "react";
import { Icon } from "@/components/Icon";
import { Badge, DataState, Notice, PageHeader, ProblemView, TableWrap } from "@/components/ui";
import { useApi, useAuth } from "@/lib/auth/AuthProvider";
import { useI18n } from "@/lib/i18n/I18nProvider";
import { can } from "@/lib/permissions";
import { useResource } from "@/lib/useResource";

export default function AuditPage() {
  return (
    <Suspense>
      <Audit />
    </Suspense>
  );
}

function Audit() {
  const { t, fmtDate } = useI18n();
  const api = useApi();
  const { identity } = useAuth();
  const search = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const object = search.get("object") || "";
  const [draft, setDraft] = useState(object);
  const logs = useResource(() => api.auditLogs(object || undefined), [api, object]);
  const integrity = useResource(() => api.auditIntegrity(), [api]);

  const apply = (e: FormEvent) => {
    e.preventDefault();
    const v = draft.trim();
    router.replace(v ? `${pathname}?object=${encodeURIComponent(v)}` : pathname);
  };

  return (
    <>
      <PageHeader title={t("nav.audit")} subtitle={t("audit.subtitle")} />
      {!can.readAudit(identity) ? (
        <Notice tone="warning" title={t("perm.denied")}>
          <p className="small">{t("perm.audit")}</p>
        </Notice>
      ) : null}

      <section className="card" aria-labelledby="audit-int" data-testid="integrity">
        <div className="card-title">
          <h2 id="audit-int">{t("audit.integrity")}</h2>
          <button type="button" className="btn btn-sm" onClick={integrity.reload}>
            <Icon name="refresh" size={14} /> {t("audit.verify")}
          </button>
        </div>
        {integrity.error ? (
          <ProblemView error={integrity.error} />
        ) : !integrity.data ? (
          <p className="muted">{t("common.loading")}</p>
        ) : (
          <>
            {integrity.data.valid ? (
              <Notice tone="success" title={t("audit.integrity.valid")}>
                <p className="small">{t("audit.integrity.entries", { n: integrity.data.entries })}</p>
              </Notice>
            ) : (
              <Notice tone="danger" title={t("audit.integrity.broken")}>
                <p className="small">
                  {t("audit.integrity.brokenAt", { seq: integrity.data.broken_at_seq ?? "?" })}
                  {integrity.data.error ? ` — ${integrity.data.error}` : ""}
                </p>
              </Notice>
            )}
            {integrity.data.checkpoint ? (
              <dl className="kv">
                <dt>{t("audit.checkpoint.seq")}</dt>
                <dd>{integrity.data.checkpoint.seq}</dd>
                <dt>{t("audit.checkpoint.at")}</dt>
                <dd>{fmtDate(integrity.data.checkpoint.at)}</dd>
                <dt>{t("audit.checkpoint.hash")}</dt>
                <dd>
                  <code>{integrity.data.checkpoint.hash}</code>
                </dd>
                <dt>{t("audit.checkpoint.signature")}</dt>
                <dd>
                  <code>{integrity.data.checkpoint.signature}</code>
                </dd>
              </dl>
            ) : (
              <p className="muted small">{t("audit.checkpoint.none")}</p>
            )}
          </>
        )}
      </section>

      <section className="card" aria-labelledby="audit-log">
        <h2 id="audit-log">{t("audit.log")}</h2>
        <form className="toolbar" onSubmit={apply} role="search">
          <div className="field" style={{ flex: "1 1 280px" }}>
            <label htmlFor="audit-object">{t("audit.filterObject")}</label>
            <input id="audit-object" value={draft} onChange={(e) => setDraft(e.target.value)} placeholder="00000000-0000-0000-0000-000000000000" spellCheck={false} />
          </div>
          <button type="submit" className="btn">
            {t("audit.applyFilter")}
          </button>
          {object ? (
            <button
              type="button"
              className="btn btn-ghost"
              onClick={() => {
                setDraft("");
                router.replace(pathname);
              }}
            >
              {t("common.resetFilters")}
            </button>
          ) : null}
        </form>
        <DataState
          res={logs}
          isEmpty={(d) => d.items.length === 0}
          emptyText={t("audit.empty")}
          filtered={!!object}
          onResetFilters={() => {
            setDraft("");
            router.replace(pathname);
          }}
        >
          {(d) => (
            <TableWrap label={t("audit.log")}>
              <table data-testid="audit-table">
                <thead>
                  <tr>
                    <th scope="col">#</th>
                    <th scope="col">{t("common.time")}</th>
                    <th scope="col">{t("audit.actor")}</th>
                    <th scope="col">{t("audit.action")}</th>
                    <th scope="col">{t("audit.object")}</th>
                    <th scope="col">{t("audit.data")}</th>
                    <th scope="col">{t("audit.hash")}</th>
                  </tr>
                </thead>
                <tbody>
                  {[...d.items].reverse().map((e) => (
                    <tr key={e.seq}>
                      <td>{e.seq}</td>
                      <td className="nowrap">{fmtDate(e.at)}</td>
                      <td>
                        <code>{e.actor}</code>
                      </td>
                      <td>
                        <Badge tone="outline">{e.action}</Badge>
                      </td>
                      <td>
                        <span className="small muted">{e.object_type}</span>
                        <br />
                        {e.object_type === "change_request" ? (
                          <Link href={`/changes/${e.object_id}`} className="mono small">
                            {e.object_id.slice(0, 8)}…
                          </Link>
                        ) : (
                          <code className="small">{e.object_id}</code>
                        )}
                      </td>
                      <td>
                        {e.data ? (
                          <details>
                            <summary className="small">{t("audit.show")}</summary>
                            <pre className="code">{JSON.stringify(e.data, null, 2)}</pre>
                          </details>
                        ) : (
                          "—"
                        )}
                      </td>
                      <td>
                        <code className="small" title={e.hash}>
                          {e.hash.slice(0, 12)}…
                        </code>
                      </td>
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
