"use client";

import Link from "next/link";
import { useState, type FormEvent } from "react";
import { Icon } from "@/components/Icon";
import { DataState, Dialog, PageHeader, ProblemView, StatusBadge, TableWrap } from "@/components/ui";
import { isApiError, type ApiError } from "@/lib/api/problem";
import { INCIDENT_STATUSES, SEVERITIES, type Severity } from "@/lib/api/types";
import { useApi, useAuth } from "@/lib/auth/AuthProvider";
import { useAssets } from "@/lib/hooks";
import { useI18n } from "@/lib/i18n/I18nProvider";
import { can } from "@/lib/permissions";
import { useResource } from "@/lib/useResource";

export default function IncidentsPage() {
  const { t, te, fmtDate } = useI18n();
  const api = useApi();
  const { identity } = useAuth();
  const assets = useAssets();
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState<Severity | "">("");
  const [createOpen, setCreateOpen] = useState(false);
  const res = useResource(() => api.incidents({ status, severity }), [api, status, severity], { intervalMs: 10000 });

  return (
    <>
      <PageHeader
        title={t("nav.incidents")}
        subtitle={t("incidents.subtitle")}
        actions={
          can.manageIncidents(identity) && res.error?.kind !== "module-unavailable" ? (
            <button type="button" className="btn btn-primary" onClick={() => setCreateOpen(true)}>
              <Icon name="plus" /> {t("incidents.new")}
            </button>
          ) : null
        }
      />
      <div className="toolbar">
        <div className="field">
          <label htmlFor="inc-sev">{t("incident.severity")}</label>
          <select id="inc-sev" value={severity} onChange={(e) => setSeverity(e.target.value as Severity | "")}>
            <option value="">{t("common.all")}</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {te("st.severity", s)}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="inc-status">{t("incident.status")}</label>
          <select id="inc-status" value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">{t("common.all")}</option>
            {INCIDENT_STATUSES.map((s) => (
              <option key={s} value={s}>
                {te("st.incident", s)}
              </option>
            ))}
          </select>
        </div>
      </div>
      <DataState res={res} moduleName={t("nav.incidents")} isEmpty={(d) => (d.items || []).length === 0} emptyText={t("incidents.empty")}>
        {(d) => (
          <TableWrap label={t("nav.incidents")}>
            <table data-testid="incidents-table">
              <thead>
                <tr>
                  <th scope="col">{t("incident.title")}</th>
                  <th scope="col">{t("incident.severity")}</th>
                  <th scope="col">{t("incident.status")}</th>
                  <th scope="col">{t("incident.assets")}</th>
                  <th scope="col">{t("incident.owner")}</th>
                  <th scope="col">{t("incident.rca")}</th>
                  <th scope="col">{t("common.created")}</th>
                </tr>
              </thead>
              <tbody>
                {(d.items || []).map((i) => (
                  <tr key={i.id}>
                    <th scope="row">
                      <Link href={`/incidents/${i.id}`}>{i.title}</Link>
                    </th>
                    <td>
                      <StatusBadge kind="severity" value={i.severity} />
                    </td>
                    <td>
                      <StatusBadge kind="incident" value={i.status} />
                    </td>
                    <td className="small">{(i.asset_ids || []).map((a) => assets.byId.get(a)?.name || a).join(", ") || "—"}</td>
                    <td>{i.owner || "—"}</td>
                    <td>{te("rca", i.rca?.status || "not_started")}</td>
                    <td className="nowrap">{fmtDate(i.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        )}
      </DataState>
      {createOpen ? <CreateIncident onClose={() => setCreateOpen(false)} onCreated={res.reload} /> : null}
    </>
  );
}

function CreateIncident({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const { t, te } = useI18n();
  const api = useApi();
  const assets = useAssets();
  const [title, setTitle] = useState("");
  const [severity, setSeverity] = useState<Severity>("medium");
  const [assetIds, setAssetIds] = useState<string[]>([]);
  const [description, setDescription] = useState("");
  const [err, setErr] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e?: FormEvent) => {
    e?.preventDefault();
    if (!title.trim()) return;
    setBusy(true);
    try {
      await api.createIncident({ title: title.trim(), severity, asset_ids: assetIds, description: description.trim() || undefined });
      onCreated();
      onClose();
    } catch (x) {
      if (isApiError(x)) setErr(x);
      else throw x;
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog
      open
      title={t("incidents.new")}
      onClose={onClose}
      actions={
        <>
          <button type="button" className="btn" onClick={onClose}>
            {t("common.cancel")}
          </button>
          <button type="button" className="btn btn-primary" disabled={busy || !title.trim()} onClick={() => submit()}>
            {t("common.create")}
          </button>
        </>
      }
    >
      <form onSubmit={submit}>
        <div className="field">
          <label htmlFor="ni-title">
            {t("incident.title")} <span className="req" aria-hidden="true">*</span>
          </label>
          <input id="ni-title" value={title} onChange={(e) => setTitle(e.target.value)} required />
        </div>
        <div className="field">
          <label htmlFor="ni-sev">{t("incident.severity")}</label>
          <select id="ni-sev" value={severity} onChange={(e) => setSeverity(e.target.value as Severity)}>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {te("st.severity", s)}
              </option>
            ))}
          </select>
        </div>
        <fieldset>
          <legend>{t("incident.assets")}</legend>
          <div className="chips">
            {assets.list.map((a) => (
              <label key={a.id} className="check">
                <input
                  type="checkbox"
                  checked={assetIds.includes(a.id)}
                  onChange={(e) => setAssetIds((c) => (e.target.checked ? [...c, a.id] : c.filter((x) => x !== a.id)))}
                />
                {a.name}
              </label>
            ))}
          </div>
        </fieldset>
        <div className="field">
          <label htmlFor="ni-desc">{t("incident.description")}</label>
          <textarea id="ni-desc" value={description} onChange={(e) => setDescription(e.target.value)} />
        </div>
      </form>
      {err ? <ProblemView error={err} /> : null}
    </Dialog>
  );
}
