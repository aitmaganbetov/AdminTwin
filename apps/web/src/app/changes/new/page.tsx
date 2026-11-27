"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { RunbookSummary } from "@/components/RunbookSummary";
import { DataState, Notice, PageHeader, ProblemView } from "@/components/ui";
import { randomId } from "@/lib/api/client";
import { isApiError, paramFieldErrors, type ApiError } from "@/lib/api/problem";
import type { ChangeType, Runbook } from "@/lib/api/types";
import { useApi, useAuth } from "@/lib/auth/AuthProvider";
import { useAssets } from "@/lib/hooks";
import type { MessageKey } from "@/lib/i18n/core";
import { useI18n } from "@/lib/i18n/I18nProvider";
import {
  buildParamFields,
  coerceParamValues,
  initialParamValues,
  payloadFingerprint,
  validateParamValues,
  type ParamError,
  type ParamField,
  type ParamValues,
} from "@/lib/params";
import { can } from "@/lib/permissions";
import { useResource } from "@/lib/useResource";

const OPEN_INCIDENT = ["new", "triaged", "investigating", "mitigated", "reopened"];

export default function NewChangePage() {
  return (
    <Suspense>
      <NewChange />
    </Suspense>
  );
}

function NewChange() {
  const { t } = useI18n();
  const api = useApi();
  const { identity } = useAuth();
  const search = useSearchParams();
  const runbooks = useResource(() => api.runbooks(), [api]);
  const assets = useAssets();

  if (!can.proposeChange(identity)) {
    return (
      <>
        <PageHeader breadcrumbs={[{ href: "/changes", label: t("nav.changes") }]} title={t("changes.new")} />
        <Notice tone="warning" title={t("perm.denied")}>
          <p>{t("perm.proposeChange")}</p>
        </Notice>
      </>
    );
  }

  return (
    <>
      <PageHeader breadcrumbs={[{ href: "/changes", label: t("nav.changes") }]} title={t("changes.new")} subtitle={t("changes.new.subtitle")} />
      <DataState res={runbooks} isEmpty={(d) => d.items.length === 0} emptyText={t("runbooks.empty")}>
        {(d) => (
          <ChangeForm
            runbooks={d.items}
            assets={assets.list}
            initialRunbook={search.get("runbook") || ""}
            initialAsset={search.get("asset") || ""}
            initialIncident={search.get("incident") || ""}
          />
        )}
      </DataState>
    </>
  );
}

function ChangeForm({
  runbooks,
  assets,
  initialRunbook,
  initialAsset,
  initialIncident,
}: {
  runbooks: Runbook[];
  assets: ReturnType<typeof useAssets>["list"];
  initialRunbook: string;
  initialAsset: string;
  initialIncident: string;
}) {
  const { t, te } = useI18n();
  const api = useApi();
  const { identity } = useAuth();
  const router = useRouter();

  const [runbookId, setRunbookId] = useState(runbooks.some((r) => r.id === initialRunbook) ? initialRunbook : "");
  const rb = runbooks.find((r) => r.id === runbookId);
  const scopeTypes = useMemo(() => (rb?.scope || []).map((s) => s.asset_type), [rb]);
  const eligibleAssets = useMemo(
    () => (scopeTypes.length ? assets.filter((a) => scopeTypes.includes(a.type)) : assets),
    [assets, scopeTypes],
  );
  const [assetId, setAssetId] = useState(initialAsset);
  const asset = assets.find((a) => a.id === assetId) || null;
  const fields = useMemo<ParamField[]>(() => buildParamFields(rb?.parameters, asset), [rb, asset]);
  const [values, setValues] = useState<ParamValues>({});
  const [reason, setReason] = useState("");
  const [type, setType] = useState<ChangeType>("normal");
  const [dryRun, setDryRun] = useState(false);
  const [incidentId, setIncidentId] = useState(initialIncident);
  const [clientErrors, setClientErrors] = useState<Record<string, ParamError>>({});
  const [reasonError, setReasonError] = useState(false);
  const [targetError, setTargetError] = useState(false);
  const [serverError, setServerError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  const formRef = useRef<HTMLFormElement>(null);
  // Связь с инцидентом выбирается из открытых инцидентов; без модуля инцидентов — ввод идентификатора.
  const incidents = useResource(() => api.incidents(), [api]);
  const incidentManual =
    !!incidentId && !!incidents.data && !(incidents.data.items || []).some((i) => i.id === incidentId);

  // Сброс параметров при смене runbook/актива.
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- значения формы зависят от схемы runbook
    setValues(initialParamValues(fields));
    setClientErrors({});
  }, [fields]);

  useEffect(() => {
    if (rb) {
      const def = rb.change_type_default === "standard" || rb.change_type_default === "normal" ? rb.change_type_default : "normal";
      // eslint-disable-next-line react-hooks/set-state-in-effect -- тип по умолчанию из runbook
      setType(def);
    }
  }, [rb]);

  useEffect(() => {
    // Сбрасываем актив вне scope runbook только после загрузки CMDB: иначе актив из ссылки
    // (?asset=…) терялся, если runbooks загружались раньше активов.
    if (assets.length > 0 && assetId && !eligibleAssets.some((a) => a.id === assetId)) {
      // eslint-disable-next-line react-hooks/set-state-in-effect -- актив вне scope runbook
      setAssetId("");
    }
  }, [assets.length, eligibleAssets, assetId]);

  const body = useMemo(
    () => ({
      runbook_id: runbookId,
      asset_id: assetId,
      params: coerceParamValues(fields, values),
      reason: reason.trim(),
      type,
      dry_run: dryRun,
      ...(incidentId.trim() ? { incident_id: incidentId.trim() } : {}),
    }),
    [runbookId, assetId, fields, values, reason, type, dryRun, incidentId],
  );
  // Idempotency-Key: один ключ на одну полезную нагрузку; повтор той же отправки безопасен.
  const fp = payloadFingerprint(body);
  const [idem, setIdem] = useState<{ fp: string; key: string }>(() => ({ fp, key: randomId() }));
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- новый ключ для новой полезной нагрузки
    if (idem.fp !== fp) setIdem({ fp, key: randomId() });
  }, [fp, idem.fp]);
  const idemKey = idem.fp === fp ? idem.key : null;

  const serverFieldErrors = paramFieldErrors(serverError?.fieldErrors);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (busy) return; // повторная отправка исключена; Idempotency-Key защищает и на сервере
    setServerError(null);
    const ce = validateParamValues(fields, values);
    setClientErrors(ce);
    const reasonMissing = !reason.trim();
    setReasonError(reasonMissing);
    setTargetError(!runbookId || !assetId);
    if (!runbookId || !assetId || reasonMissing || Object.keys(ce).length > 0) {
      requestAnimationFrame(() => formRef.current?.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus());
      return;
    }
    const key = idemKey ?? randomId();
    setIdem({ fp, key });
    setBusy(true);
    try {
      const res = await api.createChange(body, key);
      router.push(`/changes/${res.data.id}?created=${res.status}`);
    } catch (err) {
      if (isApiError(err)) setServerError(err);
      else throw err;
      setBusy(false);
    }
  };

  const errText = (f: ParamField): string | null => {
    const ce = clientErrors[f.name];
    if (ce) return t(`params.error.${ce.code}` as MessageKey, { limit: String(ce.limit ?? "") });
    return serverFieldErrors[f.name] || null;
  };

  return (
    <form ref={formRef} onSubmit={submit} noValidate data-testid="change-form">
      <div className="form-grid">
        <div className="card">
          <h2>{t("changes.new.target")}</h2>
          <div className="field">
            <label htmlFor="cf-runbook">
              {t("change.runbook")} <span className="req" aria-hidden="true">*</span>
            </label>
            <select
              id="cf-runbook"
              value={runbookId}
              onChange={(e) => setRunbookId(e.target.value)}
              required
              aria-invalid={targetError && !runbookId ? true : undefined}
              data-testid="cf-runbook"
            >
              <option value="">{t("changes.new.pickRunbook")}</option>
              {runbooks.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.id} — {r.title} ({te("st.risk", r.risk)})
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor="cf-asset">
              {t("change.asset")} <span className="req" aria-hidden="true">*</span>
            </label>
            <select
              id="cf-asset"
              value={assetId}
              onChange={(e) => setAssetId(e.target.value)}
              required
              aria-describedby="cf-asset-hint"
              aria-invalid={targetError && !assetId ? true : undefined}
              data-testid="cf-asset"
            >
              <option value="">{t("changes.new.pickAsset")}</option>
              {eligibleAssets.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name} · {a.type} · {a.environment}
                  {a.legal_hold ? ` · ${t("asset.legalHold")}` : ""}
                </option>
              ))}
            </select>
            <span id="cf-asset-hint" className="hint">
              {scopeTypes.length ? t("changes.new.scopeHint", { types: scopeTypes.join(", ") }) : t("changes.new.assetHint")}
            </span>
          </div>
          {asset?.legal_hold ? (
            <Notice tone="warning" icon="lock" title={t("asset.legalHold")}>
              <p>{t("changes.new.legalHoldWarning")}</p>
            </Notice>
          ) : null}

          <fieldset>
            <legend>{t("changes.new.params")}</legend>
            {!rb ? <p className="muted small">{t("changes.new.pickRunbookFirst")}</p> : null}
            {rb && fields.length === 0 ? <p className="muted small">{t("changes.new.noParams")}</p> : null}
            {fields.map((f) => (
              <ParamInput
                key={`${runbookId}:${f.name}`}
                field={f}
                value={values[f.name]}
                error={errText(f)}
                onChange={(v) => setValues((cur) => ({ ...cur, [f.name]: v }))}
              />
            ))}
          </fieldset>

          <div className="field">
            <label htmlFor="cf-reason">
              {t("change.reason")} <span className="req" aria-hidden="true">*</span>
            </label>
            <textarea
              id="cf-reason"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              required
              aria-invalid={reasonError || undefined}
              aria-describedby={reasonError ? "cf-reason-err" : undefined}
              data-testid="cf-reason"
            />
            {reasonError ? (
              <span id="cf-reason-err" className="error-text">
                {t("changes.new.reasonRequired")}
              </span>
            ) : (
              <span className="hint">{t("changes.new.reasonHint")}</span>
            )}
          </div>

          <div className="grid grid-2">
            <div className="field">
              <label htmlFor="cf-type">{t("change.type")}</label>
              <select id="cf-type" value={type} onChange={(e) => setType(e.target.value as ChangeType)} aria-describedby="cf-type-hint">
                <option value="standard">{te("changeType", "standard")}</option>
                <option value="normal">{te("changeType", "normal")}</option>
                {can.breakGlass(identity) ? <option value="emergency">{te("changeType", "emergency")}</option> : null}
              </select>
              <span id="cf-type-hint" className="hint">
                {t(`changeType.${type}.hint` as MessageKey)}
              </span>
            </div>
            <div className="field">
              <label htmlFor="cf-incident">{t("change.incident")}</label>
              {incidents.data && !incidentManual ? (
                <select id="cf-incident" value={incidentId} onChange={(e) => setIncidentId(e.target.value)} data-testid="cf-incident" aria-describedby="cf-incident-hint">
                  <option value="">{t("changes.new.noIncident")}</option>
                  {(incidents.data.items || [])
                    .filter((i) => OPEN_INCIDENT.includes(i.status) || i.id === incidentId)
                    .map((i) => (
                      <option key={i.id} value={i.id}>
                        {i.title} · {te("st.severity", i.severity)}
                      </option>
                    ))}
                </select>
              ) : (
                <input
                  id="cf-incident"
                  value={incidentId}
                  onChange={(e) => setIncidentId(e.target.value)}
                  placeholder="00000000-0000-0000-0000-000000000000"
                  spellCheck={false}
                  aria-describedby="cf-incident-hint"
                  data-testid="cf-incident"
                />
              )}
              <span id="cf-incident-hint" className="hint">
                {t("changes.new.incidentHint")}
              </span>
            </div>
          </div>

          <label className="check">
            <input type="checkbox" checked={dryRun} onChange={(e) => setDryRun(e.target.checked)} data-testid="cf-dry-run" />
            {t("change.dryRun")}
          </label>
          <p className="hint small muted">
            {rb?.execute?.supports_dry_run ? t("changes.new.dryRunSupported") : t("changes.new.dryRunHint")}
          </p>
        </div>

        <div className="stack form-aside">
          <div className="card">
            <h2>{t("changes.new.submitTitle")}</h2>
            <p className="small muted">{t("changes.new.submitHint")}</p>
            <p className="small">
              Idempotency-Key: <code data-testid="idem-key">{idemKey ?? t("changes.new.idemNew")}</code>
            </p>
            {serverError ? <ProblemView error={serverError} /> : null}
            <div className="btn-set">
              <Link href="/changes" className="btn btn-secondary">
                {t("common.cancel")}
              </Link>
              <button type="submit" className="btn btn-primary" disabled={busy} aria-busy={busy} data-testid="cf-submit">
                {busy ? t("common.sending") : t("changes.new.submit")}
              </button>
            </div>
          </div>
          {rb ? <RunbookSummary rb={rb} compact /> : null}
        </div>
      </div>
    </form>
  );
}

function ParamInput({
  field: f,
  value,
  error,
  onChange,
}: {
  field: ParamField;
  value: string | boolean | undefined;
  error: string | null;
  onChange: (v: string | boolean) => void;
}) {
  const { t } = useI18n();
  const id = `param-${f.name}`;
  const hintId = `${id}-hint`;
  const errId = `${id}-err`;
  const describedBy = [hintId, error ? errId : null].filter(Boolean).join(" ");
  const hints: string[] = [];
  if (f.pattern) hints.push(t("params.hint.pattern", { pattern: f.pattern }));
  if (f.min !== undefined || f.max !== undefined) hints.push(t("params.hint.range", { min: f.min ?? "−∞", max: f.max ?? "∞" }));
  if (f.maxLength) hints.push(t("params.hint.maxLength", { n: f.maxLength }));
  if (f.inventoryKind) hints.push(t("params.hint.inventory", { kind: f.inventoryKind }));
  if (f.defaultValue !== undefined) hints.push(t("params.hint.default", { v: String(f.defaultValue) }));
  if (f.protectedOptions?.length) hints.push(t("params.hint.protected", { list: f.protectedOptions.join(", ") }));

  if (f.control === "checkbox") {
    return (
      <div className="field">
        <label className="check" htmlFor={id}>
          <input id={id} type="checkbox" checked={value === true} onChange={(e) => onChange(e.target.checked)} aria-describedby={describedBy} />
          <code>{f.name}</code>
        </label>
        <span id={hintId} className="hint">
          {t("params.type.boolean")}
          {hints.length ? ` · ${hints.join(" · ")}` : ""}
        </span>
      </div>
    );
  }
  const common = {
    id,
    "aria-describedby": describedBy,
    "aria-invalid": error ? true : undefined,
    "aria-required": f.required || undefined,
    "data-testid": id,
  } as const;
  return (
    <div className="field">
      <label htmlFor={id}>
        <code>{f.name}</code> {f.required ? <span className="req" aria-hidden="true">*</span> : null}
      </label>
      {f.control === "select" ? (
        <select {...common} value={typeof value === "string" ? value : ""} onChange={(e) => onChange(e.target.value)}>
          <option value="">{t("params.choose")}</option>
          {(f.options || []).map((o) => (
            <option key={o} value={o}>
              {o}
              {f.protectedOptions?.includes(o) ? ` (${t("params.protected")})` : ""}
            </option>
          ))}
        </select>
      ) : f.control === "number" ? (
        <input
          {...common}
          type="number"
          inputMode="numeric"
          step={f.type === "integer" ? 1 : "any"}
          min={f.min}
          max={f.max}
          value={typeof value === "string" ? value : ""}
          onChange={(e) => onChange(e.target.value)}
        />
      ) : (
        <input
          {...common}
          type="text"
          spellCheck={false}
          autoComplete="off"
          maxLength={f.maxLength}
          value={typeof value === "string" ? value : ""}
          onChange={(e) => onChange(e.target.value)}
        />
      )}
      <span id={hintId} className="hint">
        {t(`params.type.${f.type === "integer" || f.type === "number" || f.type === "boolean" ? f.type : "string"}` as MessageKey)}
        {f.fromInventory && f.options?.length === 0 ? ` · ${t("params.noInventory")}` : ""}
        {hints.length ? ` · ${hints.join(" · ")}` : ""}
      </span>
      {error ? (
        <span id={errId} className="error-text">
          {error}
        </span>
      ) : null}
    </div>
  );
}
