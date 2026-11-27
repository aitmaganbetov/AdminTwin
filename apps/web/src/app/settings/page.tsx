"use client";

import { useState } from "react";
import { useKillSwitch } from "@/components/AppShell";
import { Icon } from "@/components/Icon";
import { Badge, Dialog, Notice, PageHeader, ProblemView } from "@/components/ui";
import { isApiError, type ApiError } from "@/lib/api/problem";
import type { KillSwitchState } from "@/lib/api/types";
import { useApi, useAuth } from "@/lib/auth/AuthProvider";
import { DEMO_TENANTS } from "@/lib/auth/dev";
import { LOCALES, type Locale, type MessageKey } from "@/lib/i18n/core";
import { useI18n } from "@/lib/i18n/I18nProvider";
import { can } from "@/lib/permissions";
import { useTheme, type ThemePref } from "@/lib/theme";

export default function SettingsPage() {
  const { t, locale, setLocale } = useI18n();
  const { pref, setPref } = useTheme();
  const { identity, mode } = useAuth();
  return (
    <>
      <PageHeader title={t("nav.settings")} subtitle={t("settings.subtitle")} />
      <div className="stack">
        <KillSwitchCard />
        <div className="grid grid-2">
          <section className="card" aria-labelledby="set-ui">
            <h2 id="set-ui">{t("settings.interface")}</h2>
            <div className="field">
              <label htmlFor="set-lang">{t("settings.language")}</label>
              <select id="set-lang" value={locale} onChange={(e) => setLocale(e.target.value as Locale)}>
                {LOCALES.map((l) => (
                  <option key={l} value={l}>
                    {t(`locale.${l}` as MessageKey)}
                  </option>
                ))}
              </select>
            </div>
            <fieldset>
              <legend>{t("settings.theme")}</legend>
              {(["system", "light", "dark"] as ThemePref[]).map((p) => (
                <label key={p} className="check" style={{ marginRight: 16 }}>
                  <input type="radio" name="theme" value={p} checked={pref === p} onChange={() => setPref(p)} />
                  {t(`theme.${p}` as MessageKey)}
                </label>
              ))}
            </fieldset>
          </section>
          <section className="card" aria-labelledby="set-id">
            <h2 id="set-id">{t("settings.identity")}</h2>
            {mode === "dev" ? (
              <Notice tone="dev" title={t("auth.dev.title")}>
                <p className="small">{t("auth.dev.warning")}</p>
              </Notice>
            ) : null}
            <dl className="kv">
              <dt>{t("auth.dev.actor")}</dt>
              <dd>
                <code>{identity?.actorId}</code>
              </dd>
              <dt>{t("auth.dev.tenant")}</dt>
              <dd>
                {DEMO_TENANTS.find((x) => x.id === identity?.tenantId)?.label} <code>{identity?.tenantId || "—"}</code>
              </dd>
              <dt>{t("auth.dev.roles")}</dt>
              <dd>{identity?.roles.map((r) => t(`role.${r}` as MessageKey)).join(", ") || "—"}</dd>
              <dt>{t("auth.dev.scopes")}</dt>
              <dd>{identity?.scopes.join(", ") || "—"}</dd>
              <dt>{t("settings.authMode")}</dt>
              <dd>{mode === "dev" ? t("settings.authMode.dev") : t("settings.authMode.oidc")}</dd>
            </dl>
          </section>
        </div>
      </div>
    </>
  );
}

function StateView({ s, label }: { s: KillSwitchState; label: string }) {
  const { t, fmtDate } = useI18n();
  return (
    <div>
      <h3>{label}</h3>
      <p>
        <Badge tone={s.active ? "critical" : "success"}>{s.active ? t("kill.state.active") : t("kill.state.inactive")}</Badge>
      </p>
      <dl className="kv small">
        <dt>{t("kill.reason")}</dt>
        <dd>{s.reason || "—"}</dd>
        <dt>{t("kill.actor")}</dt>
        <dd>{s.actor ? <code>{s.actor}</code> : "—"}</dd>
        <dt>{t("kill.changedAt")}</dt>
        <dd>{fmtDate(s.changed_at)}</dd>
      </dl>
    </div>
  );
}

function KillSwitchCard() {
  const { t } = useI18n();
  const api = useApi();
  const { identity } = useAuth();
  const kill = useKillSwitch();
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<ApiError | null>(null);
  const [reasonErr, setReasonErr] = useState(false);
  const tenant = kill?.data?.tenant;
  const platform = kill?.data?.platform;
  const target = !(tenant?.active ?? false);
  const allowed = can.killSwitch(identity);

  const submit = async () => {
    if (!reason.trim()) {
      setReasonErr(true);
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      await api.setKillSwitch(target, reason.trim(), "tenant");
      setOpen(false);
      setReason("");
      setConfirmed(false);
      kill?.reload();
    } catch (e) {
      if (isApiError(e)) setErr(e);
      else throw e;
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="card" aria-labelledby="kill-h" data-testid="kill-card">
      <div className="card-title">
        <h2 id="kill-h">
          {t("kill.title")}
        </h2>
        {tenant ? (
          <Badge tone={tenant.active ? "critical" : "success"}>
            <span data-testid="kill-state">{tenant.active ? t("kill.state.active") : t("kill.state.inactive")}</span>
          </Badge>
        ) : null}
      </div>
      <p className="small muted">{t("kill.semantics")}</p>
      {kill?.error ? <ProblemView error={kill.error} onRetry={kill.reload} /> : null}
      {tenant && platform ? (
        <div className="grid grid-2">
          <StateView s={tenant} label={t("kill.scope.tenant")} />
          <StateView s={platform} label={t("kill.scope.platform")} />
        </div>
      ) : (
        !kill?.error && <p className="muted">{t("common.loading")}</p>
      )}
      {!allowed ? (
        <Notice tone="info" title={t("perm.denied")}>
          <p className="small">{t("perm.killSwitch")}</p>
        </Notice>
      ) : null}
      {err && !open ? <ProblemView error={err} /> : null}
      <div className="row" style={{ marginTop: 12 }}>
        <button
          type="button"
          className={target ? "btn btn-danger" : "btn btn-primary"}
          disabled={!allowed || !tenant}
          onClick={() => {
            setErr(null);
            setReasonErr(false);
            setOpen(true);
          }}
          data-testid="kill-toggle"
        >
          <Icon name={target ? "stop" : "check"} /> {target ? t("kill.activate") : t("kill.deactivate")}
        </button>
      </div>
      <Dialog
        open={open}
        title={target ? t("kill.confirm.activateTitle") : t("kill.confirm.deactivateTitle")}
        onClose={() => setOpen(false)}
        actions={
          <>
            <button type="button" className="btn btn-secondary" onClick={() => setOpen(false)}>
              {t("common.cancel")}
            </button>
            <button
              type="button"
              className={target ? "btn btn-danger" : "btn btn-primary"}
              disabled={busy || (target && !confirmed)}
              aria-busy={busy}
              onClick={submit}
              data-testid="kill-confirm"
            >
              {target ? t("kill.activate") : t("kill.deactivate")}
            </button>
          </>
        }
      >
        <p className="small">{target ? t("kill.confirm.activateText") : t("kill.confirm.deactivateText")}</p>
        <div className="field">
          <label htmlFor="kill-reason">
            {t("kill.reason")} <span className="req" aria-hidden="true">*</span>
          </label>
          <textarea
            id="kill-reason"
            value={reason}
            onChange={(e) => {
              setReason(e.target.value);
              setReasonErr(false);
            }}
            required
            aria-invalid={reasonErr || undefined}
            aria-describedby={reasonErr ? "kill-reason-err" : undefined}
            data-testid="kill-reason"
          />
          {reasonErr ? (
            <span id="kill-reason-err" className="error-text">
              {t("params.error.required")}
            </span>
          ) : null}
        </div>
        {target ? (
          <label className="check">
            <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} data-testid="kill-ack" />
            {t("kill.confirm.ack")}
          </label>
        ) : null}
        {err ? <ProblemView error={err} /> : null}
      </Dialog>
    </section>
  );
}
