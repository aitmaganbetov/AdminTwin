"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useState, type FormEvent } from "react";
import { Icon, LogoMark } from "@/components/Icon";
import { Notice } from "@/components/ui";
import { ALL_ROLES, ENGINEER_SCOPES, type Role } from "@/lib/api/types";
import { useAuth } from "@/lib/auth/AuthProvider";
import { DEMO_TENANTS, DEV_PRESETS, isValidDevId } from "@/lib/auth/dev";
import { safeReturnTo } from "@/lib/auth/oidc";
import { LOCALES, type Locale, type MessageKey } from "@/lib/i18n/core";
import { useI18n } from "@/lib/i18n/I18nProvider";

export default function LoginPage() {
  return (
    <Suspense>
      <Login />
    </Suspense>
  );
}

function Login() {
  const { t, locale, setLocale } = useI18n();
  const { mode, devLogin, oidcLogin, expired } = useAuth();
  const router = useRouter();
  const search = useSearchParams();
  const next = safeReturnTo(search.get("next"));

  const [tenantId, setTenantId] = useState<string>(DEMO_TENANTS[0].id);
  const [actorId, setActorId] = useState("alice");
  const [roles, setRoles] = useState<Role[]>(["tenant_admin"]);
  const [scopes, setScopes] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [fieldError, setFieldError] = useState<"actor" | "roles" | null>(null);

  const applyPreset = (key: string) => {
    const p = DEV_PRESETS.find((x) => x.key === key);
    if (!p) return;
    setActorId(p.actorId);
    setRoles(p.roles);
    setScopes(p.scopes);
  };

  const submit = (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!isValidDevId(actorId)) {
      setFieldError("actor");
      document.getElementById("dev-actor")?.focus();
      return;
    }
    if (roles.length === 0) {
      setFieldError("roles");
      document.querySelector<HTMLInputElement>('input[name="roles"]')?.focus();
      return;
    }
    setFieldError(null);
    devLogin({ tenantId, actorId, roles, scopes });
    router.replace(next);
  };

  return (
    <main className="login-wrap" id="main">
      <div className="card login-card">
        <div className="row spread" style={{ marginBottom: 12 }}>
          <div className="brand">
            <LogoMark />
            <span>AdminTwin</span>
          </div>
          <div>
            <label htmlFor="login-lang" className="visually-hidden">
              {t("settings.language")}
            </label>
            <select id="login-lang" value={locale} onChange={(e) => setLocale(e.target.value as Locale)}>
              {LOCALES.map((l) => (
                <option key={l} value={l}>
                  {t(`locale.${l}` as MessageKey)}
                </option>
              ))}
            </select>
          </div>
        </div>
        <h1>{t("auth.title")}</h1>
        <p className="muted">AI Infrastructure Digital Twin & Autonomous IT Operations Platform</p>
        {expired ? <Notice tone="warning" title={t("auth.expired")} /> : null}

        {mode === "oidc" ? (
          <>
            <p>{t("auth.oidc.text")}</p>
            <button
              type="button"
              className="btn btn-primary"
              disabled={busy}
              onClick={async () => {
                setBusy(true);
                try {
                  await oidcLogin(next);
                } catch (err) {
                  setError(err instanceof Error ? err.message : String(err));
                  setBusy(false);
                }
              }}
            >
              {t("auth.oidc.button")} <Icon name="lock" />
            </button>
            {error ? <Notice tone="danger">{error}</Notice> : null}
          </>
        ) : (
          <form onSubmit={submit} aria-describedby="dev-warning" data-testid="dev-login">
            <div id="dev-warning">
              <Notice tone="dev" title={t("auth.dev.title")}>
                <p>{t("auth.dev.warning")}</p>
              </Notice>
            </div>

            <div className="field">
              <label htmlFor="dev-preset">{t("auth.dev.preset")}</label>
              <select id="dev-preset" defaultValue="" onChange={(e) => applyPreset(e.target.value)}>
                <option value="" disabled>
                  {t("auth.dev.presetPlaceholder")}
                </option>
                {DEV_PRESETS.map((p) => (
                  <option key={p.key} value={p.key}>
                    {t(`role.${p.roles[0]}` as MessageKey)} — {p.actorId}
                    {p.scopes.length ? ` (${p.scopes.join(", ")})` : ""}
                  </option>
                ))}
              </select>
            </div>

            <div className="field">
              <label htmlFor="dev-tenant">{t("auth.dev.tenant")}</label>
              <select id="dev-tenant" value={tenantId} onChange={(e) => setTenantId(e.target.value)} data-testid="dev-tenant">
                {DEMO_TENANTS.map((x) => (
                  <option key={x.id} value={x.id}>
                    {x.label} — {t(`mode.${x.mode}` as MessageKey)} ({x.id})
                  </option>
                ))}
              </select>
            </div>

            <div className="grid grid-2">
              <div className="field">
                <label htmlFor="dev-actor">
                  {t("auth.dev.actor")} <span className="req" aria-hidden="true">*</span>
                </label>
                <input
                  id="dev-actor"
                  value={actorId}
                  onChange={(e) => {
                    setActorId(e.target.value.trim());
                    if (fieldError === "actor") setFieldError(null);
                  }}
                  required
                  autoComplete="username"
                  aria-invalid={fieldError === "actor" || undefined}
                  aria-describedby={fieldError === "actor" ? "dev-actor-err dev-actor-hint" : "dev-actor-hint"}
                />
                {fieldError === "actor" ? (
                  <span id="dev-actor-err" className="error-text" role="alert">
                    {t("auth.dev.invalidActor")}
                  </span>
                ) : null}
                <span id="dev-actor-hint" className="hint">
                  {t("auth.dev.actorHint")}
                </span>
              </div>
              <div className="field">
                <label htmlFor="dev-kind">{t("auth.dev.kind")}</label>
                <select id="dev-kind" value="user" disabled aria-describedby="dev-kind-hint">
                  <option value="user">{t("auth.dev.kindUser")}</option>
                </select>
                <span id="dev-kind-hint" className="hint">
                  {t("auth.dev.kindHint")}
                </span>
              </div>
            </div>

            <fieldset aria-describedby={fieldError === "roles" ? "dev-roles-err" : undefined}>
              <legend>{t("auth.dev.roles")}</legend>
              {fieldError === "roles" ? (
                <p id="dev-roles-err" className="error-text" role="alert">
                  {t("auth.dev.noRoles")}
                </p>
              ) : null}
              <div className="chips">
                {ALL_ROLES.map((r) => (
                  <label key={r} className="check">
                    <input
                      type="checkbox"
                      name="roles"
                      value={r}
                      checked={roles.includes(r)}
                      onChange={(e) => {
                        setRoles((cur) => (e.target.checked ? [...cur, r] : cur.filter((x) => x !== r)));
                        if (e.target.checked && fieldError === "roles") setFieldError(null);
                      }}
                    />
                    {t(`role.${r}` as MessageKey)}
                  </label>
                ))}
              </div>
            </fieldset>

            <fieldset>
              <legend>{t("auth.dev.scopes")}</legend>
              <div className="chips">
                {ENGINEER_SCOPES.map((s) => (
                  <label key={s} className="check">
                    <input
                      type="checkbox"
                      name="scopes"
                      value={s}
                      checked={scopes.includes(s)}
                      onChange={(e) => setScopes((cur) => (e.target.checked ? [...cur, s] : cur.filter((x) => x !== s)))}
                    />
                    {s}
                  </label>
                ))}
              </div>
            </fieldset>

            {error ? <Notice tone="danger">{error}</Notice> : null}
            <button type="submit" className="btn btn-primary" data-testid="dev-login-submit">
              {t("auth.dev.submit")}
            </button>
          </form>
        )}
      </div>
    </main>
  );
}
