"use client";

import Link from "next/link";
import type { Runbook, RunbookCheck } from "@/lib/api/types";
import type { MessageKey } from "@/lib/i18n/core";
import { useI18n } from "@/lib/i18n/I18nProvider";
import { Badge, StatusBadge } from "./ui";

function checkLabel(c: RunbookCheck): string {
  const args = c.args ? ` (${Object.entries(c.args).map(([k, v]) => `${k}=${String(v)}`).join(", ")})` : "";
  return `${c.check}${args}`;
}

export function RunbookSummary({ rb, compact, action }: { rb: Runbook; compact?: boolean; action?: boolean }) {
  const { t, te } = useI18n();
  const H = compact ? "h3" : "h2";
  const id = `rb-${rb.id.replace(/[^a-z0-9]/gi, "-")}`;
  return (
    <article className="card" aria-labelledby={id} data-testid={`runbook-${rb.id}`}>
      <div className="card-title">
        <H id={id}>
          {rb.title} <code className="muted">{rb.id}@{rb.version}</code>
        </H>
        <div className="row">
          <StatusBadge kind="risk" value={rb.risk} />
          <Badge tone="outline">{te("changeType", rb.change_type_default)}</Badge>
        </div>
      </div>
      <dl className="kv">
        <dt>{t("runbook.scope")}</dt>
        <dd>{rb.scope.map((s) => s.asset_type).join(", ") || "—"}</dd>
        <dt>{t("runbook.modes")}</dt>
        <dd className="row">
          {rb.modes_allowed.map((m) => (
            <Badge key={m} tone="info">
              {t(`mode.${m}` as MessageKey)}
            </Badge>
          ))}
        </dd>
        <dt>{t("runbook.execute")}</dt>
        <dd>
          <code>
            {rb.execute.engine}:{rb.execute.action}
          </code>{" "}
          · {t("runbook.timeout", { s: rb.execute.timeout_s })}
          {rb.execute.supports_dry_run ? ` · ${t("runbook.supportsDryRun")}` : ""}
        </dd>
        <dt>{t("runbook.preflight")}</dt>
        <dd>
          <ul className="small" style={{ margin: 0, paddingLeft: 18 }}>
            {rb.preflight.map((c, i) => (
              <li key={i}>
                <code>{checkLabel(c)}</code>
              </li>
            ))}
          </ul>
        </dd>
        <dt>{t("runbook.postCheck")}</dt>
        <dd>
          <ul className="small" style={{ margin: 0, paddingLeft: 18 }}>
            {rb.post_check.map((c, i) => (
              <li key={i}>
                <code>{checkLabel(c)}</code>
                {c.if_defined ? <span className="muted"> ({t("runbook.ifDefined")})</span> : null}
              </li>
            ))}
          </ul>
        </dd>
        <dt>{t("runbook.rollback")}</dt>
        <dd>{rb.rollback === "none" ? <Badge tone="warning">{t("runbook.rollbackNone")}</Badge> : <code>{rb.rollback}</code>}</dd>
        <dt>{t("runbook.compensation")}</dt>
        <dd>
          {rb.compensation.length === 0 ? (
            "—"
          ) : (
            <ul className="small" style={{ margin: 0, paddingLeft: 18 }}>
              {rb.compensation.map((a, i) => (
                <li key={i}>
                  <code>{a.action}</code>
                  {a.when ? <span className="muted"> — {t("runbook.when", { when: a.when })}</span> : null}
                  {a.propose ? (
                    <span>
                      {" "}
                      → <code>{a.propose}</code>
                    </span>
                  ) : null}
                </li>
              ))}
            </ul>
          )}
        </dd>
        <dt>{t("runbook.sideEffects")}</dt>
        <dd className="row">
          {rb.side_effects.length === 0
            ? "—"
            : rb.side_effects.map((s) => (
                <Badge key={s} tone="warning">
                  {s}
                </Badge>
              ))}
        </dd>
        <dt>{t("runbook.rateLimit")}</dt>
        <dd>
          <code>{rb.rate_limit}</code>
        </dd>
        {!compact ? (
          <>
            <dt>{t("runbook.params")}</dt>
            <dd>
              {Object.keys(rb.parameters || {}).length === 0 ? (
                "—"
              ) : (
                <ul className="small" style={{ margin: 0, paddingLeft: 18 }}>
                  {Object.entries(rb.parameters).map(([k, p]) => (
                    <li key={k}>
                      <code>{k}</code>: {p.type}
                      {p.enum ? ` ∈ {${p.enum.join(", ")}}` : ""}
                      {p.pattern ? ` /${p.pattern}/` : ""}
                      {p.minimum !== undefined || p.maximum !== undefined ? ` [${p.minimum ?? ""}..${p.maximum ?? ""}]` : ""}
                      {p.default !== undefined ? ` = ${String(p.default)}` : ""}
                      {p.source ? ` · ${p.source}${p.kind ? `:${p.kind}` : ""}` : ""}
                    </li>
                  ))}
                </ul>
              )}
            </dd>
            <dt>{t("runbook.owner")}</dt>
            <dd>
              {rb.owner} · {t("runbook.certifiedBy")}: {rb.certified_by.join(", ")}
            </dd>
            <dt>{t("runbook.digest")}</dt>
            <dd>
              <code>{rb.digest}</code>
            </dd>
          </>
        ) : null}
      </dl>
      {action ? (
        <p style={{ marginTop: 12, marginBottom: 0 }}>
          <Link className="btn btn-sm" href={`/changes/new?runbook=${encodeURIComponent(rb.id)}`}>
            {t("runbooks.createChange")}
          </Link>
        </p>
      ) : null}
    </article>
  );
}
