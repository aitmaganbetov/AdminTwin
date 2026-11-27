"use client";

import Link from "next/link";
import { useEffect, useId, useRef, type ReactNode } from "react";
import type { ApiError } from "@/lib/api/problem";
import type { MessageKey } from "@/lib/i18n/core";
import { useI18n } from "@/lib/i18n/I18nProvider";
import type { Resource } from "@/lib/useResource";
import { Icon } from "./Icon";

export type Tone = "neutral" | "info" | "success" | "warning" | "danger" | "critical" | "dev" | "outline";

export function Badge({ tone = "neutral", children, title }: { tone?: Tone; children: ReactNode; title?: string }) {
  return (
    <span className={`badge tone-${tone}`} title={title}>
      {children}
    </span>
  );
}

const CHANGE_TONE: Record<string, Tone> = {
  waiting_approval: "warning",
  proposed: "info",
  approved: "info",
  scheduled: "info",
  executing: "info",
  cancellation_pending: "warning",
  verified: "success",
  closed: "success",
  rejected: "danger",
  failed: "danger",
  preflight_failed: "danger",
  unknown: "danger",
  manual_review: "danger",
  rolled_back: "warning",
  compensated: "warning",
  closed_with_rollback: "warning",
  closed_with_compensation: "warning",
  cancelled: "neutral",
};
const RISK_TONE: Record<string, Tone> = { low: "success", medium: "warning", high: "danger", critical: "critical" };
const SEV_TONE: Record<string, Tone> = { critical: "critical", high: "danger", medium: "warning", low: "info", info: "neutral" };
const INC_TONE: Record<string, Tone> = {
  new: "warning",
  triaged: "info",
  investigating: "info",
  mitigated: "warning",
  resolved: "success",
  closed: "neutral",
  reopened: "danger",
};
const TASK_TONE: Record<string, Tone> = {
  created: "neutral",
  queued: "neutral",
  running: "info",
  waiting_input: "warning",
  waiting_approval: "warning",
  blocked: "danger",
  completed: "success",
  failed: "danger",
  cancelled: "neutral",
  timed_out: "danger",
};
const EXEC_TONE: Record<string, Tone> = {
  preflight: "info",
  executing: "info",
  verified: "success",
  dry_run: "success",
  preflight_failed: "danger",
  post_check_failed: "danger",
  failed: "danger",
  cancelled: "neutral",
  unknown: "danger",
};

export type StatusKind = "change" | "risk" | "severity" | "incident" | "task" | "execution";
const TONES: Record<StatusKind, Record<string, Tone>> = {
  change: CHANGE_TONE,
  risk: RISK_TONE,
  severity: SEV_TONE,
  incident: INC_TONE,
  task: TASK_TONE,
  execution: EXEC_TONE,
};

export function StatusBadge({ kind, value }: { kind: StatusKind; value: string | undefined | null }) {
  const { te } = useI18n();
  const v = value || "";
  return <Badge tone={TONES[kind][v] ?? "neutral"}>{te(`st.${kind}`, v)}</Badge>;
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="page-header">
      <div>
        <h1>{title}</h1>
        {subtitle ? <p>{subtitle}</p> : null}
      </div>
      {actions ? <div className="row">{actions}</div> : null}
    </div>
  );
}

export function Notice({ tone = "info", title, children, icon }: { tone?: Tone; title?: ReactNode; children?: ReactNode; icon?: string }) {
  const ic = icon ?? (tone === "danger" || tone === "warning" ? "warning" : tone === "success" ? "check" : "info");
  return (
    <div className={`notice tone-${tone}`} role={tone === "danger" ? "alert" : undefined}>
      <Icon name={ic} />
      <div className="notice-body">
        {title ? <strong>{title}</strong> : null}
        {children}
      </div>
    </div>
  );
}

const SPECIAL_CODES = [
  "policy-denied",
  "separation-of-duties",
  "kill-switch-active",
  "legal-hold",
  "invalid-params",
  "budget-exhausted",
  "unauthenticated",
  "forbidden",
  "not-found",
  "conflict",
  "idempotency-key-reused",
  "invalid-transition",
  "bad-request",
  "internal",
];

/** Отображение RFC 9457: title/detail/request_id и пояснение для особых типов ошибок. */
export function ProblemView({ error, onRetry }: { error: ApiError; onRetry?: () => void }) {
  const { t } = useI18n();
  const p = error.problem;
  const code = error.code;
  const special = SPECIAL_CODES.includes(code) ? code : null;

  if (error.kind === "module-unavailable") return <ModuleUnavailable />;

  const tone: Tone = code === "kill-switch-active" || code === "legal-hold" ? "danger" : error.kind === "network" ? "warning" : "danger";
  const heading =
    error.kind === "network"
      ? t("problem.network")
      : error.kind === "upstream-unavailable"
        ? t("problem.upstream")
        : special
          ? t(`problem.${special}` as MessageKey)
          : p.title;
  return (
    <div className={`notice tone-${tone}`} role="alert" data-problem-code={code}>
      <Icon name={code === "kill-switch-active" ? "stop" : code === "legal-hold" ? "lock" : "warning"} />
      <div className="notice-body">
        <strong>{heading}</strong>
        {p.title && p.title !== heading ? <p className="small">{p.title}{p.status ? ` (HTTP ${p.status})` : ""}</p> : null}
        {p.detail ? <p>{p.detail}</p> : null}
        {special ? <p className="small">{t(`problem.${special}.hint` as MessageKey)}</p> : null}
        {code === "kill-switch-active" ? (
          <p className="small">
            <Link href="/settings">{t("nav.settings")}</Link>
          </p>
        ) : null}
        {error.fieldErrors.length > 0 ? (
          <ul className="small">
            {error.fieldErrors.map((e, i) => (
              <li key={i}>
                <code>{e.field}</code>: {e.reason}
              </li>
            ))}
          </ul>
        ) : null}
        <p className="small muted">
          {p.policy_id ? (
            <>
              {t("problem.policyId")}: <code>{p.policy_id}</code>
              <br />
            </>
          ) : null}
          {p.change_id ? (
            <>
              {t("problem.changeId")}: <Link href={`/changes/${p.change_id}`}>{p.change_id}</Link>
              <br />
            </>
          ) : null}
          {error.requestId ? (
            <>
              {t("problem.requestId")}: <code data-testid="request-id">{error.requestId}</code>
            </>
          ) : null}
        </p>
        {onRetry ? (
          <button type="button" className="btn btn-sm" onClick={onRetry}>
            <Icon name="refresh" size={14} /> {t("common.retry")}
          </button>
        ) : null}
      </div>
    </div>
  );
}

export function ModuleUnavailable({ name }: { name?: string }) {
  const { t } = useI18n();
  return (
    <div className="empty" role="status" data-testid="module-unavailable">
      <Icon name="plug" size={28} />
      <h3>{t("module.unavailable.title")}</h3>
      <p>{name ? t("module.unavailable.named", { name }) : t("module.unavailable.text")}</p>
    </div>
  );
}

export function Loading() {
  const { t } = useI18n();
  return (
    <p className="muted" role="status" aria-live="polite">
      {t("common.loading")}
    </p>
  );
}

export function Empty({ title, text }: { title?: string; text?: string }) {
  const { t } = useI18n();
  return (
    <div className="empty" role="status">
      <h3>{title ?? t("common.empty")}</h3>
      {text ? <p>{text}</p> : null}
    </div>
  );
}

/** Загрузка / ошибка / «модуль недоступен» / пусто / данные. */
export function DataState<T>({
  res,
  isEmpty,
  emptyText,
  moduleName,
  children,
}: {
  res: Resource<T>;
  isEmpty?: (d: T) => boolean;
  emptyText?: string;
  moduleName?: string;
  children: (d: T) => ReactNode;
}) {
  if (res.error && (res.error.kind === "module-unavailable" || res.data === undefined)) {
    if (res.error.kind === "module-unavailable") return <ModuleUnavailable name={moduleName} />;
    return <ProblemView error={res.error} onRetry={res.reload} />;
  }
  if (res.data === undefined) return <Loading />;
  if (isEmpty && isEmpty(res.data)) return <Empty text={emptyText} />;
  return <>{children(res.data)}</>;
}

export function ConfidenceBar({ value, label }: { value: number | undefined | null; label?: string }) {
  const v = Math.max(0, Math.min(1, Number(value ?? 0)));
  const pct = Math.round(v * 100);
  const tone = v >= 0.75 ? "success" : v >= 0.4 ? "warning" : "danger";
  return (
    <div className="conf">
      <div
        className={`bar tone-${tone}`}
        role="meter"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={pct}
        aria-label={label}
      >
        <span style={{ width: `${pct}%` }} />
      </div>
      <span className="small nowrap">{pct}%</span>
    </div>
  );
}

export function TableWrap({ label, children }: { label: string; children: ReactNode }) {
  return (
    // Прокручиваемая область таблицы доступна с клавиатуры.
    <div className="table-wrap" role="region" aria-label={label} tabIndex={0}>
      {children}
    </div>
  );
}

/** Модальный диалог на нативном <dialog>: ловушка фокуса, Escape, возврат фокуса. */
export function Dialog({
  open,
  title,
  onClose,
  children,
  actions,
}: {
  open: boolean;
  title: string;
  onClose: () => void;
  children: ReactNode;
  actions: ReactNode;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) {
      const prev = document.activeElement as HTMLElement | null;
      d.showModal();
      return () => prev?.focus?.();
    }
    if (!open && d.open) d.close();
  }, [open]);
  return (
    <dialog
      ref={ref}
      className="modal"
      aria-labelledby={titleId}
      onCancel={(e) => {
        e.preventDefault();
        onClose();
      }}
    >
      {open ? (
        <>
          <div className="modal-body">
            <h2 id={titleId}>{title}</h2>
            {children}
          </div>
          <div className="modal-actions">{actions}</div>
        </>
      ) : null}
    </dialog>
  );
}

export function ShortId({ id }: { id: string | undefined | null }) {
  if (!id) return <>—</>;
  return (
    <code title={id} className="nowrap">
      {id.length > 12 ? `${id.slice(0, 8)}…` : id}
    </code>
  );
}

export function YesNo({ v }: { v: boolean | undefined | null }) {
  const { t } = useI18n();
  return <>{v ? t("common.yes") : t("common.no")}</>;
}
