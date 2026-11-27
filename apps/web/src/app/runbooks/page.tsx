"use client";

import { RunbookSummary } from "@/components/RunbookSummary";
import { DataState, Notice, PageHeader } from "@/components/ui";
import { useApi, useAuth } from "@/lib/auth/AuthProvider";
import { useI18n } from "@/lib/i18n/I18nProvider";
import { can } from "@/lib/permissions";
import { useResource } from "@/lib/useResource";

export default function RunbooksPage() {
  const { t } = useI18n();
  const api = useApi();
  const { identity } = useAuth();
  const res = useResource(() => api.runbooks(), [api]);
  return (
    <>
      <PageHeader title={t("nav.runbooks")} subtitle={t("runbooks.subtitle")} />
      <Notice tone="info" title={t("runbooks.rules.title")}>
        <p className="small">{t("runbooks.rules.text")}</p>
      </Notice>
      <DataState res={res} isEmpty={(d) => d.items.length === 0} emptyText={t("runbooks.empty")}>
        {(d) => (
          <div className="grid grid-2">
            {d.items.map((rb) => (
              <RunbookSummary key={rb.id} rb={rb} action={can.proposeChange(identity)} />
            ))}
          </div>
        )}
      </DataState>
    </>
  );
}
