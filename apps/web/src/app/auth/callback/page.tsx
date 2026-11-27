"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { Notice } from "@/components/ui";
import { useAuth } from "@/lib/auth/AuthProvider";
import { useI18n } from "@/lib/i18n/I18nProvider";

export default function OidcCallbackPage() {
  const { oidcCallback } = useAuth();
  const { t } = useI18n();
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    const search = new URLSearchParams(window.location.search);
    // Код авторизации не оставляем в истории браузера.
    window.history.replaceState(null, "", "/auth/callback");
    oidcCallback(search)
      .then((to) => router.replace(to))
      .catch((e: unknown) => setError(e instanceof Error ? e.message : String(e)));
  }, [oidcCallback, router]);

  return (
    <main className="login-wrap" id="main">
      <div className="card login-card">
        {error ? (
          <Notice tone="danger" title={t("auth.callback.failed")}>
            <p>{error}</p>
            <Link href="/login">{t("auth.title")}</Link>
          </Notice>
        ) : (
          <p role="status">{t("auth.callback.processing")}</p>
        )}
      </div>
    </main>
  );
}
