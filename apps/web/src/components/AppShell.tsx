"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import type { KillSwitchStatus } from "@/lib/api/types";
import { useAuth } from "@/lib/auth/AuthProvider";
import { DEMO_TENANTS } from "@/lib/auth/dev";
import { LOCALES, type Locale, type MessageKey } from "@/lib/i18n/core";
import { useI18n } from "@/lib/i18n/I18nProvider";
import { useTheme } from "@/lib/theme";
import { useResource, type Resource } from "@/lib/useResource";
import { Icon, LogoMark } from "./Icon";

interface NavItem {
  href: string;
  key: MessageKey;
  icon: string;
}

export const NAV: { group: MessageKey; items: NavItem[] }[] = [
  {
    group: "nav.group.operations",
    items: [
      { href: "/", key: "nav.commandCenter", icon: "dashboard" },
      { href: "/incidents", key: "nav.incidents", icon: "alert" },
      { href: "/collaboration", key: "nav.collaboration", icon: "agents" },
      { href: "/changes", key: "nav.changes", icon: "changes" },
    ],
  },
  {
    group: "nav.group.inventory",
    items: [
      { href: "/assets", key: "nav.assets", icon: "server" },
      { href: "/topology", key: "nav.topology", icon: "topology" },
    ],
  },
  {
    group: "nav.group.catalog",
    items: [
      { href: "/runbooks", key: "nav.runbooks", icon: "book" },
      { href: "/capabilities", key: "nav.capabilities", icon: "shield" },
      { href: "/ai", key: "nav.ai", icon: "cpu" },
    ],
  },
  {
    group: "nav.group.platform",
    items: [
      { href: "/audit", key: "nav.audit", icon: "audit" },
      { href: "/health", key: "nav.health", icon: "heart" },
      { href: "/settings", key: "nav.settings", icon: "settings" },
    ],
  },
];

const PUBLIC_PATHS = ["/login", "/auth/callback"];

const KillCtx = createContext<Resource<KillSwitchStatus> | null>(null);
export function useKillSwitch(): Resource<KillSwitchStatus> | null {
  return useContext(KillCtx);
}

function isActive(pathname: string, href: string): boolean {
  return href === "/" ? pathname === "/" : pathname === href || pathname.startsWith(href + "/");
}

export function AppShell({ children }: { children: ReactNode }) {
  const pathname = usePathname() || "/";
  const router = useRouter();
  const { ready, identity, expired, mode } = useAuth();
  const isPublic = PUBLIC_PATHS.some((p) => pathname.startsWith(p));

  useEffect(() => {
    if (!ready || isPublic) return;
    if (!identity || expired) router.replace(`/login?next=${encodeURIComponent(pathname)}`);
  }, [ready, identity, expired, isPublic, pathname, router]);

  if (isPublic) return <>{children}</>;
  if (!ready || !identity) {
    return (
      <main className="login-wrap" id="main">
        <p role="status" className="muted">
          …
        </p>
      </main>
    );
  }
  return <Shell mode={mode}>{children}</Shell>;
}

function Shell({ children, mode }: { children: ReactNode; mode: "dev" | "oidc" }) {
  const pathname = usePathname() || "/";
  const { t, locale, setLocale } = useI18n();
  const { resolved, toggle } = useTheme();
  const { identity, logout, api } = useAuth();
  const router = useRouter();
  const [navOpen, setNavOpen] = useState(false);
  const kill = useResource(() => api.killSwitch(), [api], { intervalMs: 15000 });

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- закрыть мобильное меню после перехода
    setNavOpen(false);
  }, [pathname]);

  const menuRef = useRef<HTMLButtonElement>(null);
  const navRef = useRef<HTMLElement>(null);
  useEffect(() => {
    if (!navOpen) return;
    // Открытое меню на узком экране: фокус на первый пункт, Escape закрывает и возвращает фокус на кнопку.
    navRef.current?.querySelector<HTMLElement>("a[aria-current=page], a")?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setNavOpen(false);
        menuRef.current?.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [navOpen]);

  const tenantLabel = DEMO_TENANTS.find((x) => x.id === identity?.tenantId)?.label;
  const killActive = !!kill.data && (kill.data.tenant.active || kill.data.platform.active);

  return (
    <KillCtx.Provider value={kill}>
      <a className="skip-link" href="#main">
        {t("a11y.skipToContent")}
      </a>
      <div className="shell">
        <header className="header" aria-label="AdminTwin">
          <button
            ref={menuRef}
            type="button"
            className="header-action menu-button"
            aria-expanded={navOpen}
            aria-controls="primary-nav"
            aria-label={navOpen ? t("a11y.closeMenu") : t("a11y.openMenu")}
            title={navOpen ? t("a11y.closeMenu") : t("a11y.openMenu")}
            onClick={() => setNavOpen((v) => !v)}
          >
            <Icon name={navOpen ? "x" : "menu"} size={20} />
          </button>
          <Link href="/" className="brand">
            <LogoMark />
            <span>AdminTwin</span>
            <span className="brand-tag hide-sm">Observe · Analyze · Automate · Secure</span>
          </Link>
          <div className="header-spacer" />
          <div className="header-tools">
            {mode === "dev" ? (
              <span className="hide-sm">
                <span className="badge tone-dev header-tag" title={t("auth.dev.bannerText")}>
                  DEV
                </span>
              </span>
            ) : null}
            <div className="identity-chip" title={t("auth.signedInAs")}>
              <strong>{identity?.displayName || identity?.actorId}</strong>
              <span>{tenantLabel ? `${tenantLabel} · ` : ""}{identity?.roles.map((r) => t(`role.${r}` as MessageKey)).join(", ")}</span>
            </div>
            <label htmlFor="lang-select" className="visually-hidden">
              {t("settings.language")}
            </label>
            <select
              id="lang-select"
              className="header-select"
              value={locale}
              onChange={(e) => setLocale(e.target.value as Locale)}
              data-testid="lang-select"
            >
              {LOCALES.map((l) => (
                <option key={l} value={l}>
                  {t(`locale.${l}` as MessageKey)}
                </option>
              ))}
            </select>
            <button
              type="button"
              className="header-action"
              onClick={toggle}
              aria-label={resolved === "dark" ? t("theme.switchToLight") : t("theme.switchToDark")}
              title={resolved === "dark" ? t("theme.switchToLight") : t("theme.switchToDark")}
              data-testid="theme-toggle"
            >
              <Icon name={resolved === "dark" ? "sun" : "moon"} size={20} />
            </button>
            <button
              type="button"
              className="header-action"
              aria-label={t("auth.logout")}
              title={t("auth.logout")}
              onClick={() => {
                logout();
                router.replace("/login");
              }}
            >
              <Icon name="logout" size={20} />
            </button>
          </div>
        </header>

        <div className="banner-area">
          {mode === "dev" ? (
            <div className="dev-banner" role="note">
              <Icon name="warning" />
              {t("auth.dev.bannerText")}
            </div>
          ) : null}
          {killActive ? (
            <div className="kill-banner" role="alert" data-testid="kill-banner">
              <Icon name="stop" />
              <span>
                {kill.data?.platform.active ? t("kill.banner.platform") : t("kill.banner.tenant")}
              </span>
              <Link href="/settings">{t("kill.banner.manage")}</Link>
            </div>
          ) : null}
        </div>

        <button
          type="button"
          className="backdrop"
          data-open={navOpen}
          aria-hidden="true"
          tabIndex={-1}
          onClick={() => setNavOpen(false)}
        />
        <nav ref={navRef} id="primary-nav" className="sidebar" data-open={navOpen} aria-label={t("a11y.primaryNav")}>
          {NAV.map((g) => (
            <div key={g.group}>
              <p className="nav-group-title">{t(g.group)}</p>
              <ul className="nav-list">
                {g.items.map((it) => (
                  <li key={it.href}>
                    <Link className="nav-link" href={it.href} aria-current={isActive(pathname, it.href) ? "page" : undefined}>
                      <Icon name={it.icon} className="nav-icon" size={16} />
                      <span>{t(it.key)}</span>
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </nav>

        <main className="main" id="main" tabIndex={-1}>
          {children}
        </main>
      </div>
    </KillCtx.Provider>
  );
}
