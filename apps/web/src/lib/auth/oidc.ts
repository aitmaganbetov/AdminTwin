// OIDC Authorization Code + PKCE (S256) для публичного клиента.
// Токены хранятся ТОЛЬКО в памяти; в sessionStorage — лишь одноразовые state/verifier на время редиректа.
import type { Role } from "../api/types";
import { ALL_ROLES } from "../api/types";
import type { Identity } from "../permissions";

export interface OidcConfig {
  issuer: string;
  clientId: string;
  scope: string;
  audience?: string;
  rolesClaim: string;
  tenantClaim: string;
}

export function oidcConfigFromEnv(): OidcConfig | null {
  const issuer = process.env.NEXT_PUBLIC_OIDC_ISSUER;
  if (!issuer) return null;
  return {
    issuer: issuer.replace(/\/+$/, ""),
    clientId: process.env.NEXT_PUBLIC_OIDC_CLIENT_ID || "admintwin-web",
    scope: process.env.NEXT_PUBLIC_OIDC_SCOPE || "openid profile email",
    audience: process.env.NEXT_PUBLIC_OIDC_AUDIENCE || undefined,
    rolesClaim: process.env.NEXT_PUBLIC_OIDC_ROLES_CLAIM || "roles",
    tenantClaim: process.env.NEXT_PUBLIC_OIDC_TENANT_CLAIM || "tenant_id",
  };
}

export interface OidcTokens {
  accessToken: string;
  idToken?: string;
  expiresAt: number;
}

interface Discovery {
  authorization_endpoint: string;
  token_endpoint: string;
  end_session_endpoint?: string;
}

const PENDING_KEY = "admintwin.oidc.pending";

export function base64UrlEncode(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function randomString(bytes = 32): string {
  const b = new Uint8Array(bytes);
  crypto.getRandomValues(b);
  return base64UrlEncode(b);
}

/** code_challenge = BASE64URL(SHA256(verifier)) — RFC 7636 §4.2. */
export async function pkceChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return base64UrlEncode(new Uint8Array(digest));
}

async function discover(issuer: string): Promise<Discovery> {
  const res = await fetch(`${issuer}/.well-known/openid-configuration`, { cache: "no-store" });
  if (!res.ok) throw new Error(`OIDC discovery failed: HTTP ${res.status}`);
  return (await res.json()) as Discovery;
}

export async function beginLogin(cfg: OidcConfig, returnTo: string): Promise<void> {
  const d = await discover(cfg.issuer);
  const verifier = randomString(48);
  const state = randomString(16);
  const nonce = randomString(16);
  const redirectUri = `${window.location.origin}/auth/callback`;
  window.sessionStorage.setItem(PENDING_KEY, JSON.stringify({ verifier, state, nonce, returnTo, redirectUri }));
  const u = new URL(d.authorization_endpoint);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", cfg.clientId);
  u.searchParams.set("redirect_uri", redirectUri);
  u.searchParams.set("scope", cfg.scope);
  u.searchParams.set("state", state);
  u.searchParams.set("nonce", nonce);
  u.searchParams.set("code_challenge", await pkceChallenge(verifier));
  u.searchParams.set("code_challenge_method", "S256");
  if (cfg.audience) u.searchParams.set("audience", cfg.audience);
  window.location.assign(u.toString());
}

export async function completeLogin(cfg: OidcConfig, search: URLSearchParams): Promise<{ tokens: OidcTokens; returnTo: string }> {
  const raw = window.sessionStorage.getItem(PENDING_KEY);
  window.sessionStorage.removeItem(PENDING_KEY);
  if (!raw) throw new Error("OIDC: no pending login");
  const pending = JSON.parse(raw) as { verifier: string; state: string; nonce: string; returnTo: string; redirectUri: string };
  const err = search.get("error");
  if (err) throw new Error(`OIDC: ${err} ${search.get("error_description") || ""}`.trim());
  if (search.get("state") !== pending.state) throw new Error("OIDC: state mismatch");
  const code = search.get("code");
  if (!code) throw new Error("OIDC: missing code");
  const d = await discover(cfg.issuer);
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: pending.redirectUri,
    client_id: cfg.clientId,
    code_verifier: pending.verifier,
  });
  const res = await fetch(d.token_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
    cache: "no-store",
  });
  if (!res.ok) throw new Error(`OIDC token exchange failed: HTTP ${res.status}`);
  const tr = (await res.json()) as { access_token: string; id_token?: string; expires_in?: number };
  if (!tr.access_token) throw new Error("OIDC: no access_token");
  if (tr.id_token) {
    const claims = decodeJwt(tr.id_token);
    if (claims && claims.nonce !== undefined && claims.nonce !== pending.nonce) throw new Error("OIDC: nonce mismatch");
  }
  return {
    tokens: { accessToken: tr.access_token, idToken: tr.id_token, expiresAt: Date.now() + (tr.expires_in ?? 300) * 1000 },
    returnTo: safeReturnTo(pending.returnTo),
  };
}

/** Только относительные пути внутри приложения (защита от open redirect). */
export function safeReturnTo(p: string | null | undefined): string {
  if (!p || !p.startsWith("/") || p.startsWith("//") || p.startsWith("/\\")) return "/";
  return p;
}

/** Декодирование payload JWT для отображения (подпись проверяет ядро). */
export function decodeJwt(token: string): Record<string, unknown> | null {
  const part = token.split(".")[1];
  if (!part) return null;
  try {
    const b64 = part.replace(/-/g, "+").replace(/_/g, "/");
    const json = decodeURIComponent(
      Array.from(atob(b64 + "===".slice((b64.length + 3) % 4)), (c) => "%" + c.charCodeAt(0).toString(16).padStart(2, "0")).join(""),
    );
    return JSON.parse(json) as Record<string, unknown>;
  } catch {
    return null;
  }
}

export function identityFromTokens(cfg: OidcConfig, t: OidcTokens): Identity {
  const claims = decodeJwt(t.idToken || t.accessToken) || {};
  const access = decodeJwt(t.accessToken) || {};
  const pick = (k: string) => access[k] ?? claims[k];
  const rawRoles = pick(cfg.rolesClaim);
  const roles = (Array.isArray(rawRoles) ? rawRoles : typeof rawRoles === "string" ? rawRoles.split(/[ ,]/) : [])
    .map(String)
    .filter((r): r is Role => (ALL_ROLES as string[]).includes(r));
  const rawScopes = pick("admintwin_scopes");
  const scopes = Array.isArray(rawScopes) ? rawScopes.map(String) : [];
  return {
    actorId: String(pick("sub") ?? "unknown"),
    tenantId: String(pick(cfg.tenantClaim) ?? ""),
    roles,
    scopes,
    displayName: typeof claims.name === "string" ? claims.name : typeof claims.email === "string" ? claims.email : undefined,
  };
}
