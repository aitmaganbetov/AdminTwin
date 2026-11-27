// Сессия в памяти вкладки: токен OIDC никогда не попадает в localStorage/sessionStorage.
import type { Identity } from "../permissions";
import type { OidcTokens } from "./oidc";

export class SessionStore {
  private tokens: OidcTokens | null = null;
  private identity: Identity | null = null;

  set(identity: Identity | null, tokens: OidcTokens | null = null): void {
    this.identity = identity;
    this.tokens = tokens;
  }

  clear(): void {
    this.set(null, null);
  }

  /** Действующий access token или null (истёкший токен не отправляется). */
  accessToken(): string | null {
    const t = this.tokens;
    if (!t) return null;
    return t.expiresAt > Date.now() ? t.accessToken : null;
  }

  currentIdentity(): Identity | null {
    return this.identity;
  }
}
