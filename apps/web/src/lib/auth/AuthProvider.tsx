"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { ApiClient } from "../api/client";
import { endpoints, type Endpoints } from "../api/endpoints";
import type { Identity } from "../permissions";
import { devHeaders, loadDevIdentity, saveDevIdentity } from "./dev";
import { beginLogin, completeLogin, identityFromTokens, oidcConfigFromEnv, type OidcConfig } from "./oidc";
import { SessionStore } from "./session";

export type AuthMode = "oidc" | "dev";

interface AuthCtx {
  mode: AuthMode;
  ready: boolean;
  identity: Identity | null;
  /** Сессия завершилась (401) — нужен повторный вход. */
  expired: boolean;
  client: ApiClient;
  api: Endpoints;
  devLogin: (id: Identity) => void;
  oidcLogin: (returnTo: string) => Promise<void>;
  oidcCallback: (search: URLSearchParams) => Promise<string>;
  logout: () => void;
}

const Ctx = createContext<AuthCtx | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const oidc = useMemo<OidcConfig | null>(() => oidcConfigFromEnv(), []);
  const mode: AuthMode = oidc ? "oidc" : "dev";
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [ready, setReady] = useState(false);
  const [expired, setExpired] = useState(false);
  // Изменяемое хранилище сессии: токен — только в памяти, никогда в localStorage/sessionStorage.
  const [session] = useState(() => new SessionStore());

  useEffect(() => {
    if (mode === "dev") {
      const id = loadDevIdentity();
      if (id) {
        session.set(id);
        // eslint-disable-next-line react-hooks/set-state-in-effect -- восстановление DEV-идентичности вкладки
        setIdentity(id);
      }
    }
    setReady(true);
  }, [mode, session]);

  const client = useMemo(
    () =>
      new ApiClient({
        getHeaders: () => {
          if (mode === "oidc") {
            const token = session.accessToken();
            return token ? { Authorization: `Bearer ${token}` } : {};
          }
          const id = session.currentIdentity();
          return id ? devHeaders(id) : {};
        },
        onUnauthenticated: () => setExpired(true),
      }),
    [mode, session],
  );
  const api = useMemo(() => endpoints(client), [client]);

  const devLogin = useCallback((id: Identity) => {
    saveDevIdentity(id);
    session.set(id);
    setIdentity(id);
    setExpired(false);
  }, [session]);

  const oidcLogin = useCallback(
    async (returnTo: string) => {
      if (!oidc) return;
      await beginLogin(oidc, returnTo);
    },
    [oidc],
  );

  const oidcCallback = useCallback(
    async (search: URLSearchParams) => {
      if (!oidc) throw new Error("OIDC is not configured");
      const { tokens: t, returnTo } = await completeLogin(oidc, search);
      const id = identityFromTokens(oidc, t);
      session.set(id, t);
      setIdentity(id);
      setExpired(false);
      return returnTo;
    },
    [oidc, session],
  );

  const logout = useCallback(() => {
    session.clear();
    saveDevIdentity(null);
    setIdentity(null);
    setExpired(false);
  }, [session]);

  const value = useMemo<AuthCtx>(
    () => ({ mode, ready, identity, expired, client, api, devLogin, oidcLogin, oidcCallback, logout }),
    [mode, ready, identity, expired, client, api, devLogin, oidcLogin, oidcCallback, logout],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useAuth(): AuthCtx {
  const v = useContext(Ctx);
  if (!v) throw new Error("useAuth outside AuthProvider");
  return v;
}

export function useApi(): Endpoints {
  return useAuth().api;
}
