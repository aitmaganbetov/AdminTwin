import { NextResponse, type NextRequest } from "next/server";

// В OIDC-режиме клиентские заголовки идентичности X-AdminTwin-* не должны доходить до ядра через rewrite:
// личность определяет только Bearer-токен (защита в глубину, если ядро ошибочно запущено с dev-аутентификацией).
const oidc = Boolean(process.env.NEXT_PUBLIC_OIDC_ISSUER);

export function middleware(req: NextRequest) {
  if (!oidc) return NextResponse.next();
  const headers = new Headers(req.headers);
  for (const name of [...headers.keys()]) {
    if (name.toLowerCase().startsWith("x-admintwin-")) headers.delete(name);
  }
  return NextResponse.next({ request: { headers } });
}

export const config = { matcher: "/api/v1/:path*" };
