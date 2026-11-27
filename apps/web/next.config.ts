import type { NextConfig } from "next";

// UI ходит только в /api/v1/* ядра (docs/api/stage1-contracts.md §5).
// ADMINTWIN_CORE_URL читается при `next dev` и при `next build` (rewrites попадают в routes-manifest).
const coreUrl = (process.env.ADMINTWIN_CORE_URL || "http://localhost:8080").replace(/\/+$/, "");

const securityHeaders = [
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "no-referrer" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
];

const nextConfig: NextConfig = {
  // Docker-образ собирается с ADMINTWIN_WEB_STANDALONE=1 (node .next/standalone/server.js); локально — `next start`.
  output: process.env.ADMINTWIN_WEB_STANDALONE === "1" ? "standalone" : undefined,
  reactStrictMode: true,
  poweredByHeader: false,
  // SSE (agent-tasks/chat events) не должен буферизоваться gzip-сжатием прокси.
  compress: false,
  async rewrites() {
    return [{ source: "/api/v1/:path*", destination: `${coreUrl}/api/v1/:path*` }];
  },
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
};

export default nextConfig;
