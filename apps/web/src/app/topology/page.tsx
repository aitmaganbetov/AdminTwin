"use client";

import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { Suspense, useMemo, type KeyboardEvent } from "react";
import { Badge, ConfidenceBar, DataState, PageHeader, ProblemView, TableWrap } from "@/components/ui";
import type { Dependency, Topology } from "@/lib/api/types";
import { useApi } from "@/lib/auth/AuthProvider";
import { useI18n } from "@/lib/i18n/I18nProvider";
import { hotEdges, layoutTopology, NODE_H, NODE_W } from "@/lib/topology";
import { useResource } from "@/lib/useResource";

export default function TopologyPage() {
  return (
    <Suspense>
      <TopologyView />
    </Suspense>
  );
}

function TopologyView() {
  const { t } = useI18n();
  const api = useApi();
  const res = useResource(() => api.topology(), [api], { intervalMs: 30000 });
  return (
    <>
      <PageHeader title={t("nav.topology")} subtitle={t("topology.subtitle")} />
      <DataState res={res} isEmpty={(d) => (d.nodes || []).length === 0} emptyText={t("topology.empty")}>
        {(d) => <Graph topo={d} />}
      </DataState>
    </>
  );
}

function dash(e: Dependency): string | undefined {
  if (e.verified_by === "user") return undefined;
  if (e.verified_by === "agent") return "2 4";
  return "7 4";
}

function Graph({ topo }: { topo: Topology }) {
  const { t, te } = useI18n();
  const api = useApi();
  const search = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const selected = search.get("asset");
  const nodes = useMemo(() => topo.nodes || [], [topo.nodes]);
  const edges = useMemo(() => topo.edges || [], [topo.edges]);
  const layout = useMemo(() => layoutTopology(nodes, edges), [nodes, edges]);
  const blast = useResource(() => api.blastRadius(selected!), [api, selected], { enabled: !!selected });
  const br = selected && blast.data?.asset_id === selected ? blast.data : undefined;
  const impacted = useMemo(() => new Set((br?.items || []).map((i) => i.asset_id)), [br]);
  const hot = useMemo(() => hotEdges(edges, selected, impacted), [edges, selected, impacted]);
  const names = useMemo(() => new Map(nodes.map((n) => [n.id, n.name])), [nodes]);

  const select = (id: string | null) => router.replace(id && id !== selected ? `${pathname}?asset=${id}` : pathname, { scroll: false });
  const onKey = (e: KeyboardEvent, id: string) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      select(id);
    }
  };

  return (
    <div className="stack">
      <section className="card" aria-labelledby="topo-graph">
        <div className="card-title">
          <h2 id="topo-graph">{t("topology.graph")}</h2>
          {selected ? (
            <button type="button" className="btn btn-sm" onClick={() => select(null)}>
              {t("topology.clear")}
            </button>
          ) : null}
        </div>
        <p className="small muted" id="topo-help">
          {t("topology.help")}
        </p>
        <div className="topo-wrap">
          <svg
            className="topo-svg"
            viewBox={`0 0 ${layout.width} ${layout.height}`}
            role="group"
            aria-label={t("topology.graph")}
            aria-describedby="topo-help"
            style={{ maxWidth: Math.max(layout.width, 640) }}
          >
            <defs>
              <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
                <path d="M0 0 10 5 0 10z" className="topo-arrow" />
              </marker>
              <marker id="arrow-hot" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
                <path d="M0 0 10 5 0 10z" style={{ fill: "var(--danger)" }} />
              </marker>
            </defs>
            {edges.map((e, i) => {
              const s = layout.byId.get(e.source);
              const tg = layout.byId.get(e.target);
              if (!s || !tg) return null;
              const forward = tg.x > s.x;
              const x1 = forward ? s.x + NODE_W : s.x + NODE_W / 2;
              const y1 = forward ? s.y + NODE_H / 2 : s.y + NODE_H;
              const x2 = forward ? tg.x : tg.x + NODE_W / 2;
              const y2 = forward ? tg.y + NODE_H / 2 : tg.y + NODE_H;
              const mx = (x1 + x2) / 2;
              const d = forward
                ? `M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`
                : `M${x1},${y1} C${x1},${y1 + 60} ${x2},${y2 + 60} ${x2},${y2}`;
              const isHot = hot.has(i);
              const dim = !!selected && !isHot;
              return (
                <g key={i}>
                  <path
                    d={d}
                    className={`topo-edge${isHot ? " is-hot" : ""}${dim ? " is-dim" : ""}`}
                    strokeWidth={1 + 2.5 * e.confidence}
                    strokeDasharray={dash(e)}
                    markerEnd={`url(#${isHot ? "arrow-hot" : "arrow"})`}
                  />
                  <text x={mx} y={forward ? Math.min(y1, y2) - 20 : Math.max(y1, y2) + 34} textAnchor="middle" className="topo-edge-label">
                    <tspan x={mx}>{e.relation_type}</tspan>
                    <tspan x={mx} dy={13}>
                      {Math.round(e.confidence * 100)}% · {te("verifiedBy", e.verified_by)}
                    </tspan>
                  </text>
                </g>
              );
            })}
            {layout.nodes.map((n) => {
              const a = n.asset;
              const isSel = a.id === selected;
              const isImp = impacted.has(a.id);
              const dim = !!selected && !isSel && !isImp;
              return (
                <g
                  key={a.id}
                  className={`topo-node${isSel ? " is-selected" : ""}${isImp ? " is-impacted" : ""}${dim ? " is-dim" : ""}`}
                  transform={`translate(${n.x},${n.y})`}
                  role="button"
                  tabIndex={0}
                  aria-pressed={isSel}
                  aria-label={`${a.name}, ${a.type}, ${te("env", a.environment)}${isImp ? `, ${t("topology.impacted")}` : ""}${a.legal_hold ? `, ${t("asset.legalHold")}` : ""}`}
                  onClick={() => select(a.id)}
                  onKeyDown={(e) => onKey(e, a.id)}
                  data-testid={`topo-node-${a.name}`}
                >
                  <rect width={NODE_W} height={NODE_H} rx={8} />
                  <text x={12} y={22}>
                    {a.name.length > 18 ? `${a.name.slice(0, 17)}…` : a.name}
                  </text>
                  {a.legal_hold ? (
                    <g transform={`translate(${NODE_W - 30},6)`} aria-hidden="true">
                      <rect width={24} height={16} rx={4} style={{ fill: "var(--danger-bg)", stroke: "var(--danger)" }} />
                      <text x={12} y={12} textAnchor="middle" style={{ fill: "var(--danger)", fontSize: 10, fontWeight: 700 }}>
                        LH
                      </text>
                    </g>
                  ) : null}
                  <text x={12} y={41} className="sub">
                    {a.type} · tier {a.service_tier ?? "—"} · {a.criticality}
                  </text>
                </g>
              );
            })}
          </svg>
        </div>
        <div className="legend" aria-label={t("topology.legend")}>
          <span>
            <svg width="36" height="8" aria-hidden="true">
              <line x1="0" y1="4" x2="36" y2="4" stroke="var(--border-strong)" strokeWidth="2.5" />
            </svg>
            {t("topology.legend.user")}
          </span>
          <span>
            <svg width="36" height="8" aria-hidden="true">
              <line x1="0" y1="4" x2="36" y2="4" stroke="var(--border-strong)" strokeWidth="2.5" strokeDasharray="7 4" />
            </svg>
            {t("topology.legend.discovery")}
          </span>
          <span>
            <svg width="36" height="8" aria-hidden="true">
              <line x1="0" y1="4" x2="36" y2="4" stroke="var(--border-strong)" strokeWidth="2.5" strokeDasharray="2 4" />
            </svg>
            {t("topology.legend.agent")}
          </span>
          <span>{t("topology.legend.width")}</span>
          <span>
            <i className="swatch" style={{ borderColor: "var(--accent)", background: "var(--accent-soft)" }} /> {t("topology.selected")}
          </span>
          <span>
            <i className="swatch" style={{ borderColor: "var(--danger)", background: "var(--danger-bg)" }} /> {t("topology.impacted")}
          </span>
        </div>
      </section>

      {selected ? (
        <section className="card" aria-labelledby="topo-br" aria-live="polite">
          <h2 id="topo-br">
            {t("topology.blastRadiusOf", { name: names.get(selected) || selected })}
          </h2>
          {blast.error ? (
            <ProblemView error={blast.error} onRetry={blast.reload} />
          ) : !br ? (
            <p className="muted">{t("common.loading")}</p>
          ) : br.items.length === 0 ? (
            <p className="muted" data-testid="blast-empty">
              {t("impact.none")}
            </p>
          ) : (
            <TableWrap label={t("topology.blastRadiusOf", { name: names.get(selected) || selected })}>
              <table data-testid="blast-table">
                <thead>
                  <tr>
                    <th scope="col">{t("asset.name")}</th>
                    <th scope="col">{t("impact.depth")}</th>
                    <th scope="col">{t("asset.tier")}</th>
                    <th scope="col">{t("asset.criticality")}</th>
                    <th scope="col">{t("topology.confidence")}</th>
                  </tr>
                </thead>
                <tbody>
                  {br.items.map((b) => (
                    <tr key={b.asset_id}>
                      <td className="nowrap">{b.name}</td>
                      <td>{b.depth}</td>
                      <td>{b.service_tier ?? "—"}</td>
                      <td>{b.criticality}</td>
                      <td>
                        <ConfidenceBar value={b.confidence} label={t("topology.confidence")} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          )}
          <p className="small" style={{ marginTop: 8 }}>
            <Link href={`/changes/new?asset=${selected}`}>{t("assets.change")}</Link>
          </p>
        </section>
      ) : null}

      <section className="card" aria-labelledby="topo-edges">
        <h2 id="topo-edges">{t("topology.edges")}</h2>
        <TableWrap label={t("topology.edges")}>
          <table>
            <thead>
              <tr>
                <th scope="col">{t("topology.source")}</th>
                <th scope="col">{t("topology.relation")}</th>
                <th scope="col">{t("topology.target")}</th>
                <th scope="col">{t("topology.confidence")}</th>
                <th scope="col">{t("topology.verifiedBy")}</th>
              </tr>
            </thead>
            <tbody>
              {edges.map((e, i) => (
                <tr key={i}>
                  <td>{names.get(e.source) || e.source}</td>
                  <td>
                    <code>{e.relation_type}</code>
                  </td>
                  <td>{names.get(e.target) || e.target}</td>
                  <td>
                    <ConfidenceBar value={e.confidence} label={t("topology.confidence")} />
                  </td>
                  <td>
                    <Badge tone={e.verified_by === "user" ? "success" : "info"}>{te("verifiedBy", e.verified_by)}</Badge>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      </section>
    </div>
  );
}
