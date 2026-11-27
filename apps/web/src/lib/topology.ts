// Слоистая раскладка графа зависимостей (source зависит от target): потребители слева, основания справа.
import type { Asset, Dependency } from "./api/types";

export interface LaidNode {
  asset: Asset;
  layer: number;
  row: number;
  x: number;
  y: number;
}

export interface Layout {
  nodes: LaidNode[];
  byId: Map<string, LaidNode>;
  width: number;
  height: number;
}

export const NODE_W = 176;
export const NODE_H = 56;
const COL_GAP = 170;
const ROW_GAP = 40;
const PAD = 24;

/** layer = длина самого длинного пути от узла без входящих рёбер (с защитой от циклов). */
export function computeLayers(ids: string[], edges: Pick<Dependency, "source" | "target">[]): Map<string, number> {
  const layer = new Map<string, number>(ids.map((id) => [id, 0]));
  const known = new Set(ids);
  const es = edges.filter((e) => known.has(e.source) && known.has(e.target) && e.source !== e.target);
  for (let i = 0; i < ids.length; i++) {
    let changed = false;
    for (const e of es) {
      const want = (layer.get(e.source) ?? 0) + 1;
      if (want > (layer.get(e.target) ?? 0) && want < ids.length) {
        layer.set(e.target, want);
        changed = true;
      }
    }
    if (!changed) break;
  }
  return layer;
}

export function layoutTopology(nodes: Asset[], edges: Dependency[]): Layout {
  const layers = computeLayers(
    nodes.map((n) => n.id),
    edges,
  );
  const cols = new Map<number, Asset[]>();
  for (const n of [...nodes].sort((a, b) => a.name.localeCompare(b.name))) {
    const l = layers.get(n.id) ?? 0;
    if (!cols.has(l)) cols.set(l, []);
    cols.get(l)!.push(n);
  }
  const laid: LaidNode[] = [];
  let maxRows = 0;
  for (const [l, list] of cols) {
    maxRows = Math.max(maxRows, list.length);
    list.forEach((asset, row) => {
      laid.push({ asset, layer: l, row, x: PAD + l * (NODE_W + COL_GAP), y: PAD + row * (NODE_H + ROW_GAP) });
    });
  }
  const maxLayer = Math.max(0, ...laid.map((n) => n.layer));
  return {
    nodes: laid,
    byId: new Map(laid.map((n) => [n.asset.id, n])),
    width: PAD * 2 + (maxLayer + 1) * NODE_W + maxLayer * COL_GAP,
    height: PAD * 2 + Math.max(1, maxRows) * NODE_H + Math.max(0, maxRows - 1) * ROW_GAP,
  };
}

/** Рёбра на пути распространения влияния: source ∈ impacted, target ∈ impacted ∪ {selected}. */
export function hotEdges(edges: Dependency[], selected: string | null, impacted: Set<string>): Set<number> {
  const out = new Set<number>();
  if (!selected) return out;
  edges.forEach((e, i) => {
    if (impacted.has(e.source) && (impacted.has(e.target) || e.target === selected)) out.add(i);
  });
  return out;
}
