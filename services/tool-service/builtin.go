package toolsvc

import (
	"context"
	"fmt"

	"github.com/aitmaganbetov/admintwin/pkg/problem"
)

// registerBuiltins — инструменты поверх CMDB.
func (s *Service) registerBuiltins() {
	if _, ok := s.contracts["asset.get"]; ok {
		s.handlers["asset.get"] = s.assetGet
	}
	if _, ok := s.contracts["topology.blast_radius"]; ok {
		s.handlers["topology.blast_radius"] = s.blastRadius
	}
}

func (s *Service) assetGet(_ context.Context, c Call) (Result, error) {
	a := c.Asset
	if a == nil {
		return Result{}, problem.New(problem.NotFound, "asset not found")
	}
	env := a.Environment
	if env == "" {
		env = "test" // неклассифицированный актив никогда не трактуется как production-разрешение; см. preflight
	}
	crit := a.Criticality
	if crit == "" {
		crit = "low"
	}
	out := map[string]any{
		"asset_id": a.ID, "name": a.Name, "type": a.Type, "environment": env, "criticality": crit,
		"ring": nullable(a.Ring), "service_tier": nil, "data_class": orUnknown(a.DataClass), "legal_hold": a.LegalHold,
		"tags": map[string]any{},
	}
	if a.ServiceTier != nil {
		out["service_tier"] = *a.ServiceTier
	}
	if a.Environment == "" || a.Criticality == "" {
		out["tags"] = map[string]any{"classification": "incomplete"}
	}
	return Result{Data: out}, nil
}

func (s *Service) blastRadius(_ context.Context, c Call) (Result, error) {
	depth := 5
	if d, ok := c.Input["depth"]; ok {
		if f, err := toInt(d); err == nil {
			depth = f
		}
	}
	items, err := s.inv.BlastRadius(c.TenantID, c.Asset.ID, depth)
	if err != nil {
		return Result{}, problem.New(problem.NotFound, "asset not found")
	}
	nodes := make([]map[string]any, 0, len(items))
	inSet := map[string]bool{c.Asset.ID: true}
	for _, it := range items {
		a, _ := s.inv.Get(c.TenantID, it.AssetID)
		typ := "unknown"
		if a != nil {
			typ = a.Type
		}
		nodes = append(nodes, map[string]any{"asset_id": it.AssetID, "name": it.Name, "type": typ, "depth": it.Depth})
		inSet[it.AssetID] = true
	}
	edges := []map[string]any{}
	for _, d := range s.inv.Dependencies(c.TenantID) {
		if inSet[d.Source] && inSet[d.Target] {
			edges = append(edges, map[string]any{"from": d.Source, "to": d.Target, "kind": d.RelationType, "source": d.VerifiedBy, "confidence": d.Confidence})
		}
	}
	return Result{Data: map[string]any{"asset_id": c.Asset.ID, "nodes": nodes, "edges": edges}}, nil
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func toInt(v any) (int, error) {
	switch x := v.(type) {
	case float64:
		return int(x), nil
	case int:
		return x, nil
	case interface{ Int64() (int64, error) }:
		n, err := x.Int64()
		return int(n), err
	}
	return 0, fmt.Errorf("not an integer")
}
