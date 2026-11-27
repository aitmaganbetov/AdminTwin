package main

import "testing"

// Значения по умолчанию воспроизводят ориентиры ТЗ §9.1 для 1000 активов.
func TestDefaultsMatchSpecBallpark(t *testing.T) {
	r, err := Compute(Defaults())
	if err != nil {
		t.Fatal(err)
	}
	perYear := map[string]float64{}
	for _, l := range r.Lines {
		if l.Tier == "hot" || l.Kind == "audit" {
			perYear[l.Kind] = l.PerYearGB
		}
	}
	check := func(kind string, lo, hi float64) {
		if v := perYear[kind]; v < lo || v > hi {
			t.Errorf("%s: %.1f GB/year outside the spec ballpark [%v, %v]", kind, v, lo, hi)
		}
	}
	check("metrics raw", 150, 250)
	check("logs", 1000, 3000)
	check("audit", 15, 25)

	in := Defaults()
	in.FlowsPerSecond = 3000
	r, _ = Compute(in)
	var flows float64
	for _, l := range r.Lines {
		if l.Kind == "flows raw" {
			flows = l.PerYearGB
		}
	}
	if flows < 2000 || flows > 5000 {
		t.Errorf("flows raw %.0f GB/year outside 2–5 TB", flows)
	}
	in.ReplicationFactor = 2
	r2, _ := Compute(in)
	if r2.TotalGB < 1.99*r.TotalGB || r2.TotalGB > 2.01*r.TotalGB {
		t.Errorf("replication factor must scale storage: %v vs %v", r2.TotalGB, r.TotalGB)
	}
	if _, err := Compute(Input{}); err == nil {
		t.Error("empty input must be rejected")
	}
}
