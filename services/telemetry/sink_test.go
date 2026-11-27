package telemetry

import (
	"context"
	"testing"
	"time"

	"github.com/aitmaganbetov/admintwin/services/inventory"
)

func TestRetentionFromEnv(t *testing.T) {
	env := map[string]string{"ADMINTWIN_RETENTION_LOGS": "90d"}
	r, err := RetentionFromEnv(func(k string) string { return env[k] })
	if err != nil || r.Logs != 90*Day || r.MetricsRaw != 15*Day {
		t.Fatalf("%+v %v", r, err)
	}
	env["ADMINTWIN_RETENTION_EVENTS"] = "forever"
	if _, err := RetentionFromEnv(func(k string) string { return env[k] }); err == nil {
		t.Fatal("invalid retention must fail")
	}
}

type countingSub struct{ n int }

func (c *countingSub) HandleEvents(_ context.Context, _ string, evs []Event) ([]string, error) {
	c.n += len(evs)
	return nil, nil
}

func TestPipelineSinkAppliesRules(t *testing.T) {
	inv := inventory.NewStore()
	_ = inv.Put(inventory.Asset{ID: "a1", TenantID: tA, Name: "h", Type: "docker_host"})
	svc := NewService(NewMemoryStore(Limits{}, Retention{}), inv)
	sub := &countingSub{}
	svc.Subscriber = sub
	sink := svc.AsSink()
	ctx := context.Background()
	if err := sink.WriteSamples(ctx, []Sample{{TenantID: tA, AssetID: "a1", Metric: "container_up", Labels: map[string]string{"container": "api"}, Value: 0, At: time.Now()}}); err != nil {
		t.Fatal(err)
	}
	if sub.n != 1 {
		t.Fatalf("container_up=0 through Sink must produce an event, got %d", sub.n)
	}
	if err := sink.WriteSamples(ctx, []Sample{{AssetID: "a1", Metric: "m", Value: 1}}); err == nil {
		t.Fatal("record without tenant must be rejected")
	}
	if err := sink.WriteLogs(ctx, []LogRecord{{TenantID: tB, AssetID: "a1", Message: "x"}}); err == nil {
		t.Fatal("asset of another tenant must be rejected")
	}
}
