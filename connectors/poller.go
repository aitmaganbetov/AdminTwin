package connectors

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/aitmaganbetov/admintwin/connectors/db"
	"github.com/aitmaganbetov/admintwin/connectors/docker"
	"github.com/aitmaganbetov/admintwin/connectors/linux"
	"github.com/aitmaganbetov/admintwin/services/inventory"
	"github.com/aitmaganbetov/admintwin/services/telemetry"
)

// Poller — периодический опрос метрик активов с Connection и запись в telemetry.Sink:
// ssh → node_cpu_usage_percent, node_memory_used_percent, node_disk_used_percent{mount};
// docker_api → container_up{container}, container_restarts_total{container};
// postgres → pg_connections_total, pg_connections_max, pg_replication_lag_bytes{client}.
// Недоступный актив пропускается (журнал), опрос остальных продолжается.
type Poller struct {
	s       *Set
	sink    telemetry.Sink
	tenants func() []string
	// Interval — период опроса (по умолчанию 30 с).
	Interval time.Duration
	// Concurrency — одновременно опрашиваемых активов (по умолчанию 8).
	Concurrency int
	// AssetTimeout — предел опроса одного актива (по умолчанию 20 с).
	AssetTimeout time.Duration
}

// Poller создаёт опросчик. tenants возвращает tenant_id, чьи активы опрашиваются
// (inventory.Repository не перечисляет tenants).
func (s *Set) Poller(sink telemetry.Sink, tenants func() []string) *Poller {
	return &Poller{s: s, sink: sink, tenants: tenants, Interval: 30 * time.Second, Concurrency: 8, AssetTimeout: 20 * time.Second}
}

// Run опрашивает до отмены контекста.
func (p *Poller) Run(ctx context.Context) {
	t := time.NewTicker(p.Interval)
	defer t.Stop()
	for {
		_ = p.PollOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// PollOnce — один проход по всем активам. Возвращает объединённые ошибки (для тестов и диагностики).
func (p *Poller) PollOnce(ctx context.Context) error {
	if p.s.cfg.Inventory == nil || p.sink == nil || p.tenants == nil {
		return errors.New("poller is not configured")
	}
	conc := max(p.Concurrency, 1)
	sem := make(chan struct{}, conc)
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
	)
tenants:
	for _, tid := range p.tenants() {
		for _, a := range p.s.cfg.Inventory.List(tid) {
			if a.Connection == nil || a.TenantID != tid {
				continue
			}
			switch a.Connection.Method {
			case linux.Method, docker.Method, db.Method:
			default:
				continue
			}
			if ctx.Err() != nil {
				break tenants
			}
			sem <- struct{}{}
			wg.Add(1)
			go func(a inventory.Asset) {
				defer func() { <-sem; wg.Done() }()
				if err := p.pollAsset(ctx, a); err != nil {
					p.s.log.Warn("metrics poll failed", "tenant_id", a.TenantID, "asset_id", a.ID, "method", a.Connection.Method, "error", err.Error())
					mu.Lock()
					errs = append(errs, err)
					mu.Unlock()
				}
			}(a)
		}
	}
	wg.Wait()
	return errors.Join(errs...)
}

func (p *Poller) pollAsset(ctx context.Context, a inventory.Asset) error {
	ctx, cancel := context.WithTimeout(ctx, p.AssetTimeout)
	defer cancel()
	cred, err := p.s.readOnly(ctx, &a)
	if err != nil {
		return err
	}
	var samples []telemetry.Sample
	switch a.Connection.Method {
	case linux.Method:
		samples, err = p.s.linux.Metrics(ctx, a, cred)
	case docker.Method:
		samples, err = p.s.docker.Metrics(ctx, a, cred)
	case db.Method:
		samples, err = p.s.pg.Metrics(ctx, a, cred)
	}
	if err != nil {
		return err
	}
	if len(samples) == 0 {
		return nil
	}
	return p.sink.WriteSamples(ctx, samples)
}
