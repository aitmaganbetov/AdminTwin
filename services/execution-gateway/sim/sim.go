// Package sim — симулятор инфраструктуры для разработки и тестов. Реализует те же интерфейсы,
// что и реальные коннекторы (Facts, Engine, CredentialBroker), с внедрением отказов.
// Не используется в production-сборке: включается только флагом ADMINTWIN_SIMULATOR=true.
package sim

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	gateway "github.com/aitmaganbetov/admintwin/services/execution-gateway"
)

// Fault — внедряемый отказ при следующем исполнении на активе.
type Fault string

const (
	FaultNone          Fault = ""
	FaultPostCheckFail Fault = "post_check_fail" // объект не поднимается после действия
	FaultChannelLost   Fault = "channel_lost"    // потеря управляющего канала
	FaultHangConfirm   Fault = "hang_confirm"    // зависание; отмена подтверждается движком
	FaultHangNoConfirm Fault = "hang_noconfirm"  // зависание; движок не может подтвердить отмену
	FaultExitNonZero   Fault = "exit_nonzero"
)

// Infra — состояние симулируемой инфраструктуры.
type Infra struct {
	mu        sync.Mutex
	running   map[string]bool // asset/object -> running
	restarts  map[string][]time.Time
	disk      map[string]float64 // asset -> %
	faults    map[string]Fault   // asset -> fault
	vaultDown bool
	leases    map[string]time.Time
	Started   chan string // сигнал о старте исполнения (для тестов kill switch); может быть nil
}

// New создаёт симулятор.
func New() *Infra {
	return &Infra{running: map[string]bool{}, restarts: map[string][]time.Time{}, disk: map[string]float64{}, faults: map[string]Fault{}, leases: map[string]time.Time{}}
}

func key(asset, obj string) string { return asset + "/" + obj }

// SetRunning задаёт состояние объекта (контейнер/юнит).
func (s *Infra) SetRunning(asset, obj string, v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.running[key(asset, obj)] = v
}

// SetDisk задаёт заполненность диска.
func (s *Infra) SetDisk(asset string, pct float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.disk[asset] = pct
}

// InjectFault задаёт отказ на следующем исполнении.
func (s *Infra) InjectFault(asset string, f Fault) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.faults[asset] = f
}

// SetVaultDown имитирует недоступность Vault.
func (s *Infra) SetVaultDown(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vaultDown = v
}

// ActiveLeases — число невыведенных краткоживущих кредов.
func (s *Infra) ActiveLeases() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.leases)
}

// --- Facts ---

func (s *Infra) ContainerRunning(_, asset, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running[key(asset, id)], nil
}

func (s *Infra) UnitActive(_, asset, unit string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running[key(asset, unit)], nil
}

func (s *Infra) RestartsLastHour(_, asset, obj string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, t := range s.restarts[key(asset, obj)] {
		if time.Since(t) < time.Hour {
			n++
		}
	}
	return n, nil
}

func (s *Infra) DiskUsagePercent(_, asset string) (float64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.disk[asset], nil
}

func (s *Infra) LogWritersHealthy(_, _ string) (bool, error) { return true, nil }

func (s *Infra) HealthOK(_, asset, _ string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.faults[asset] != FaultPostCheckFail, nil
}

// --- CredentialBroker ---

func (s *Infra) Lease(_ context.Context, _, _ string, ttl time.Duration) (gateway.Lease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vaultDown {
		return gateway.Lease{}, errors.New("vault sealed or unreachable")
	}
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	h := "lease-" + hex.EncodeToString(b)
	s.leases[h] = time.Now().Add(ttl)
	return gateway.Lease{Handle: h, ExpiresAt: time.Now().Add(ttl)}, nil
}

func (s *Infra) Revoke(_ context.Context, l gateway.Lease) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.leases, l.Handle)
	return nil
}

// --- Engines ---

// Engines возвращает движки docker_api, ssh_argv, builtin поверх симулятора.
func (s *Infra) Engines() map[string]gateway.Engine {
	return map[string]gateway.Engine{"docker_api": engine{s}, "ssh_argv": engine{s}, "builtin": engine{s}}
}

type engine struct{ s *Infra }

func (e engine) Execute(ctx context.Context, r gateway.EngineRequest) (gateway.EngineResult, error) {
	s := e.s
	s.mu.Lock()
	fault := s.faults[r.AssetID]
	s.faults[r.AssetID] = FaultNone
	started := s.Started
	s.mu.Unlock()
	if started != nil {
		started <- r.AssetID
	}

	switch fault {
	case FaultChannelLost:
		return gateway.EngineResult{}, gateway.ErrChannelLost
	case FaultHangConfirm:
		<-ctx.Done()
		return gateway.EngineResult{}, gateway.ErrCancelConfirmed
	case FaultHangNoConfirm:
		<-ctx.Done()
		return gateway.EngineResult{}, ctx.Err()
	case FaultExitNonZero:
		return gateway.EngineResult{Stderr: "operation failed token=abc123", ExitCode: 1}, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if fault == FaultPostCheckFail {
		s.faults[r.AssetID] = FaultPostCheckFail // держим отказ для health-check
	}
	switch r.Action {
	case "restart":
		id := fmt.Sprint(r.Params["container_id"])
		s.restarts[key(r.AssetID, id)] = append(s.restarts[key(r.AssetID, id)], time.Now())
		s.running[key(r.AssetID, id)] = fault != FaultPostCheckFail
		return gateway.EngineResult{Stdout: "container " + id + " restarted"}, nil
	case "systemctl_restart":
		if len(r.Argv) != 3 || r.Argv[0] != "systemctl" || r.Argv[1] != "restart" {
			return gateway.EngineResult{ExitCode: 2, Stderr: "unexpected argv"}, nil
		}
		unit := r.Argv[2]
		s.restarts[key(r.AssetID, unit)] = append(s.restarts[key(r.AssetID, unit)], time.Now())
		s.running[key(r.AssetID, unit)] = fault != FaultPostCheckFail
		return gateway.EngineResult{Stdout: "restarted " + unit}, nil
	case "logs_rotate_cleanup":
		freed := 12.5
		if r.DryRun {
			return gateway.EngineResult{Stdout: fmt.Sprintf("dry-run: would free %.1f%% in %v older than %v days", freed, r.Params["directory"], r.Params["older_than_days"])}, nil
		}
		s.disk[r.AssetID] -= freed
		if s.disk[r.AssetID] < 0 {
			s.disk[r.AssetID] = 0
		}
		return gateway.EngineResult{Stdout: fmt.Sprintf("freed %.1f%% in %v", freed, r.Params["directory"])}, nil
	}
	return gateway.EngineResult{ExitCode: 127, Stderr: "unknown action " + r.Action}, nil
}
