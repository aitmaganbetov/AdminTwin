package docker

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/aitmaganbetov/admintwin/connectors/internal/common"
	"github.com/aitmaganbetov/admintwin/services/discovery"
	gateway "github.com/aitmaganbetov/admintwin/services/execution-gateway"
	"github.com/aitmaganbetov/admintwin/services/inventory"
	"github.com/aitmaganbetov/admintwin/services/telemetry"
)

// Method — значение inventory.Connection.Method для этого коннектора.
const Method = "docker_api"

// stopTimeoutS — параметр t= для restart (секунды на graceful stop до SIGKILL).
const stopTimeoutS = 10

var containerIDRe = regexp.MustCompile(`^[a-f0-9]{12,64}$`)

// Connector — Docker Engine API.
type Connector struct{ o Options }

// New создаёт коннектор.
func New(o Options) *Connector { return &Connector{o: o.withDefaults()} }

// --- Engine (docker_api) ---

// Execute исполняет действие runbook. Поддерживается только restart (docker.container.restart).
func (c *Connector) Execute(ctx context.Context, req gateway.EngineRequest) (gateway.EngineResult, error) {
	if req.Action != "restart" {
		return gateway.EngineResult{}, fmt.Errorf("docker: unsupported action %q", req.Action)
	}
	if err := common.CheckLease(req.Lease, c.o.Now()); err != nil {
		return gateway.EngineResult{}, err
	}
	id, _ := req.Params["container_id"].(string)
	// Повторная проверка (defense in depth): формат, наличие в CMDB, защищённый список.
	if !containerIDRe.MatchString(id) {
		return gateway.EngineResult{}, errors.New("docker: container_id has invalid format")
	}
	if !req.Asset.HasObject("container", id) || req.Asset.IsProtected(id) {
		return gateway.EngineResult{}, errors.New("docker: container is not an allowed inventory object of the asset")
	}
	if req.DryRun {
		return gateway.EngineResult{}, errors.New("docker: restart does not support dry run")
	}
	cl, err := dial(req.Asset.Connection, req.Lease.Credential, c.o)
	if err != nil {
		return gateway.EngineResult{}, err
	}
	defer cl.close()
	status, err := cl.restart(ctx, id, stopTimeoutS)
	if err != nil {
		return gateway.EngineResult{}, err
	}
	switch status {
	case 204, 200:
		return gateway.EngineResult{Stdout: "container " + id + " restarted"}, nil
	case 404:
		return gateway.EngineResult{Stderr: "no such container " + id, ExitCode: 1}, nil
	default:
		return gateway.EngineResult{Stderr: fmt.Sprintf("docker engine returned status %d", status), ExitCode: 1}, nil
	}
}

// --- Facts ---

// ContainerRunning — контейнер запущен (Running, не Paused и не Restarting).
func (c *Connector) ContainerRunning(ctx context.Context, conn *inventory.Connection, cred gateway.Credential, id string) (bool, error) {
	cl, err := dial(conn, cred, c.o)
	if err != nil {
		return false, err
	}
	defer cl.close()
	r, err := cl.inspect(ctx, id)
	if errors.Is(err, ErrNoSuchContainer) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return r.State.Running && !r.State.Paused && !r.State.Restarting, nil
}

// RestartsLastHour — число событий start контейнера за последний час (Engine API /events).
// Каждый перезапуск — ручной (API/CLI) или по restart policy — порождает событие start; первичный
// запуск созданного в этот час контейнера тоже учитывается (оценка сверху: fail closed для лимита).
// Источник — журнал событий демона, поэтому учёт переживает перезапуск AdminTwin.
func (c *Connector) RestartsLastHour(ctx context.Context, conn *inventory.Connection, cred gateway.Credential, id string) (int, error) {
	cl, err := dial(conn, cred, c.o)
	if err != nil {
		return 0, err
	}
	defer cl.close()
	r, err := cl.inspect(ctx, id)
	if err != nil {
		return 0, err
	}
	now := c.o.Now()
	return cl.countEvents(ctx, r.ID, "start", now.Add(-time.Hour), now)
}

// --- read tool docker.container.inspect ---

var statusEnum = map[string]bool{"created": true, "running": true, "paused": true, "restarting": true, "removing": true, "exited": true, "dead": true}

// Inspect возвращает данные по контракту ai/tools/read/docker.container.inspect.json.
// Переменные окружения не читаются; значения меток проходят редактирование секретов.
func (c *Connector) Inspect(ctx context.Context, conn *inventory.Connection, cred gateway.Credential, container string) (map[string]any, error) {
	cl, err := dial(conn, cred, c.o)
	if err != nil {
		return nil, err
	}
	defer cl.close()
	r, err := cl.inspect(ctx, container)
	if err != nil {
		return nil, err
	}
	if !statusEnum[r.State.Status] {
		return nil, fmt.Errorf("docker: unexpected container status %q", common.Truncate(r.State.Status, 32))
	}
	state := map[string]any{
		"status": r.State.Status, "running": r.State.Running, "exit_code": r.State.ExitCode,
		"oom_killed": r.State.OOMKilled, "restart_count": max(r.RestartCount, 0),
		"started_at": dockerTime(r.State.StartedAt), "finished_at": dockerTime(r.State.FinishedAt), "health": nil,
	}
	if r.State.Health != nil {
		switch h := r.State.Health.Status; h {
		case "healthy", "unhealthy", "starting", "none":
			state["health"] = h
		}
	}
	name := strings.TrimPrefix(r.Name, "/")
	if name == "" {
		name = shortID(r.ID)
	}
	out := map[string]any{
		"container": name, "image": common.Truncate(r.Config.Image, 512), "image_digest": nilIfEmpty(r.Image),
		"state": state, "restart_policy": common.Truncate(r.HostConfig.RestartPolicy.Name, 32),
		"ports": ports(r), "labels": labels(r.Config.Labels),
	}
	return out, nil
}

func ports(r inspectResp) []string {
	keys := make([]string, 0, len(r.NetworkSettings.Ports))
	for k := range r.NetworkSettings.Ports {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := []string{}
	for _, k := range keys {
		binds := r.NetworkSettings.Ports[k]
		if len(binds) == 0 {
			out = append(out, common.Truncate(k, 64))
		}
		for _, b := range binds {
			out = append(out, common.Truncate(fmt.Sprintf("%s:%s->%s", b.HostIP, b.HostPort, k), 64))
		}
		if len(out) >= 100 {
			return out[:100]
		}
	}
	return out
}

// labels — не более 16 КиБ суммарно (лимит ответа инструмента 32 КиБ), значения ≤ 512 байт, секреты редактируются.
func labels(in map[string]string) map[string]string {
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := map[string]string{}
	budget := 16 << 10
	for _, k := range keys {
		v := common.Truncate(gateway.Redact(in[k]), 512)
		k2 := common.Truncate(k, 256)
		if budget -= len(k2) + len(v) + 8; budget < 0 {
			break
		}
		out[k2] = v
	}
	return out
}

func dockerTime(s string) any {
	if s == "" || strings.HasPrefix(s, "0001-01-01") {
		return nil
	}
	return s
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func shortID(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// --- метрики ---

// maxContainersPolled — верхняя граница inspect-запросов за один опрос хоста.
const maxContainersPolled = 100

// Metrics — container_up{container} и container_restarts_total{container} (RestartCount демона).
func (c *Connector) Metrics(ctx context.Context, a inventory.Asset, cred gateway.Credential) ([]telemetry.Sample, error) {
	cl, err := dial(a.Connection, cred, c.o)
	if err != nil {
		return nil, err
	}
	defer cl.close()
	list, err := cl.list(ctx)
	if err != nil {
		return nil, err
	}
	now := c.o.Now().UTC()
	var out []telemetry.Sample
	for i, s := range list {
		if i >= maxContainersPolled {
			break
		}
		r, err := cl.inspect(ctx, s.ID)
		if err != nil {
			continue // контейнер удалён между list и inspect
		}
		lbl := map[string]string{"container": shortID(r.ID), "name": common.Truncate(strings.TrimPrefix(r.Name, "/"), 128)}
		up := 0.0
		if r.State.Running && !r.State.Restarting {
			up = 1
		}
		out = append(out,
			telemetry.Sample{TenantID: a.TenantID, AssetID: a.ID, Metric: "container_up", Labels: lbl, Value: up, At: now},
			telemetry.Sample{TenantID: a.TenantID, AssetID: a.ID, Metric: "container_restarts_total", Labels: cloneLabels(lbl), Value: float64(r.RestartCount), At: now})
	}
	return out, nil
}

func cloneLabels(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// --- discovery ---

// Collector возвращает read-only сборщик docker_api.
func (c *Connector) Collector() discovery.Collector { return collector{c} }

type collector struct{ c *Connector }

func (collector) Method() string { return Method }

// Collect — хост docker_host; Objects["container"] — короткие (12 символов) ID всех контейнеров:
// именно эти значения принимает параметр container_id runbook docker.container.restart.
func (k collector) Collect(ctx context.Context, t discovery.Target, cred discovery.Credential) (discovery.Observation, error) {
	conn := &inventory.Connection{Method: Method, Address: t.Address, Port: t.Port, CredentialRef: t.CredentialRef, TLSServerName: t.TLSServerName}
	cl, err := dial(conn, common.FromDiscovery(cred), k.c.o)
	if err != nil {
		return discovery.Observation{}, err
	}
	defer cl.close()
	info, err := cl.info(ctx)
	if err != nil {
		return discovery.Observation{}, err
	}
	list, err := cl.list(ctx)
	if err != nil {
		return discovery.Observation{}, err
	}
	obs := discovery.Observation{Confidence: 0.95}
	ids := make([]string, 0, len(list))
	for _, s := range list {
		id := shortID(s.ID)
		if !containerIDRe.MatchString(id) {
			continue
		}
		ids = append(ids, id)
		switch s.State {
		case "restarting", "dead":
			obs.Warnings = append(obs.Warnings, fmt.Sprintf("container %s is %s", id, s.State))
		}
	}
	sort.Strings(ids)
	name := sanitize(info.Name)
	if name == "" {
		name = t.Address
		obs.Confidence = 0.7
		obs.Warnings = append(obs.Warnings, "docker daemon did not report a hostname")
	}
	asset := inventory.Asset{
		TenantID: t.TenantID, Name: name, Type: "docker_host", Source: "discovery", Reachability: "reachable",
		Objects: map[string][]string{"container": ids}, Connection: conn,
	}
	if v := sanitize(info.ServerVersion); v != "" {
		asset.Objects["docker_version"] = []string{v}
	}
	if os := sanitize(info.OperatingSystem); os != "" {
		asset.Objects["os"] = []string{os}
	}
	obs.Assets = []inventory.Asset{asset}
	return obs, nil
}

// sanitize — данные демона недоверенные (§18.6): убираем управляющие символы, ограничиваем длину.
func sanitize(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	return common.Truncate(strings.TrimSpace(s), 255)
}
