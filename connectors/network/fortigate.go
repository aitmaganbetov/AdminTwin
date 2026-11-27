// Package network — read-only коннектор Fortinet FortiGate (FortiOS REST API, §14 п.3, тир MVP read-only):
// инструмент fortigate.policy.status, discovery (hostname, модель, прошивка, интерфейсы, IPsec).
//
// Только чтение: клиент умеет исключительно GET к фиксированным путям /api/v2/cmdb/... и /api/v2/monitor/...;
// методов изменения конфигурации в коде нет (изменения FortiGate — runbooks тира P1a через Gateway).
// Аутентификация — API-токен read-only профиля (Credential.Token) в заголовке Authorization: Bearer;
// токен в URL (access_token) не передаётся. TLS-проверка включена по умолчанию.
package network

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aitmaganbetov/admintwin/connectors/internal/common"
	"github.com/aitmaganbetov/admintwin/services/discovery"
	gateway "github.com/aitmaganbetov/admintwin/services/execution-gateway"
	"github.com/aitmaganbetov/admintwin/services/inventory"
)

// Method — значение inventory.Connection.Method.
const Method = "fortigate_api"

const (
	maxBody     = 8 << 20 // список политик крупного устройства
	maxPolicies = 500
)

// Пути FortiOS REST API (только чтение).
const (
	pathPolicyCMDB    = "/api/v2/cmdb/firewall/policy"
	pathPolicyMonitor = "/api/v2/monitor/firewall/policy"
	pathHAConfig      = "/api/v2/cmdb/system/ha"
	pathHAChecksums   = "/api/v2/monitor/system/ha-checksums"
	pathStatus        = "/api/v2/monitor/system/status"
	pathInterfaces    = "/api/v2/cmdb/system/interface"
	pathIPsec         = "/api/v2/monitor/vpn/ipsec"
)

// ErrAccessDenied — токен отклонён или профиль не даёт чтения.
var ErrAccessDenied = errors.New("fortigate: access denied for API token")

// ErrNotFound — объект не найден.
var ErrNotFound = errors.New("fortigate: object not found")

// Options — параметры коннектора.
type Options struct {
	Logger  *slog.Logger
	Timeout time.Duration // на один запрос (10 с)
	Now     func() time.Time
}

// Connector — FortiOS REST API.
type Connector struct{ o Options }

// New создаёт коннектор.
func New(o Options) *Connector {
	if o.Timeout <= 0 {
		o.Timeout = 10 * time.Second
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	o.Logger = common.Logger(o.Logger)
	return &Connector{o: o}
}

type client struct {
	hc      *http.Client
	base    string
	token   string
	timeout time.Duration
}

func (c *Connector) client(conn *inventory.Connection, cred gateway.Credential) (*client, error) {
	if conn == nil || conn.Address == "" {
		return nil, errors.New("fortigate: asset has no connection address")
	}
	if cred.Token == "" {
		return nil, errors.New("fortigate: API token is not configured in vault")
	}
	host := strings.TrimPrefix(conn.Address, "https://")
	if strings.HasPrefix(conn.Address, "http://") || host == "" || strings.ContainsAny(host, "/?#@ ") {
		return nil, errors.New("fortigate: address must be a host name or IP (https only)")
	}
	sn := conn.TLSServerName
	if sn == "" {
		sn = host
	}
	tc, err := common.TLSConfig(common.TLSOptions{ServerName: sn, SkipVerify: conn.TLSSkipVerify, Component: "fortigate", Address: host}, cred, c.o.Logger)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{TLSClientConfig: tc, DialContext: (&net.Dialer{Timeout: c.o.Timeout}).DialContext,
		TLSHandshakeTimeout: c.o.Timeout, ResponseHeaderTimeout: c.o.Timeout, MaxIdleConns: 2, IdleConnTimeout: 30 * time.Second}
	return &client{
		// Перенаправления не выполняются: токен не должен уйти на другой адрес.
		hc:   &http.Client{Transport: tr, Timeout: c.o.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		base: "https://" + common.HostPort(host, conn.Port, 443), token: cred.Token, timeout: c.o.Timeout,
	}, nil
}

func (cl *client) close() { cl.hc.CloseIdleConnections() }

// envelope — общий конверт ответа FortiOS.
type envelope struct {
	HTTPStatus int             `json:"http_status"`
	Status     string          `json:"status"`
	Results    json.RawMessage `json:"results"`
	Serial     string          `json:"serial"`
	Version    string          `json:"version"`
	Build      int             `json:"build"`
	VDOM       string          `json:"vdom"`
}

// get — единственный метод обращения к устройству (GET).
func (cl *client) get(ctx context.Context, path string, q url.Values) (envelope, error) {
	ctx, cancel := context.WithTimeout(ctx, cl.timeout)
	defer cancel()
	u := cl.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return envelope{}, err
	}
	req.Header.Set("Authorization", "Bearer "+cl.token)
	req.Header.Set("Accept", "application/json")
	resp, err := cl.hc.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return envelope{}, fmt.Errorf("fortigate: request failed: %v", err)
	}
	defer resp.Body.Close()
	body, err := common.ReadLimited(resp.Body, maxBody)
	if err != nil {
		return envelope{}, fmt.Errorf("fortigate: %w", err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return envelope{}, ErrAccessDenied
	case http.StatusNotFound:
		return envelope{}, ErrNotFound
	default:
		return envelope{}, fmt.Errorf("fortigate: unexpected status %d", resp.StatusCode)
	}
	var env envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return envelope{}, errors.New("fortigate: malformed response")
	}
	if env.Status != "" && env.Status != "success" {
		return envelope{}, fmt.Errorf("fortigate: request status %q", common.Truncate(env.Status, 32))
	}
	return env, nil
}

var vdomRe = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,31}$`)

// PolicyInput — вход fortigate.policy.status.
type PolicyInput struct {
	PolicyID *int
	VDOM     string
}

type namedRef struct {
	Name string `json:"name"`
}

type policyCMDB struct {
	PolicyID int        `json:"policyid"`
	Name     string     `json:"name"`
	Action   string     `json:"action"`
	Status   string     `json:"status"`
	SrcIntf  []namedRef `json:"srcintf"`
	DstIntf  []namedRef `json:"dstintf"`
}

type policyStats struct {
	PolicyID int   `json:"policyid"`
	HitCount int64 `json:"hit_count"`
	LastUsed int64 `json:"last_used"`
}

// PolicyStatus — данные по контракту ai/tools/read/fortigate.policy.status.json.
func (c *Connector) PolicyStatus(ctx context.Context, conn *inventory.Connection, cred gateway.Credential, in PolicyInput) (map[string]any, error) {
	if in.VDOM != "" && !vdomRe.MatchString(in.VDOM) {
		return nil, errors.New("fortigate: invalid vdom")
	}
	if in.PolicyID != nil && (*in.PolicyID < 0 || *in.PolicyID > 1000000) {
		return nil, errors.New("fortigate: invalid policy id")
	}
	cl, err := c.client(conn, cred)
	if err != nil {
		return nil, err
	}
	defer cl.close()
	q := url.Values{"format": {"policyid|name|action|status|srcintf|dstintf"}}
	mq := url.Values{}
	if in.VDOM != "" {
		q.Set("vdom", in.VDOM)
		mq.Set("vdom", in.VDOM)
	}
	path := pathPolicyCMDB
	if in.PolicyID != nil {
		path += "/" + strconv.Itoa(*in.PolicyID)
		mq.Set("policyid", strconv.Itoa(*in.PolicyID))
	}
	env, err := cl.get(ctx, path, q)
	if errors.Is(err, ErrNotFound) {
		return map[string]any{"policies": []any{}, "ha_status": c.haStatus(ctx, cl)}, nil
	}
	if err != nil {
		return nil, err
	}
	var cmdb []policyCMDB
	if err := json.Unmarshal(env.Results, &cmdb); err != nil {
		return nil, errors.New("fortigate: malformed policy list")
	}
	stats := map[int]policyStats{}
	if menv, err := cl.get(ctx, pathPolicyMonitor, mq); err == nil {
		var ms []policyStats
		if json.Unmarshal(menv.Results, &ms) == nil {
			for _, s := range ms {
				stats[s.PolicyID] = s
			}
		}
	} else if !errors.Is(err, ErrNotFound) {
		c.o.Logger.Warn("fortigate policy counters unavailable", "address", conn.Address, "error", err.Error())
	}
	policies := make([]map[string]any, 0, min(len(cmdb), maxPolicies))
	for _, p := range cmdb {
		if len(policies) >= maxPolicies {
			break
		}
		if !oneOf(p.Action, "accept", "deny", "ipsec") || !oneOf(p.Status, "enable", "disable") {
			continue // неизвестные значения не вписываются в контракт; не выдумываем
		}
		item := map[string]any{"policy_id": p.PolicyID, "name": common.Truncate(sanitize(p.Name), 255), "action": p.Action, "status": p.Status,
			"srcintf": names(p.SrcIntf), "dstintf": names(p.DstIntf), "last_used": nil}
		if s, ok := stats[p.PolicyID]; ok {
			item["hit_count"] = max(s.HitCount, 0)
			if s.LastUsed > 0 {
				item["last_used"] = time.Unix(s.LastUsed, 0).UTC().Format(time.RFC3339)
			}
		}
		policies = append(policies, item)
	}
	return map[string]any{"policies": policies, "ha_status": c.haStatus(ctx, cl)}, nil
}

// haStatus — "standalone" или "<mode>: <n> members, in sync|out of sync"; null, если недоступно.
func (c *Connector) haStatus(ctx context.Context, cl *client) any {
	env, err := cl.get(ctx, pathHAConfig, url.Values{"format": {"mode"}})
	if err != nil {
		return nil
	}
	var cfg struct {
		Mode string `json:"mode"`
	}
	if json.Unmarshal(env.Results, &cfg) != nil || cfg.Mode == "" {
		return nil
	}
	mode := sanitize(cfg.Mode)
	if mode == "standalone" {
		return "standalone"
	}
	cenv, err := cl.get(ctx, pathHAChecksums, nil)
	if err != nil {
		return common.Truncate(mode+": checksums unavailable", 128)
	}
	var members []struct {
		Serial   string            `json:"serial_no"`
		Checksum map[string]string `json:"checksum"`
	}
	if json.Unmarshal(cenv.Results, &members) != nil {
		return common.Truncate(mode+": checksums unavailable", 128)
	}
	sync := "in sync"
	for _, m := range members {
		if m.Checksum["all"] == "" || m.Checksum["all"] != members[0].Checksum["all"] {
			sync = "out of sync"
		}
	}
	return common.Truncate(fmt.Sprintf("%s: %d members, %s", mode, len(members), sync), 128)
}

func names(refs []namedRef) []string {
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		if len(out) >= 64 {
			break
		}
		out = append(out, common.Truncate(sanitize(r.Name), 64))
	}
	return out
}

func oneOf(v string, set ...string) bool {
	for _, s := range set {
		if v == s {
			return true
		}
	}
	return false
}

// sanitize — данные устройства недоверенные (§18.6): без управляющих символов.
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, "?"))
}

// --- discovery ---

// Collector — read-only сборщик fortigate_api.
func (c *Connector) Collector() discovery.Collector { return collector{c} }

type collector struct{ c *Connector }

func (collector) Method() string { return Method }

// Collect — актив firewall: hostname, модель, прошивка, серийный номер, интерфейсы, IPsec-туннели.
func (k collector) Collect(ctx context.Context, t discovery.Target, cred discovery.Credential) (discovery.Observation, error) {
	conn := &inventory.Connection{Method: Method, Address: t.Address, Port: t.Port, CredentialRef: t.CredentialRef, TLSServerName: t.TLSServerName}
	cl, err := k.c.client(conn, common.FromDiscovery(cred))
	if err != nil {
		return discovery.Observation{}, err
	}
	defer cl.close()
	env, err := cl.get(ctx, pathStatus, nil)
	if err != nil {
		return discovery.Observation{}, err
	}
	var st struct {
		Hostname    string `json:"hostname"`
		Model       string `json:"model"`
		ModelName   string `json:"model_name"`
		ModelNumber string `json:"model_number"`
	}
	_ = json.Unmarshal(env.Results, &st)
	obs := discovery.Observation{Confidence: 0.95}
	a := inventory.Asset{TenantID: t.TenantID, Type: "firewall", Source: "discovery", Reachability: "reachable", Connection: conn,
		Name: common.Truncate(sanitize(st.Hostname), 128), Objects: map[string][]string{}}
	model := strings.TrimSpace(st.ModelName + " " + st.ModelNumber)
	if model == "" {
		model = st.Model
	}
	if model != "" {
		a.Objects["model"] = []string{common.Truncate(sanitize(model), 64)}
	}
	if env.Version != "" {
		fw := env.Version
		if env.Build > 0 {
			fw += " build" + strconv.Itoa(env.Build)
		}
		a.Objects["firmware"] = []string{common.Truncate(sanitize(fw), 64)}
	}
	if env.Serial != "" {
		a.Objects["serial"] = []string{common.Truncate(sanitize(env.Serial), 64)}
	}
	if ienv, err := cl.get(ctx, pathInterfaces, url.Values{"format": {"name|type|status"}}); err == nil {
		var ifs []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		}
		if json.Unmarshal(ienv.Results, &ifs) == nil {
			for _, i := range ifs {
				if n := common.Truncate(sanitize(i.Name), 64); n != "" && len(a.Objects["interface"]) < 1000 {
					a.Objects["interface"] = append(a.Objects["interface"], n)
				}
			}
			sort.Strings(a.Objects["interface"])
		}
	} else {
		obs.Warnings = append(obs.Warnings, "interfaces are not readable with this API profile")
		obs.Confidence = 0.8
	}
	if venv, err := cl.get(ctx, pathIPsec, nil); err == nil {
		var tunnels []struct {
			Name    string `json:"name"`
			ProxyID []struct {
				Status string `json:"status"`
			} `json:"proxyid"`
		}
		if json.Unmarshal(venv.Results, &tunnels) == nil {
			for _, tn := range tunnels {
				n := common.Truncate(sanitize(tn.Name), 64)
				if n == "" || len(a.Objects["ipsec_tunnel"]) >= 500 {
					continue
				}
				a.Objects["ipsec_tunnel"] = append(a.Objects["ipsec_tunnel"], n)
				for _, p := range tn.ProxyID {
					if p.Status != "up" {
						obs.Warnings = append(obs.Warnings, "ipsec tunnel "+n+" has a phase2 selector down")
						break
					}
				}
			}
		}
	}
	if a.Name == "" {
		a.Name = t.Address
		obs.Confidence = 0.7
	}
	obs.Assets = []inventory.Asset{a}
	return obs, nil
}
