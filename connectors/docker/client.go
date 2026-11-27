// Package docker — коннектор Docker Engine API (§14 п.2): restart через Engine API (без docker CLI и shell),
// read-only факты, инструмент docker.container.inspect, discovery и метрики контейнеров.
//
// Транспорт: unix-сокет (Connection.Address = "unix:///var/run/docker.sock" или абсолютный путь) либо
// TCP + mTLS (Connection.Address = хост, порт по умолчанию 2376; клиентский сертификат/ключ/CA — из Vault).
// Нешифрованный TCP (2375) не поддерживается.
package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/aitmaganbetov/admintwin/connectors/internal/common"
	gateway "github.com/aitmaganbetov/admintwin/services/execution-gateway"
	"github.com/aitmaganbetov/admintwin/services/inventory"
)

// APIVersion — версия Engine API (Docker ≥ 20.10).
const APIVersion = "v1.41"

const (
	maxBody       = 4 << 20 // 4 МиБ: inspect/list
	maxEventsBody = 1 << 20
	defaultPort   = 2376
)

// ErrNoSuchContainer — контейнер не найден на хосте.
var ErrNoSuchContainer = errors.New("no such container")

// Options — параметры коннектора.
type Options struct {
	Logger *slog.Logger
	// Timeout — на один запрос к Engine API (кроме restart, ограниченного контекстом Gateway). По умолчанию 10 с.
	Timeout    time.Duration
	APIVersion string
	Now        func() time.Time
}

func (o Options) withDefaults() Options {
	if o.Timeout <= 0 {
		o.Timeout = 10 * time.Second
	}
	if o.APIVersion == "" {
		o.APIVersion = APIVersion
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	o.Logger = common.Logger(o.Logger)
	return o
}

// client — HTTP-клиент Engine API для одного актива.
type client struct {
	hc      *http.Client
	base    string
	ver     string
	timeout time.Duration
	tr      *http.Transport
}

// dial создаёт клиента по параметрам подключения актива.
func dial(conn *inventory.Connection, cred gateway.Credential, o Options) (*client, error) {
	if conn == nil || conn.Address == "" {
		return nil, errors.New("docker: asset has no connection address")
	}
	tr := &http.Transport{
		MaxIdleConns: 2, IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: o.Timeout,
		ResponseHeaderTimeout: 0, // restart ждёт остановки контейнера; ограничение — контекст
		DisableCompression:    true,
	}
	addr := conn.Address
	var base string
	switch {
	case strings.HasPrefix(addr, "unix://") || strings.HasPrefix(addr, "/"):
		sock := strings.TrimPrefix(addr, "unix://")
		if !strings.HasPrefix(sock, "/") {
			return nil, errors.New("docker: unix socket path must be absolute")
		}
		d := &net.Dialer{Timeout: o.Timeout}
		tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) { return d.DialContext(ctx, "unix", sock) }
		base = "http://docker"
	case strings.HasPrefix(addr, "http://"):
		return nil, errors.New("docker: plain TCP Engine API is not allowed; use unix socket or TLS (mTLS)")
	default:
		host := strings.TrimPrefix(strings.TrimPrefix(addr, "tcp://"), "https://")
		port := conn.Port
		if h, p, err := net.SplitHostPort(host); err == nil {
			host = h
			if port == 0 {
				port, _ = strconv.Atoi(p)
			}
		}
		if host == "" || strings.ContainsAny(host, "/?#@") {
			return nil, errors.New("docker: invalid host address")
		}
		sn := conn.TLSServerName
		if sn == "" {
			sn = host
		}
		tc, err := common.TLSConfig(common.TLSOptions{ServerName: sn, SkipVerify: conn.TLSSkipVerify, RequireClientCert: true,
			Component: "docker", Address: host}, cred, o.Logger)
		if err != nil {
			return nil, err
		}
		tr.TLSClientConfig = tc
		tr.DialContext = (&net.Dialer{Timeout: o.Timeout}).DialContext
		base = "https://" + common.HostPort(host, port, defaultPort)
	}
	return &client{
		hc:   &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		base: base, ver: o.APIVersion, timeout: o.Timeout, tr: tr,
	}, nil
}

func (c *client) close() { c.tr.CloseIdleConnections() }

func (c *client) url(path string, q url.Values) string {
	u := c.base + "/" + c.ver + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	return u
}

// get — GET с таймаутом и лимитом размера; 404 → ErrNoSuchContainer.
func (c *client) get(ctx context.Context, path string, q url.Values, max int64, out any) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url(path, q), nil)
	if err != nil {
		return err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("docker: request failed: %w", unwrapURL(err))
	}
	defer resp.Body.Close()
	body, err := common.ReadLimited(resp.Body, max)
	if err != nil {
		return fmt.Errorf("docker: %w", err)
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return ErrNoSuchContainer
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("docker: unexpected status %d", resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	if raw, ok := out.(*[]byte); ok {
		*raw = body
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return errors.New("docker: malformed response")
	}
	return nil
}

// restart — POST /containers/{id}/restart?t=10.
// Отмена: ErrCancelConfirmed только если ни один байт запроса не был отправлен демону;
// иначе — ошибка контекста (Gateway фиксирует unknown) или ErrChannelLost.
func (c *client) restart(ctx context.Context, id string, stopTimeout int) (int, error) {
	if ctx.Err() != nil {
		return 0, gateway.ErrCancelConfirmed
	}
	var sent atomic.Bool
	trace := &httptrace.ClientTrace{
		WroteHeaderField: func(string, []string) { sent.Store(true) },
		WroteHeaders:     func() { sent.Store(true) },
	}
	q := url.Values{"t": {strconv.Itoa(stopTimeout)}}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodPost,
		c.url("/containers/"+url.PathEscape(id)+"/restart", q), nil)
	if err != nil {
		return 0, err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		switch {
		case !sent.Load() && ctx.Err() != nil:
			return 0, gateway.ErrCancelConfirmed
		case !sent.Load():
			// Соединение не установлено — запрос не отправлен, состояние не менялось.
			return 0, fmt.Errorf("docker: connection failed before request was sent: %w", unwrapURL(err))
		case ctx.Err() != nil:
			return 0, ctx.Err()
		}
		return 0, fmt.Errorf("%w: %v", gateway.ErrChannelLost, unwrapURL(err))
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, nil
}

// countEvents считает события action контейнера за интервал [since, until] (GET /events с until — конечный поток).
func (c *client) countEvents(ctx context.Context, fullID, action string, since, until time.Time) (int, error) {
	filters, _ := json.Marshal(map[string][]string{"type": {"container"}, "container": {fullID}, "event": {action}})
	q := url.Values{
		"since":   {strconv.FormatInt(since.Unix(), 10)},
		"until":   {strconv.FormatInt(until.Unix(), 10)},
		"filters": {string(filters)},
	}
	var raw []byte
	if err := c.get(ctx, "/events", q, maxEventsBody, &raw); err != nil {
		return 0, err
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	n := 0
	for {
		var ev struct {
			Type   string `json:"Type"`
			Action string `json:"Action"`
			Actor  struct {
				ID string `json:"ID"`
			} `json:"Actor"`
		}
		if err := dec.Decode(&ev); err == io.EOF {
			break
		} else if err != nil {
			return 0, errors.New("docker: malformed events stream")
		}
		// Повторная фильтрация на стороне клиента (защита от широкого серверного фильтра).
		if ev.Type == "container" && ev.Action == action && ev.Actor.ID == fullID {
			n++
		}
	}
	return n, nil
}

func unwrapURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// --- модели ответов Engine API (только используемые поля; Config.Env не читается) ---

type inspectResp struct {
	ID      string `json:"Id"`
	Name    string `json:"Name"`
	Image   string `json:"Image"`
	Created string `json:"Created"`
	State   struct {
		Status     string `json:"Status"`
		Running    bool   `json:"Running"`
		Paused     bool   `json:"Paused"`
		Restarting bool   `json:"Restarting"`
		OOMKilled  bool   `json:"OOMKilled"`
		Dead       bool   `json:"Dead"`
		ExitCode   int    `json:"ExitCode"`
		StartedAt  string `json:"StartedAt"`
		FinishedAt string `json:"FinishedAt"`
		Health     *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
	RestartCount int `json:"RestartCount"`
	Config       struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	HostConfig struct {
		RestartPolicy struct {
			Name string `json:"Name"`
		} `json:"RestartPolicy"`
	} `json:"HostConfig"`
	NetworkSettings struct {
		Ports map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"Ports"`
	} `json:"NetworkSettings"`
}

type summaryResp struct {
	ID     string   `json:"Id"`
	Names  []string `json:"Names"`
	Image  string   `json:"Image"`
	State  string   `json:"State"`
	Status string   `json:"Status"`
}

type infoResp struct {
	ID              string `json:"ID"`
	Name            string `json:"Name"`
	ServerVersion   string `json:"ServerVersion"`
	OperatingSystem string `json:"OperatingSystem"`
	KernelVersion   string `json:"KernelVersion"`
	NCPU            int    `json:"NCPU"`
	MemTotal        int64  `json:"MemTotal"`
	Containers      int    `json:"Containers"`
}

func (c *client) inspect(ctx context.Context, id string) (inspectResp, error) {
	var r inspectResp
	err := c.get(ctx, "/containers/"+url.PathEscape(id)+"/json", nil, maxBody, &r)
	return r, err
}

func (c *client) list(ctx context.Context) ([]summaryResp, error) {
	var r []summaryResp
	err := c.get(ctx, "/containers/json", url.Values{"all": {"1"}}, maxBody, &r)
	return r, err
}

func (c *client) info(ctx context.Context) (infoResp, error) {
	var r infoResp
	err := c.get(ctx, "/info", nil, maxBody, &r)
	return r, err
}
