package telemetry

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aitmaganbetov/admintwin/services/inventory"
)

// SyslogMessage — разобранное сообщение RFC 3164 / RFC 5424.
// Hostname — поле из сообщения: недоверенное, для tenant и сопоставления с активом не используется.
type SyslogMessage struct {
	Format    string // rfc3164 | rfc5424
	Facility  int
	Severity  int
	Timestamp time.Time // нулевое, если отсутствует или не разобрано
	Hostname  string
	App       string
	ProcID    string
	MsgID     string
	Message   string
}

var errSyslogPRI = errors.New("syslog: missing or invalid PRI")

// ParseSyslog разбирает одно сообщение. RFC 5424 определяется по версии "1" после PRI,
// иначе — RFC 3164 (BSD), включая устройства без временной метки (например, FortiGate key=value).
func ParseSyslog(b []byte) (SyslogMessage, error) {
	b = bytes.TrimRight(b, "\r\n\x00")
	var m SyslogMessage
	if len(b) < 3 || b[0] != '<' {
		return m, errSyslogPRI
	}
	end := bytes.IndexByte(b[:min(len(b), 5)], '>')
	if end < 2 {
		return m, errSyslogPRI
	}
	pri, err := strconv.Atoi(string(b[1:end]))
	if err != nil || pri < 0 || pri > 191 {
		return m, errSyslogPRI
	}
	m.Facility, m.Severity = pri/8, pri%8
	rest := b[end+1:]
	if len(rest) >= 2 && rest[0] == '1' && rest[1] == ' ' {
		return parse5424(m, rest[2:])
	}
	return parse3164(m, rest), nil
}

func nextField(b []byte) (string, []byte) {
	i := bytes.IndexByte(b, ' ')
	if i < 0 {
		return string(b), nil
	}
	return string(b[:i]), b[i+1:]
}

func nilValue(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

func parse5424(m SyslogMessage, b []byte) (SyslogMessage, error) {
	m.Format = "rfc5424"
	var ts, host, app, proc, msgid string
	ts, b = nextField(b)
	host, b = nextField(b)
	app, b = nextField(b)
	proc, b = nextField(b)
	msgid, b = nextField(b)
	if ts != "-" {
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			m.Timestamp = t.UTC()
		}
	}
	m.Hostname, m.App, m.ProcID, m.MsgID = nilValue(host), nilValue(app), nilValue(proc), nilValue(msgid)
	// STRUCTURED-DATA: "-" или последовательность [..] с экранированием \" \\ \] внутри значений.
	if len(b) > 0 && b[0] == '-' {
		b = b[1:]
	} else {
		for len(b) > 0 && b[0] == '[' {
			n, err := sdElementLen(b)
			if err != nil {
				return m, err
			}
			b = b[n:]
		}
	}
	if len(b) > 0 && b[0] == ' ' {
		b = b[1:]
	}
	b = bytes.TrimPrefix(b, []byte("\xEF\xBB\xBF")) // BOM
	m.Message = string(b)
	return m, nil
}

func sdElementLen(b []byte) (int, error) {
	inQuote, esc := false, false
	for i := 1; i < len(b); i++ {
		c := b[i]
		switch {
		case esc:
			esc = false
		case c == '\\' && inQuote:
			esc = true
		case c == '"':
			inQuote = !inQuote
		case c == ']' && !inQuote:
			return i + 1, nil
		}
	}
	return 0, errors.New("syslog: unterminated structured data")
}

var months = map[string]time.Month{"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6, "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}

func parse3164(m SyslogMessage, b []byte) SyslogMessage {
	m.Format = "rfc3164"
	// TIMESTAMP "Mmm dd hh:mm:ss" (день может быть дополнен пробелом).
	if len(b) >= 16 && b[3] == ' ' && b[15] == ' ' {
		if mon, ok := months[string(b[:3])]; ok {
			day, e1 := strconv.Atoi(strings.TrimSpace(string(b[4:6])))
			clock, e2 := time.Parse("15:04:05", string(b[7:15]))
			if e1 == nil && e2 == nil {
				now := time.Now().UTC()
				t := time.Date(now.Year(), mon, day, clock.Hour(), clock.Minute(), clock.Second(), 0, time.UTC)
				if t.After(now.Add(24 * time.Hour)) {
					t = t.AddDate(-1, 0, 0) // перелом года
				}
				m.Timestamp = t
				b = b[16:]
				var host string
				host, b = nextField(b)
				m.Hostname = host
			}
		}
	}
	// TAG[PID]: MSG
	rest := string(b)
	if i := strings.IndexAny(rest, ":["); i > 0 && i <= 48 && !strings.ContainsAny(rest[:i], " =") {
		m.App = rest[:i]
		r := rest[i:]
		if r[0] == '[' {
			if j := strings.IndexByte(r, ']'); j > 0 {
				m.ProcID = r[1:j]
				r = r[j+1:]
			}
		}
		r = strings.TrimPrefix(r, ":")
		rest = strings.TrimPrefix(r, " ")
	}
	m.Message = rest
	return m
}

// LogSeverity — сопоставление syslog severity (0..7) с уровнями §9.
func (m SyslogMessage) LogSeverity() Severity {
	switch {
	case m.Severity <= 2:
		return SevCritical
	case m.Severity == 3:
		return SevHigh
	case m.Severity == 4:
		return SevMedium
	case m.Severity == 5:
		return SevLow
	}
	return SevInfo
}

// AssetResolver сопоставляет IP-адрес источника с активом CMDB (по Connection.Address).
type AssetResolver interface {
	ResolveSource(ip netip.Addr) (inventory.Asset, bool)
}

// InventoryResolver — AssetResolver поверх CMDB. Индекс адресов строится по активам всех tenant
// (список tenant даёт Tenants) и обновляется не чаще Refresh. Адрес, принадлежащий активам разных
// tenant, считается неоднозначным и не сопоставляется (tenant не угадывается).
type InventoryResolver struct {
	Inv     inventory.Repository
	Tenants func() []string
	Refresh time.Duration

	mu    sync.Mutex
	index map[netip.Addr][]inventory.Asset
	built time.Time
	now   func() time.Time
}

// NewInventoryResolver создаёт резолвер с обновлением индекса раз в 30 с.
func NewInventoryResolver(inv inventory.Repository, tenants func() []string) *InventoryResolver {
	return &InventoryResolver{Inv: inv, Tenants: tenants, Refresh: 30 * time.Second, now: time.Now}
}

func (r *InventoryResolver) rebuild() {
	idx := map[netip.Addr][]inventory.Asset{}
	for _, t := range r.Tenants() {
		for _, a := range r.Inv.List(t) {
			if a.Connection == nil || a.TenantID != t {
				continue
			}
			ip, err := netip.ParseAddr(a.Connection.Address)
			if err != nil {
				continue // hostname: без DNS-разрешения источник не сопоставляется
			}
			idx[ip.Unmap()] = append(idx[ip.Unmap()], a)
		}
	}
	for k := range idx {
		sort.Slice(idx[k], func(i, j int) bool { return idx[k][i].Name < idx[k][j].Name })
	}
	r.index, r.built = idx, r.now()
}

// ResolveSource реализует AssetResolver.
func (r *InventoryResolver) ResolveSource(ip netip.Addr) (inventory.Asset, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.index == nil || r.now().Sub(r.built) > r.Refresh {
		r.rebuild()
	}
	cands := r.index[ip.Unmap()]
	if len(cands) == 0 {
		return inventory.Asset{}, false
	}
	for _, c := range cands[1:] {
		if c.TenantID != cands[0].TenantID {
			return inventory.Asset{}, false
		}
	}
	return cands[0], true
}

// Invalidate сбрасывает индекс (после изменения CMDB).
func (r *InventoryResolver) Invalidate() {
	r.mu.Lock()
	r.index = nil
	r.mu.Unlock()
}

// SyslogStats — счётчики приёмника.
type SyslogStats struct {
	Received       uint64 `json:"received"`
	Accepted       uint64 `json:"accepted"`
	DroppedUnknown uint64 `json:"dropped_unknown_source"`
	ParseErrors    uint64 `json:"parse_errors"`
	IngestErrors   uint64 `json:"ingest_errors"`
}

// LogIngester — приём записей журналов (Service.IngestLogs).
type LogIngester interface {
	IngestLogs(ctx context.Context, tenantID string, in []LogRecord) (int, []string, error)
}

// SyslogReceiver — приёмник syslog по UDP и TCP (RFC 3164/5424; TCP-кадрирование RFC 6587:
// octet counting или LF). Tenant и актив определяются только по IP источника.
type SyslogReceiver struct {
	Addr       string // ADMINTWIN_SYSLOG_ADDR, например ":5514"
	Resolver   AssetResolver
	Ingest     LogIngester
	MaxMessage int // по умолчанию 8 КиБ
	MaxConns   int // одновременных TCP-соединений, по умолчанию 128
	IdleTCP    time.Duration

	received, accepted, unknown, parseErr, ingestErr atomic.Uint64

	mu     sync.Mutex
	udp    net.PacketConn
	tcp    net.Listener
	wg     sync.WaitGroup
	cancel context.CancelFunc
	conns  map[net.Conn]struct{}
}

// Stats — текущие счётчики.
func (s *SyslogReceiver) Stats() SyslogStats {
	return SyslogStats{Received: s.received.Load(), Accepted: s.accepted.Load(), DroppedUnknown: s.unknown.Load(), ParseErrors: s.parseErr.Load(), IngestErrors: s.ingestErr.Load()}
}

// Start открывает UDP и TCP на Addr. Для Addr с портом 0 порты UDP и TCP могут различаться (см. UDPAddr/TCPAddr).
func (s *SyslogReceiver) Start(ctx context.Context) error {
	if s.MaxMessage <= 0 {
		s.MaxMessage = 8192
	}
	if s.MaxConns <= 0 {
		s.MaxConns = 128
	}
	if s.IdleTCP <= 0 {
		s.IdleTCP = 5 * time.Minute
	}
	if s.Resolver == nil || s.Ingest == nil {
		return errors.New("syslog: resolver and ingest are required")
	}
	pc, err := net.ListenPacket("udp", s.Addr)
	if err != nil {
		return fmt.Errorf("syslog udp: %w", err)
	}
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		pc.Close()
		return fmt.Errorf("syslog tcp: %w", err)
	}
	ctx, cancel := context.WithCancel(ctx)
	s.mu.Lock()
	s.udp, s.tcp, s.cancel, s.conns = pc, ln, cancel, map[net.Conn]struct{}{}
	s.mu.Unlock()
	s.wg.Add(2)
	go s.serveUDP(ctx, pc)
	go s.serveTCP(ctx, ln)
	go func() { <-ctx.Done(); s.Close() }()
	return nil
}

// UDPAddr — фактический адрес UDP.
func (s *SyslogReceiver) UDPAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.udp.LocalAddr()
}

// TCPAddr — фактический адрес TCP.
func (s *SyslogReceiver) TCPAddr() net.Addr { s.mu.Lock(); defer s.mu.Unlock(); return s.tcp.Addr() }

// Close останавливает приёмник и дожидается обработчиков.
func (s *SyslogReceiver) Close() error {
	s.mu.Lock()
	if s.cancel != nil {
		s.cancel()
	}
	if s.udp != nil {
		s.udp.Close()
	}
	if s.tcp != nil {
		s.tcp.Close()
	}
	for c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	return nil
}

func (s *SyslogReceiver) serveUDP(ctx context.Context, pc net.PacketConn) {
	defer s.wg.Done()
	buf := make([]byte, 65536)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		ua, ok := addr.(*net.UDPAddr)
		if !ok {
			continue
		}
		ip, _ := netip.AddrFromSlice(ua.IP)
		msg := buf[:n]
		if len(msg) > s.MaxMessage {
			msg = msg[:s.MaxMessage]
		}
		s.Handle(ctx, ip, append([]byte(nil), msg...))
	}
}

func (s *SyslogReceiver) serveTCP(ctx context.Context, ln net.Listener) {
	defer s.wg.Done()
	sem := make(chan struct{}, s.MaxConns)
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		select {
		case sem <- struct{}{}:
		default:
			c.Close() // перегрузка: соединение сверх лимита закрывается
			continue
		}
		s.mu.Lock()
		s.conns[c] = struct{}{}
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-sem }()
			defer func() { s.mu.Lock(); delete(s.conns, c); s.mu.Unlock(); c.Close() }()
			s.serveConn(ctx, c)
		}()
	}
}

func (s *SyslogReceiver) serveConn(ctx context.Context, c net.Conn) {
	ta, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return
	}
	ip, _ := netip.AddrFromSlice(ta.IP)
	r := bufio.NewReaderSize(c, s.MaxMessage+16)
	for {
		_ = c.SetReadDeadline(time.Now().Add(s.IdleTCP))
		first, err := r.Peek(1)
		if err != nil {
			return
		}
		var msg []byte
		if first[0] >= '1' && first[0] <= '9' {
			// Octet counting: "<len> <msg>".
			lenStr, err := r.ReadString(' ')
			if err != nil || len(lenStr) > 7 {
				return
			}
			n, err := strconv.Atoi(strings.TrimSpace(lenStr))
			if err != nil || n <= 0 || n > s.MaxMessage {
				return // нарушение кадрирования — соединение закрывается
			}
			msg = make([]byte, n)
			if _, err := io.ReadFull(r, msg); err != nil {
				return
			}
		} else {
			line, err := r.ReadSlice('\n')
			if errors.Is(err, bufio.ErrBufferFull) {
				// Слишком длинная строка: усекаем и пропускаем остаток.
				msg = append([]byte(nil), line[:s.MaxMessage]...)
				for errors.Is(err, bufio.ErrBufferFull) {
					_, err = r.ReadSlice('\n')
				}
			} else if err != nil {
				if len(line) == 0 {
					return
				}
				msg = append([]byte(nil), line...)
			} else {
				msg = append([]byte(nil), line...)
			}
		}
		if ctx.Err() != nil {
			return
		}
		if len(bytes.TrimSpace(msg)) > 0 {
			s.Handle(ctx, ip, msg)
		}
	}
}

// Handle обрабатывает одно сообщение от источника ip (используется UDP/TCP и тестами).
func (s *SyslogReceiver) Handle(ctx context.Context, ip netip.Addr, raw []byte) {
	s.received.Add(1)
	asset, ok := s.Resolver.ResolveSource(ip)
	if !ok {
		s.unknown.Add(1) // неизвестный источник: отбрасывается, tenant не угадывается
		return
	}
	m, err := ParseSyslog(raw)
	if err != nil {
		s.parseErr.Add(1)
		return
	}
	at := time.Now().UTC()
	if !m.Timestamp.IsZero() && m.Format == "rfc5424" && absDur(at.Sub(m.Timestamp)) < time.Hour {
		at = m.Timestamp
	}
	rec := LogRecord{
		TenantID: asset.TenantID, AssetID: asset.ID, Source: "syslog", Host: m.Hostname, App: m.App,
		Severity: m.LogSeverity(), Message: m.Message, At: at,
		Labels: map[string]string{"facility": strconv.Itoa(m.Facility), "format": m.Format, "source_ip": ip.Unmap().String()},
	}
	if _, _, err := s.Ingest.IngestLogs(ctx, asset.TenantID, []LogRecord{rec}); err != nil {
		s.ingestErr.Add(1)
		slog.Warn("syslog: ingest failed", "tenant_id", asset.TenantID, "asset_id", asset.ID, "error", err)
		return
	}
	s.accepted.Add(1)
}

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}
