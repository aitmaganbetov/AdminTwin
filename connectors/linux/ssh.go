package linux

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/aitmaganbetov/admintwin/connectors/internal/common"
	gateway "github.com/aitmaganbetov/admintwin/services/execution-gateway"
	"github.com/aitmaganbetov/admintwin/services/inventory"
)

// Ошибки SSH-транспорта (без секретов и без вывода удалённой стороны).
var (
	ErrNoHostKey       = errors.New("ssh: expected host key is not configured for the asset (connection.host_key)")
	ErrHostKeyMismatch = errors.New("ssh: host key mismatch")
	ErrNoAuth          = errors.New("ssh: no usable credential (private key or password) in vault")
)

const (
	defaultSSHPort = 22
	maxStderr      = 64 << 10
)

// session — SSH-подключение к одному активу на время операции.
type session struct {
	c   *Connector
	cl  *ssh.Client
	tcp net.Conn
}

// hostKeyAlgorithms — алгоритмы, соответствующие закреплённому ключу (сервер предъявит именно его).
func hostKeyAlgorithms(k ssh.PublicKey) []string {
	if k.Type() == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
	}
	return []string{k.Type()}
}

// parseHostKey — ожидаемый ключ в формате authorized_keys ("ssh-ed25519 AAAA... [comment]").
func parseHostKey(s string) (ssh.PublicKey, error) {
	if strings.TrimSpace(s) == "" {
		return nil, ErrNoHostKey
	}
	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(s))
	if err != nil {
		return nil, errors.New("ssh: connection.host_key is not a valid public key")
	}
	if _, isCert := k.(*ssh.Certificate); isCert {
		return nil, errors.New("ssh: host certificates are not supported; pin the host public key")
	}
	return k, nil
}

func authMethods(cred gateway.Credential) ([]ssh.AuthMethod, error) {
	var out []ssh.AuthMethod
	if len(cred.PrivateKey) > 0 {
		signer, err := ssh.ParsePrivateKey(cred.PrivateKey)
		var missing *ssh.PassphraseMissingError
		if errors.As(err, &missing) && cred.Password != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(cred.PrivateKey, []byte(cred.Password))
		}
		if err != nil {
			return nil, errors.New("ssh: private key from vault cannot be parsed")
		}
		out = append(out, ssh.PublicKeys(signer))
	} else if cred.Password != "" {
		out = append(out, ssh.Password(cred.Password))
	}
	if len(out) == 0 || cred.Username == "" {
		return nil, ErrNoAuth
	}
	return out, nil
}

// dial подключается с обязательной проверкой host key (InsecureIgnoreHostKey не используется).
func (c *Connector) dial(ctx context.Context, conn *inventory.Connection, cred gateway.Credential) (*session, error) {
	if conn == nil || conn.Address == "" {
		return nil, errors.New("ssh: asset has no connection address")
	}
	want, err := parseHostKey(conn.HostKey)
	if err != nil {
		return nil, err
	}
	auth, err := authMethods(cred)
	if err != nil {
		return nil, err
	}
	cfg := &ssh.ClientConfig{
		User: cred.Username, Auth: auth, Timeout: c.o.DialTimeout,
		HostKeyAlgorithms: hostKeyAlgorithms(want),
		HostKeyCallback: func(_ string, _ net.Addr, got ssh.PublicKey) error {
			if !bytes.Equal(got.Marshal(), want.Marshal()) {
				return ErrHostKeyMismatch
			}
			return nil
		},
	}
	addr := common.HostPort(conn.Address, conn.Port, defaultSSHPort)
	dctx, cancel := context.WithTimeout(ctx, c.o.DialTimeout)
	defer cancel()
	tcp, err := (&net.Dialer{}).DialContext(dctx, "tcp", addr)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("ssh: connect failed: %w", stripAddr(err))
	}
	// Рукопожатие ограничено таймаутом и контекстом.
	_ = tcp.SetDeadline(time.Now().Add(c.o.DialTimeout))
	stop := context.AfterFunc(ctx, func() { _ = tcp.Close() })
	sc, chans, reqs, err := ssh.NewClientConn(tcp, addr, cfg)
	stop()
	if err != nil {
		_ = tcp.Close()
		if errors.Is(err, ErrHostKeyMismatch) {
			c.o.Logger.Warn("ssh host key mismatch: connection refused", "address", conn.Address)
			return nil, ErrHostKeyMismatch
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if strings.Contains(err.Error(), "unable to authenticate") {
			return nil, errors.New("ssh: authentication failed")
		}
		return nil, errors.New("ssh: handshake failed")
	}
	_ = tcp.SetDeadline(time.Time{})
	return &session{c: c, cl: ssh.NewClient(sc, chans, reqs), tcp: tcp}, nil
}

func (s *session) close() { _ = s.cl.Close() }

func stripAddr(err error) error {
	var op *net.OpError
	if errors.As(err, &op) && op.Err != nil {
		return op.Err
	}
	return err
}

// execResult — результат команды.
type execResult struct {
	stderr  string
	exit    int
	started bool // команда передана удалённой стороне
}

// run исполняет команду из allowlist. stdout пишется в w (вызывающий ограничивает объём).
// Ошибка: контекст (после старта — исход неизвестен), ErrChannelLost (канал потерян после старта),
// прочие — команда не запускалась.
func (s *session) run(ctx context.Context, cmd command, w io.Writer) (execResult, error) {
	argv := cmd.argv
	if cmd.write && s.c.o.Sudo {
		argv = append([]string{"sudo", "-n", "--"}, argv...)
	}
	if err := s.c.allowed(argv); err != nil {
		return execResult{}, err
	}
	line, err := Join(argv)
	if err != nil {
		return execResult{}, err
	}
	if ctx.Err() != nil {
		return execResult{}, gateway.ErrCancelConfirmed
	}
	sess, err := s.cl.NewSession()
	if err != nil {
		return execResult{}, fmt.Errorf("ssh: cannot open session: %w", err)
	}
	defer sess.Close()
	_ = sess.Setenv("LC_ALL", "C") // разбор вывода не зависит от локали; сервер может отклонить — не критично
	stderr := &capBuffer{max: maxStderr}
	sess.Stdout, sess.Stderr = w, stderr
	if err := sess.Start(line); err != nil {
		return execResult{}, fmt.Errorf("ssh: cannot start command: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()
	select {
	case <-ctx.Done():
		_ = sess.Signal(ssh.SIGTERM)
		_ = s.cl.Close()
		<-done
		return execResult{started: true, stderr: stderr.String()}, ctx.Err()
	case err := <-done:
		res := execResult{started: true, stderr: stderr.String()}
		var ee *ssh.ExitError
		switch {
		case err == nil:
			return res, nil
		case errors.As(err, &ee):
			res.exit = ee.ExitStatus()
			return res, nil
		case ctx.Err() != nil:
			return res, ctx.Err()
		}
		// ExitMissingError, io.EOF и т.п.: команда запущена, итог неизвестен.
		return res, fmt.Errorf("%w: %v", gateway.ErrChannelLost, err)
	}
}

// output — команда с захватом stdout (не больше max байт; превышение — ошибка).
func (s *session) output(ctx context.Context, cmd command, max int) (string, execResult, error) {
	buf := &capBuffer{max: max}
	res, err := s.run(ctx, cmd, buf)
	if err == nil && buf.over {
		err = common.ErrResponseTooLarge
	}
	return buf.String(), res, err
}

// mustOutput — output, где ненулевой код возврата — ошибка (для read-only команд).
func (s *session) mustOutput(ctx context.Context, cmd command, max int) (string, error) {
	out, res, err := s.output(ctx, cmd, max)
	if err != nil {
		return "", err
	}
	if res.exit != 0 {
		return "", fmt.Errorf("ssh: %s exited with code %d", cmd.argv[0], res.exit)
	}
	return out, nil
}

// capBuffer — буфер с верхней границей; лишнее отбрасывается и отмечается.
type capBuffer struct {
	b    bytes.Buffer
	max  int
	over bool
}

func (c *capBuffer) Write(p []byte) (int, error) {
	if room := c.max - c.b.Len(); room < len(p) {
		c.over = true
		if room > 0 {
			c.b.Write(p[:room])
		}
		return len(p), nil
	}
	return c.b.Write(p)
}

func (c *capBuffer) String() string { return c.b.String() }
