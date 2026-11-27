package linux

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// resp — заготовленный ответ на exec.
type resp struct {
	out, errOut string
	exit        int
	hang        bool // команда «зависает» до закрытия канала клиентом
	drop        bool // соединение рвётся без exit-status
}

// sshServer — SSH-сервер в процессе теста: записывает строки exec и отдаёт заготовленный вывод.
type sshServer struct {
	t         *testing.T
	ln        net.Listener
	hostKey   ssh.Signer
	clientKey []byte // PEM приватного ключа клиента
	password  string

	mu       sync.Mutex
	cmds     []string
	conns    int
	env      []string
	answers  map[string]resp
	executed chan string
}

func newSSHServer(t *testing.T) *sshServer {
	t.Helper()
	_, hpriv, _ := ed25519.GenerateKey(rand.Reader)
	hs, _ := ssh.NewSignerFromKey(hpriv)
	_, cpriv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKey(cpriv, "")
	if err != nil {
		t.Fatal(err)
	}
	cs, _ := ssh.NewSignerFromKey(cpriv)
	s := &sshServer{t: t, hostKey: hs, clientKey: pem.EncodeToMemory(block), password: "pw-123", answers: map[string]resp{}}
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if string(k.Marshal()) == string(cs.PublicKey().Marshal()) {
				return nil, nil
			}
			return nil, errDenied
		},
		PasswordCallback: func(_ ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
			if string(p) == s.password {
				return nil, nil
			}
			return nil, errDenied
		},
	}
	cfg.AddHostKey(hs)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.ln = ln
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.conns++
			s.mu.Unlock()
			go s.serve(c, cfg)
		}
	}()
	return s
}

type deniedErr struct{}

func (deniedErr) Error() string { return "denied" }

var errDenied = deniedErr{}

func (s *sshServer) addr() (string, int) {
	a := s.ln.Addr().(*net.TCPAddr)
	return a.IP.String(), a.Port
}

func (s *sshServer) hostKeyLine() string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.hostKey.PublicKey())))
}

func (s *sshServer) on(cmd string, r resp) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.answers[cmd] = r
}

func (s *sshServer) commands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.cmds...)
}

func (s *sshServer) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cmds = nil
}

func (s *sshServer) serve(nc net.Conn, cfg *ssh.ServerConfig) {
	sc, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		_ = nc.Close()
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)
	for nch := range chans {
		if nch.ChannelType() != "session" {
			_ = nch.Reject(ssh.UnknownChannelType, "only sessions")
			continue
		}
		ch, creqs, err := nch.Accept()
		if err != nil {
			return
		}
		go s.session(nc, ch, creqs)
	}
}

func (s *sshServer) session(nc net.Conn, ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	for req := range reqs {
		switch req.Type {
		case "env":
			var kv struct{ Name, Value string }
			_ = ssh.Unmarshal(req.Payload, &kv)
			s.mu.Lock()
			s.env = append(s.env, kv.Name+"="+kv.Value)
			s.mu.Unlock()
			_ = req.Reply(true, nil)
		case "exec":
			var p struct{ Command string }
			if err := ssh.Unmarshal(req.Payload, &p); err != nil {
				_ = req.Reply(false, nil)
				return
			}
			_ = req.Reply(true, nil)
			s.mu.Lock()
			s.cmds = append(s.cmds, p.Command)
			r, ok := s.answers[p.Command]
			exec := s.executed
			s.mu.Unlock()
			if exec != nil {
				exec <- p.Command
			}
			if !ok {
				r = resp{errOut: "not emulated: " + p.Command, exit: 127}
			}
			if r.drop {
				_ = nc.Close()
				return
			}
			if r.hang {
				for range reqs { // ждём сигнала/закрытия клиентом
				}
				return
			}
			_, _ = ch.Write([]byte(r.out))
			_, _ = ch.Stderr().Write([]byte(r.errOut))
			_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(r.exit)}))
			return
		default:
			_ = req.Reply(false, nil)
		}
	}
}
