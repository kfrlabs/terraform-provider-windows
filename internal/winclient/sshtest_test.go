package winclient

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"io"
	"net"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// This file provides a real, in-process SSH server for transport tests.
//
// It is not a mock: it speaks the wire protocol through x/crypto/ssh's server
// side, so the handshake, key exchange, host key presentation and publickey /
// password authentication are genuine protocol exchanges. That is what makes
// it meaningful for testing host key verification — the client has no idea it
// is talking to a test.
//
// What it deliberately does NOT emulate is PowerShell: it records the command
// and stdin it receives and replays canned output. Windows semantics stay the
// business of the acceptance suite.

// testServerOptions configures one in-process SSH server.
type testServerOptions struct {
	// authorizedKey, when set, is the only public key the server accepts.
	// Leaving it nil disables publickey authentication entirely.
	authorizedKey ssh.PublicKey
	// password, when non-empty, enables password authentication.
	password string

	// Canned session output.
	stdout     string
	stderr     string
	exitStatus uint32
}

// testServer is a running in-process SSH server listening on loopback.
type testServer struct {
	Addr    string
	Port    int
	HostKey ssh.PublicKey

	listener net.Listener
	wg       sync.WaitGroup

	mu           sync.Mutex
	command      string
	stdin        string
	authAttempts []string
}

// startTestServer boots a server on 127.0.0.1 and tears it down with the test.
func startTestServer(t *testing.T, opts testServerOptions) *testServer {
	t.Helper()

	hostPub, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}
	hostPubKey, err := ssh.NewPublicKey(hostPub)
	if err != nil {
		t.Fatalf("host public key: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	s := &testServer{
		Addr:     ln.Addr().String(),
		Port:     ln.Addr().(*net.TCPAddr).Port,
		HostKey:  hostPubKey,
		listener: ln,
	}

	cfg := &ssh.ServerConfig{
		AuthLogCallback: func(conn ssh.ConnMetadata, method string, err error) {
			s.mu.Lock()
			s.authAttempts = append(s.authAttempts, method)
			s.mu.Unlock()
		},
	}
	cfg.AddHostKey(hostSigner)

	if opts.authorizedKey != nil {
		want := string(opts.authorizedKey.Marshal())
		cfg.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if string(key.Marshal()) == want {
				return &ssh.Permissions{}, nil
			}
			return nil, errAuthFailed
		}
	}
	if opts.password != "" {
		cfg.PasswordCallback = func(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if string(pass) == opts.password {
				return &ssh.Permissions{}, nil
			}
			return nil, errAuthFailed
		}
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.serveConn(conn, cfg, opts)
			}()
		}
	}()

	t.Cleanup(func() {
		_ = ln.Close()
		s.wg.Wait()
	})
	return s
}

var errAuthFailed = &authError{}

type authError struct{}

func (*authError) Error() string { return "authentication failed" }

func (s *testServer) serveConn(conn net.Conn, cfg *ssh.ServerConfig, opts testServerOptions) {
	defer func() { _ = conn.Close() }()

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return // handshake or auth failure: the client-side assertion covers it
	}
	defer func() { _ = sshConn.Close() }()
	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			_ = newChan.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}
		ch, chReqs, err := newChan.Accept()
		if err != nil {
			return
		}
		s.handleSession(ch, chReqs, opts)
	}
}

func (s *testServer) handleSession(ch ssh.Channel, reqs <-chan *ssh.Request, opts testServerOptions) {
	defer func() { _ = ch.Close() }()

	for req := range reqs {
		if req.Type != "exec" {
			_ = req.Reply(false, nil)
			continue
		}

		var payload struct{ Command string }
		_ = ssh.Unmarshal(req.Payload, &payload)
		_ = req.Reply(true, nil)

		// Drain stdin first: the client streams the real script there and
		// closes when done, so this is what bounds the exchange.
		data, _ := io.ReadAll(ch)

		s.mu.Lock()
		s.command = payload.Command
		s.stdin = string(data)
		s.mu.Unlock()

		if opts.stdout != "" {
			_, _ = io.WriteString(ch, opts.stdout)
		}
		if opts.stderr != "" {
			_, _ = io.WriteString(ch.Stderr(), opts.stderr)
		}
		_, _ = ch.SendRequest("exit-status", false,
			ssh.Marshal(struct{ Status uint32 }{opts.exitStatus}))
		return
	}
}

// Command returns the command line the client asked the server to run.
func (s *testServer) Command() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.command
}

// Stdin returns everything the client wrote to the session's stdin.
func (s *testServer) Stdin() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stdin
}

// AuthAttempts returns the authentication methods the client offered, in order.
func (s *testServer) AuthAttempts() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.authAttempts...)
}

// AuthorizedKeyLine renders the server's host key in authorized_keys form,
// ready for the provider's host_key attribute.
func (s *testServer) AuthorizedKeyLine() string {
	return string(ssh.MarshalAuthorizedKey(s.HostKey))
}

// newClientKeypair returns a PEM private key and its ssh.PublicKey.
func newClientKeypair(t *testing.T) (pemBytes []byte, pub ssh.PublicKey, priv ed25519.PrivateKey) {
	t.Helper()
	pubEd, privEd, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(&privEd, "")
	if err != nil {
		t.Fatalf("marshal client key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pubEd)
	if err != nil {
		t.Fatalf("client public key: %v", err)
	}
	return pem.EncodeToMemory(block), sshPub, privEd
}
