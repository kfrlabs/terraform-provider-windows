package winclient

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
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
// What it deliberately does NOT emulate is PowerShell itself: instead of
// running powershell.exe, it speaks the REPL wire protocol
// (session.go) directly — a ready handshake, then one framed canned response
// per request it reads — so it can play the role of the persistent REPL
// bootstrap without a Windows host. Each request it decodes is recorded so
// tests can assert on what the client sent.

// testServerOptions configures one in-process SSH server.
type testServerOptions struct {
	// authorizedKey, when set, is the only public key the server accepts.
	// Leaving it nil disables publickey authentication entirely.
	authorizedKey ssh.PublicKey
	// password, when non-empty, enables password authentication.
	password string

	// stdout/stderr/status are the canned REPL response served for every
	// request, unless dropAfterCalls cuts the session short first.
	stdout string
	stderr string
	status int

	// dropAfterCalls, when > 0, closes the SSH channel after that many
	// requests have been served (without responding to the next one),
	// simulating a session that dies mid-use — for recovery tests.
	dropAfterCalls int
}

// testRequest is one decoded REPL request the server received.
type testRequest struct {
	scriptB64 string
	secretB64 string
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
	requests     []testRequest
	connections  int
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

	s.mu.Lock()
	s.connections++
	s.mu.Unlock()

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

// handleSession plays the role of the REPL bootstrap (psReplBootstrap in
// session.go): a ready handshake, then a framed canned response per request.
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

		s.mu.Lock()
		s.command = payload.Command
		s.mu.Unlock()

		_, _ = fmt.Fprintf(ch, "%stestmarker%s\n", replReadyPrefix, replReadySuffix)

		in := bufio.NewReader(ch)
		calls := 0
		for {
			scriptLine, err := in.ReadString('\n')
			if err != nil {
				break // client closed stdin: clean REPL shutdown
			}
			secretLine, err := in.ReadString('\n')
			if err != nil {
				break
			}
			calls++

			s.mu.Lock()
			s.requests = append(s.requests, testRequest{
				scriptB64: strings.TrimRight(scriptLine, "\r\n"),
				secretB64: strings.TrimRight(secretLine, "\r\n"),
			})
			s.mu.Unlock()

			if opts.dropAfterCalls > 0 && calls > opts.dropAfterCalls {
				return // simulate a session that died mid-use
			}

			writeFramedLine(ch, opts.stdout)
			_, _ = fmt.Fprintf(ch, "%s%d%s\n", replEndStdoutPrefix, opts.status, replEndStdoutSuffix)
			writeFramedLine(ch.Stderr(), opts.stderr)
			_, _ = fmt.Fprintf(ch.Stderr(), "%s\n", replEndStderrLine)
		}

		_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
		return
	}
}

// writeFramedLine writes s to w followed by a newline, unless s is empty (in
// which case nothing is written — an empty canned stdout/stderr means "no
// output", not a blank line).
func writeFramedLine(w interface{ Write([]byte) (int, error) }, s string) {
	if s == "" {
		return
	}
	_, _ = w.Write([]byte(s))
	if !strings.HasSuffix(s, "\n") {
		_, _ = w.Write([]byte("\n"))
	}
}

// Command returns the command line the client asked the server to run.
func (s *testServer) Command() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.command
}

// Requests returns every REPL request the server decoded, across every
// connection, in order.
func (s *testServer) Requests() []testRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]testRequest(nil), s.requests...)
}

// Connections returns how many separate SSH connections the client made.
// Session reuse means repeated calls keep this at 1.
func (s *testServer) Connections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connections
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
