package winclient

// Session pool tests (issue #180): the client keeps up to MaxSessions
// persistent PowerShell sessions and serves concurrent calls on them,
// instead of serialising every call onto a single session.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// N concurrent calls with pool size K use at most K connections and run
// concurrently (acceptance criterion 1). The canned response delay forces
// the callers to overlap deterministically: without parallelism the test
// would take N x delay, with a pool of K it takes N/K x delay.
func TestPoolConcurrentCallsAreBounded(t *testing.T) {
	noAgent(t)
	keyPEM, pub, _ := newClientKeypair(t)
	srv := startTestServer(t, testServerOptions{
		authorizedKey: pub, stdout: "ok", responseDelay: 200 * time.Millisecond,
	})

	c := newTransportTestClient(t, Config{
		Host: "127.0.0.1", Port: srv.Port, Username: "tester",
		PrivateKey: string(keyPEM), HostKey: srv.AuthorizedKeyLine(), Timeout: testTimeout,
		MaxSessions: 3,
	})

	const n = 9
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()
			stdout, _, err := c.RunPowerShell(ctx, "Get-Thing")
			if err != nil {
				errs <- err
				return
			}
			if got := trimNewline(stdout); got != "ok" {
				errs <- errors.New("stdout = " + stdout)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent RunPowerShell: %v", err)
	}

	if got := len(srv.Requests()); got != n {
		t.Errorf("requests = %d, want %d", got, n)
	}
	if got := srv.Connections(); got > 3 {
		t.Errorf("connections = %d, want at most 3 (pool size)", got)
	}
	if got := srv.Connections(); got < 2 {
		t.Errorf("connections = %d, want at least 2 (calls ran concurrently)", got)
	}
	if got := srv.MaxActive(); got > 3 {
		t.Errorf("max concurrent requests = %d, want at most 3 (pool size)", got)
	}
	if got := srv.MaxActive(); got < 2 {
		t.Errorf("max concurrent requests = %d, want at least 2 (calls overlapped)", got)
	}
}

// The one-shot fallback (hosts without pwsh.exe, e.g. PowerShell 5.1 only)
// borrows the same pool slot (option A): concurrent one-shot calls are
// bounded too, instead of one dial storm per call.
func TestPoolBoundsOneShotConcurrency(t *testing.T) {
	noAgent(t)
	keyPEM, pub, _ := newClientKeypair(t)
	srv := startTestServer(t, testServerOptions{
		authorizedKey: pub, stdout: "ok", oneShot: true,
		responseDelay: 150 * time.Millisecond,
	})

	c := newTransportTestClient(t, Config{
		Host: "127.0.0.1", Port: srv.Port, Username: "tester",
		PrivateKey: string(keyPEM), HostKey: srv.AuthorizedKeyLine(), Timeout: testTimeout,
		MaxSessions: 2,
	})
	c.oneShot = true

	const n = 6
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()
			if _, _, err := c.RunPowerShell(ctx, "Get-Thing"); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent one-shot RunPowerShell: %v", err)
	}

	if got := len(srv.Requests()); got != n {
		t.Errorf("requests = %d, want %d", got, n)
	}
	if got := srv.MaxActive(); got > 2 {
		t.Errorf("max concurrent one-shot requests = %d, want at most 2 (pool size)", got)
	}
}

// A call with an already-cancelled context fails fast without consuming a
// pool slot: with the single slot held by a slow call, the cancelled call
// returns context.Canceled while the slow one still succeeds.
func TestPoolAcquireHonoursContextCancel(t *testing.T) {
	noAgent(t)
	keyPEM, pub, _ := newClientKeypair(t)
	srv := startTestServer(t, testServerOptions{
		authorizedKey: pub, stdout: "ok", responseDelay: 500 * time.Millisecond,
	})

	c := newTransportTestClient(t, Config{
		Host: "127.0.0.1", Port: srv.Port, Username: "tester",
		PrivateKey: string(keyPEM), HostKey: srv.AuthorizedKeyLine(), Timeout: testTimeout,
		MaxSessions: 1,
	})

	slowDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()
		_, _, err := c.RunPowerShell(ctx, "Get-Thing")
		slowDone <- err
	}()

	// Wait until the slow call holds the only slot.
	deadline := time.Now().Add(5 * time.Second)
	for len(srv.Requests()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if len(srv.Requests()) == 0 {
		t.Fatal("slow call never reached the server")
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := c.RunPowerShell(cancelled, "Get-OtherThing"); !errors.Is(err, context.Canceled) {
		t.Errorf("expected a context.Canceled error, got: %v", err)
	}

	if err := <-slowDone; err != nil {
		t.Errorf("slow call: %v", err)
	}
	if got := len(srv.Requests()); got != 1 {
		t.Errorf("requests = %d, want 1 (cancelled call never ran)", got)
	}
}

// New validates and defaults the pool size.
func TestNewPoolSize(t *testing.T) {
	noAgent(t)

	t.Run("zero defaults to 4", func(t *testing.T) {
		c, err := New(Config{Host: "h", Username: "u", Password: "p", InsecureIgnoreHostKey: true})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		defer func() { _ = c.Close() }()
		if got := c.Config().MaxSessions; got != DefaultMaxSessions {
			t.Errorf("MaxSessions = %d, want default %d", got, DefaultMaxSessions)
		}
		if got := cap(c.sem); got != DefaultMaxSessions {
			t.Errorf("pool capacity = %d, want %d", got, DefaultMaxSessions)
		}
	})

	for _, bad := range []int{-1, -100, MaxMaxSessions + 1} {
		t.Run("rejects pool size", func(t *testing.T) {
			if _, err := New(Config{Host: "h", Username: "u", Password: "p", InsecureIgnoreHostKey: true, MaxSessions: bad}); err == nil {
				t.Errorf("New with MaxSessions=%d should fail", bad)
			}
		})
	}
}

// Close is idempotent and borrowed sessions returning after Close are torn
// down rather than re-pooled.
func TestPoolCloseIsIdempotent(t *testing.T) {
	noAgent(t)
	keyPEM, pub, _ := newClientKeypair(t)
	srv := startTestServer(t, testServerOptions{authorizedKey: pub, stdout: "ok"})

	c := newTransportTestClient(t, Config{
		Host: "127.0.0.1", Port: srv.Port, Username: "tester",
		PrivateKey: string(keyPEM), HostKey: srv.AuthorizedKeyLine(), Timeout: testTimeout,
		MaxSessions: 2,
	})

	mustRun(t, c, "Get-Thing")
	if err := c.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func trimNewline(s string) string {
	if len(s) > 0 && s[len(s)-1] == '\n' {
		return s[:len(s)-1]
	}
	return s
}
