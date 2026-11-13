// Package provider — unit tests for the provider-side source_url download
// helper used by windows_file apply (issue #325).
//
// Focus: User-Agent identity (and explicit override via source_url_headers),
// retry/backoff behaviour for transient failures, fast failure for permanent
// ones, and the insecure_skip_verify transport path. Plan-time behaviour is
// covered in resource_windows_file_test.go (no network I/O in ModifyPlan).
package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// downloadTestServer runs handler and reports how many requests arrived.
func downloadTestServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func TestDownloadSource_UserAgent(t *testing.T) {
	var gotUA string
	srv, calls := downloadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		_, _ = w.Write([]byte("hello"))
	})
	body, err := downloadSource(context.Background(), srv.URL, nil, false)
	if err != nil {
		t.Fatalf("downloadSource: %v", err)
	}
	if string(body) != "hello" {
		t.Errorf("body = %q, want %q", body, "hello")
	}
	if gotUA != fileUserAgent {
		t.Errorf("User-Agent = %q, want %q", gotUA, fileUserAgent)
	}
	if calls.Load() != 1 {
		t.Errorf("requests = %d, want 1 (no retry on success)", calls.Load())
	}
}

func TestDownloadSource_UserAgentOverride(t *testing.T) {
	var gotUA string
	srv, _ := downloadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		_, _ = w.Write([]byte("ok"))
	})
	_, err := downloadSource(context.Background(), srv.URL, map[string]string{"User-Agent": "custom/1.0"}, false)
	if err != nil {
		t.Fatalf("downloadSource: %v", err)
	}
	if gotUA != "custom/1.0" {
		t.Errorf("User-Agent = %q, want explicit header %q", gotUA, "custom/1.0")
	}
}

func TestDownloadSource_RetryThenSuccess(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n := calls.Add(1); n < 3 {
			http.Error(w, "boom", http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte("payload"))
	}))
	t.Cleanup(srv.Close)
	body, err := downloadSource(context.Background(), srv.URL, nil, false)
	if err != nil {
		t.Fatalf("downloadSource: %v", err)
	}
	if string(body) != "payload" {
		t.Errorf("body = %q, want %q", body, "payload")
	}
	if calls.Load() != 3 {
		t.Errorf("requests = %d, want 3 (two 502s then success)", calls.Load())
	}
}

func TestDownloadSource_Persistent5xxFailsAfterRetries(t *testing.T) {
	srv, calls := downloadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	})
	_, err := downloadSource(context.Background(), srv.URL, nil, false)
	if err == nil {
		t.Fatal("expected an error for a persistent 503, got nil")
	}
	if calls.Load() != int32(fileDownloadAttempts) {
		t.Errorf("requests = %d, want %d (initial attempt plus retries)", calls.Load(), fileDownloadAttempts)
	}
}

func TestDownloadSource_ClientErrorFailsFast(t *testing.T) {
	srv, calls := downloadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "gone", http.StatusNotFound)
	})
	_, err := downloadSource(context.Background(), srv.URL, nil, false)
	if err == nil {
		t.Fatal("expected an error for a 404, got nil")
	}
	if calls.Load() != 1 {
		t.Errorf("requests = %d, want 1 (4xx must not retry)", calls.Load())
	}
}

func TestDownloadSource_InvalidURLFailsFast(t *testing.T) {
	_, err := downloadSource(context.Background(), "http://[::1", nil, false)
	if err == nil {
		t.Fatal("expected an error for a malformed URL, got nil")
	}
}

func TestDownloadSource_CancelledContextFails(t *testing.T) {
	srv, _ := downloadTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := downloadSource(ctx, srv.URL, nil, false); err == nil {
		t.Error("expected an error for a cancelled context, got nil")
	}
}

func TestDownloadSource_InsecureSkipVerify(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("secret"))
	}))
	t.Cleanup(srv.Close)

	if _, err := downloadSource(context.Background(), srv.URL, nil, false); err == nil {
		t.Error("expected a TLS verification error without insecure_skip_verify, got nil")
	}
	body, err := downloadSource(context.Background(), srv.URL, nil, true)
	if err != nil {
		t.Fatalf("downloadSource with insecure_skip_verify: %v", err)
	}
	if string(body) != "secret" {
		t.Errorf("body = %q, want %q", body, "secret")
	}
}
