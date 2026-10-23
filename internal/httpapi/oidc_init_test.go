package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tabbysync/internal/config"
)

// discoveryServer answers OIDC discovery after delay, failing while
// *healthy is false, and counts the requests.
func discoveryServer(t *testing.T, delay time.Duration, healthy *atomic.Bool, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		time.Sleep(delay)
		if !healthy.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint":         srv.URL + "/token",
			"jwks_uri":               srv.URL + "/jwks",
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func testProvider(srv *httptest.Server) *oidcProvider {
	return &oidcProvider{
		cfg:        config.OIDCProvider{ID: "t", Issuer: srv.URL, ClientID: "c", ClientSecret: "s"},
		client:     srv.Client(),
		timeout:    5 * time.Second,
		retryAfter: time.Hour,
	}
}

// TestOIDCInitConcurrent: logins arriving during a slow discovery share it
// instead of queueing one discovery each.
func TestOIDCInitConcurrent(t *testing.T) {
	var healthy atomic.Bool
	var hits atomic.Int32
	healthy.Store(true)
	p := testProvider(discoveryServer(t, 300*time.Millisecond, &healthy, &hits))

	start := time.Now()
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := p.init(context.Background()); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("%d discovery requests, want 1", n)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("20 concurrent inits took %v; they should share one 300ms discovery", d)
	}
}

// TestOIDCInitFailureBackoff: while the provider is down, logins fail fast
// from the remembered error, and discovery is retried after retryAfter.
func TestOIDCInitFailureBackoff(t *testing.T) {
	var healthy atomic.Bool
	var hits atomic.Int32
	p := testProvider(discoveryServer(t, 200*time.Millisecond, &healthy, &hits))

	if _, _, err := p.init(context.Background()); err == nil {
		t.Fatal("discovery against a failing provider succeeded")
	}
	start := time.Now()
	for range 10 {
		if _, _, err := p.init(context.Background()); err == nil {
			t.Fatal("expected the remembered error")
		}
	}
	if d := time.Since(start); d > 100*time.Millisecond || hits.Load() != 1 {
		t.Fatalf("10 inits during back-off took %v with %d requests; want instant, 1 request", d, hits.Load())
	}

	// A waiter gives up at its own deadline rather than the discovery timeout.
	p.retryAfter = 0
	healthy.Store(true)
	p.mu.Lock()
	p.inflight = make(chan struct{})
	p.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, _, err := p.init(ctx); err == nil {
		t.Fatal("waiter ignored its deadline")
	}
	p.mu.Lock()
	close(p.inflight)
	p.inflight = nil
	p.mu.Unlock()

	// After the back-off, the next login retries and succeeds.
	if _, _, err := p.init(context.Background()); err != nil {
		t.Fatalf("retry after back-off: %v", err)
	}
	if hits.Load() != 2 {
		t.Fatalf("%d discovery requests, want 2", hits.Load())
	}
}
