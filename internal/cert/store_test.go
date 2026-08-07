// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

package cert

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/elazarl/goproxy"
)

// stubGen returns a generator producing a distinguishable certificate and
// counting how many times it was invoked.
func stubGen(calls *int) func() (*tls.Certificate, error) {
	return func() (*tls.Certificate, error) {
		*calls++
		return &tls.Certificate{Certificate: [][]byte{[]byte(fmt.Sprintf("cert-%d", *calls))}}, nil
	}
}

// TestCertStoreCachesBySigningOnce is the whole point: signing is the expensive
// operation. Without a store, goproxy re-signs on every CONNECT — a fresh
// RSA-2048 key pair each time when the CA key is RSA.
func TestCertStoreCachesBySigningOnce(t *testing.T) {
	s := NewCertStore(10, time.Hour)

	calls := 0
	gen := stubGen(&calls)

	for range 5 {
		if _, err := s.Fetch("api.example.com", gen); err != nil {
			t.Fatalf("Fetch: %v", err)
		}
	}
	if calls != 1 {
		t.Errorf("generator called %d times for one host, want 1", calls)
	}
}

// TestCertStoreEvictsLeastRecentlyUsed pins the bound. The previous cache was an
// unbounded sync.Map, so a CONNECT flood over random hostnames grew memory
// without limit.
func TestCertStoreEvictsLeastRecentlyUsed(t *testing.T) {
	s := NewCertStore(2, time.Hour)

	calls := 0
	gen := stubGen(&calls)

	for _, h := range []string{"a", "b"} {
		if _, err := s.Fetch(h, gen); err != nil {
			t.Fatal(err)
		}
	}
	// Touch "a" so "b" becomes least recently used.
	if _, err := s.Fetch("a", gen); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Fetch("c", gen); err != nil {
		t.Fatal(err)
	}

	if got := s.Len(); got != 2 {
		t.Errorf("Len() = %d, want 2 (the configured bound)", got)
	}

	before := calls
	if _, err := s.Fetch("a", gen); err != nil {
		t.Fatal(err)
	}
	if calls != before {
		t.Error("recently used entry was evicted; eviction must drop the least recently used")
	}
	if _, err := s.Fetch("b", gen); err != nil {
		t.Fatal(err)
	}
	if calls == before {
		t.Error("least recently used entry survived eviction")
	}
}

// TestCertStoreExpiresEntries pins the TTL. The previous cache had no expiry, so
// a process running past the 365-day leaf validity served expired certificates.
func TestCertStoreExpiresEntries(t *testing.T) {
	s := NewCertStore(10, time.Hour)

	now := time.Now()
	s.now = func() time.Time { return now }

	calls := 0
	gen := stubGen(&calls)

	if _, err := s.Fetch("api.example.com", gen); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("generator called %d times, want 1", calls)
	}

	// Still inside the TTL.
	now = now.Add(59 * time.Minute)
	if _, err := s.Fetch("api.example.com", gen); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Errorf("re-signed inside the TTL (%d calls)", calls)
	}

	// Past the TTL.
	now = now.Add(2 * time.Minute)
	if _, err := s.Fetch("api.example.com", gen); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Errorf("generator called %d times after expiry, want 2", calls)
	}
}

// TestCertStoreDoesNotCacheFailures ensures a transient signing failure is not
// remembered as a result.
func TestCertStoreDoesNotCacheFailures(t *testing.T) {
	s := NewCertStore(10, time.Hour)

	wantErr := errors.New("signing failed")
	if _, err := s.Fetch("x", func() (*tls.Certificate, error) { return nil, wantErr }); !errors.Is(err, wantErr) {
		t.Fatalf("Fetch error = %v, want %v", err, wantErr)
	}
	if got := s.Len(); got != 0 {
		t.Errorf("Len() = %d after a failed generation, want 0", got)
	}

	calls := 0
	if _, err := s.Fetch("x", stubGen(&calls)); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Error("a failed generation was cached; the retry must call the generator")
	}
}

// TestCertStoreClear covers dropping leaves after the signing CA changes.
func TestCertStoreClear(t *testing.T) {
	s := NewCertStore(10, time.Hour)

	calls := 0
	gen := stubGen(&calls)
	if _, err := s.Fetch("a", gen); err != nil {
		t.Fatal(err)
	}

	s.Clear()
	if got := s.Len(); got != 0 {
		t.Errorf("Len() = %d after Clear(), want 0", got)
	}
	if _, err := s.Fetch("a", gen); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Error("Clear() did not drop the cached certificate")
	}
}

// TestCertStoreConcurrentFetchSignsOnce pins the behavior under a burst of
// CONNECTs to the same new host: signing once is the point of the store.
func TestCertStoreConcurrentFetchSignsOnce(t *testing.T) {
	s := NewCertStore(10, time.Hour)

	var mu sync.Mutex
	calls := 0
	gen := stubGen(&calls) // guarded by the store's own lock during Fetch
	counting := func() (*tls.Certificate, error) {
		mu.Lock()
		defer mu.Unlock()
		return gen()
	}

	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Fetch("burst.example.com", counting); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Errorf("generator called %d times under concurrent first-use, want 1", calls)
	}
}

// TestCertStoreSlowGenerationDoesNotBlockOtherHosts pins the head-of-line
// property. Signing is slow -- an RSA CA means a fresh key pair per call -- so
// holding one global lock across it would stall every other Fetch, including
// cache hits for unrelated hosts, behind a single cold host.
func TestCertStoreSlowGenerationDoesNotBlockOtherHosts(t *testing.T) {
	s := NewCertStore(10, time.Hour)

	// Warm a cache entry for a second host.
	warm := 0
	if _, err := s.Fetch("warm.example.com", stubGen(&warm)); err != nil {
		t.Fatal(err)
	}

	release := make(chan struct{})
	slowStarted := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := s.Fetch("slow.example.com", func() (*tls.Certificate, error) {
			close(slowStarted)
			<-release // hold the generation open
			return &tls.Certificate{Certificate: [][]byte{[]byte("slow")}}, nil
		}); err != nil {
			t.Error(err)
		}
	}()

	<-slowStarted

	// While that generation is in flight, an unrelated cache hit must complete.
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := s.Fetch("warm.example.com", stubGen(&warm)); err != nil {
			t.Error(err)
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("a cache hit blocked behind an unrelated in-flight generation")
	}

	close(release)
	wg.Wait()
}

// TestCertStoreConcurrentSameHostSignsOnceWithoutHoldingLock complements the
// above: same-host concurrency must still collapse to a single signature, even
// though the lock is no longer held across gen().
func TestCertStoreConcurrentSameHostSignsOnceWithoutHoldingLock(t *testing.T) {
	s := NewCertStore(10, time.Hour)

	var mu sync.Mutex
	calls := 0
	counted := 0
	gen := func() (*tls.Certificate, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		// Stay in flight long enough for the other goroutines to arrive.
		time.Sleep(50 * time.Millisecond)
		return stubGen(&counted)()
	}

	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Fetch("burst.example.com", gen); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Errorf("generator called %d times for one host under concurrency, want 1", calls)
	}
}

// TestMitmTLSConfigKeysCacheByCA pins that cached leaves belong to a signing
// identity, not just a hostname.
//
// Each sub-test holds one dimension fixed. The combined version of this test
// varied CA and Organization together, so either component alone separated the
// entries — deleting the CA hash from the key left it green, and that is the
// half with security consequence: it is what stops two callers sharing a
// mitm_org but using different CAs from being served a leaf signed by the wrong
// issuer.
func TestMitmTLSConfigKeysCacheByCA(t *testing.T) {
	caA := generateTestCert(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	caB := generateTestCert(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	leafFor := func(t *testing.T, fn func(string, *goproxy.ProxyCtx) (*tls.Config, error)) *x509.Certificate {
		t.Helper()
		cfg, err := fn("shared.example.com", nil)
		if err != nil {
			t.Fatalf("build TLS config: %v", err)
		}
		leaf, err := x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		return leaf
	}

	t.Run("different CA, same org", func(t *testing.T) {
		shared := NewCertStore(10, time.Hour)
		a := leafFor(t, MitmTLSConfigFromCA(&caA, "Same Org", shared))
		b := leafFor(t, MitmTLSConfigFromCA(&caB, "Same Org", shared))

		if a.SerialNumber.Cmp(b.SerialNumber) == 0 {
			t.Error("two CAs sharing an Organization were served one cached leaf; " +
				"the second caller gets a certificate signed by the wrong issuer")
		}

		// Issuer DN is not a discriminator here: the test CAs share a subject.
		// Check who actually signed each leaf.
		caBCert, err := x509.ParseCertificate(caB.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		if err := b.CheckSignatureFrom(caBCert); err != nil {
			t.Errorf("the second caller's leaf was not signed by its own CA: %v", err)
		}
	})

	t.Run("same CA, different org", func(t *testing.T) {
		shared := NewCertStore(10, time.Hour)
		a := leafFor(t, MitmTLSConfigFromCA(&caA, "Org A", shared))
		b := leafFor(t, MitmTLSConfigFromCA(&caA, "Org B", shared))

		if len(b.Subject.Organization) == 0 || b.Subject.Organization[0] != "Org B" {
			t.Errorf("second caller got Organization %v, want [Org B]; the org is not part of the cache key",
				b.Subject.Organization)
		}
		if a.SerialNumber.Cmp(b.SerialNumber) == 0 {
			t.Error("both orgs share one cached certificate")
		}
	})

	t.Run("same CA and org still caches", func(t *testing.T) {
		shared := NewCertStore(10, time.Hour)
		fn := MitmTLSConfigFromCA(&caA, "Org A", shared)
		first := leafFor(t, fn)
		again := leafFor(t, fn)

		if first.SerialNumber.Cmp(again.SerialNumber) != 0 {
			t.Error("same CA and host re-signed; qualifying the key must not defeat caching")
		}
	})
}
