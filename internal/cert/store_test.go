// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

package cert

import (
	"crypto/tls"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
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
