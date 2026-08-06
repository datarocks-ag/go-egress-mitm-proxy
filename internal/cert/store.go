// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

package cert

import (
	"container/list"
	"crypto/tls"
	"sync"
	"time"
)

// DefaultCertCacheSize bounds how many leaf certificates are held.
//
// Each entry is a small cert plus its key; a few thousand is negligible memory
// and covers far more distinct hosts than a normal egress policy allows.
const DefaultCertCacheSize = 2048

// DefaultCertTTL is how long a cached leaf is reused.
//
// Well inside the 365-day leaf validity from SignHost, so a long-running process
// re-signs periodically instead of serving a certificate that has expired in
// cache.
const DefaultCertTTL = 24 * time.Hour

// CertStore caches generated MITM leaf certificates with a bounded LRU and a TTL.
//
// It replaces two opposite pathologies. goproxy only caches when
// proxy.CertStore is set, and it never was, so the default path re-signed on
// every CONNECT — generating a fresh RSA-2048 key pair each time when the CA key
// is RSA, at roughly 70ms of CPU per connection to the same host. Setting
// mitm_org swapped in a different path whose sync.Map cache had no eviction, no
// TTL and no expiry check, so memory grew without bound under a CONNECT flood
// over random hostnames and a process running past a year served expired leaves
// from cache.
//
// Which caching behavior applied was selected by an unrelated cosmetic field.
// Both paths now share this store.
//
// CertStore implements goproxy.CertStorage.
type CertStore struct {
	mu      sync.Mutex
	maxSize int
	ttl     time.Duration
	entries map[string]*list.Element
	order   *list.List // front = most recently used

	// now is overridable so TTL expiry is testable without sleeping.
	now func() time.Time
}

type certEntry struct {
	hostname  string
	cert      *tls.Certificate
	expiresAt time.Time
}

// NewCertStore returns a store holding at most maxSize certificates for ttl each.
// Non-positive values fall back to the defaults.
func NewCertStore(maxSize int, ttl time.Duration) *CertStore {
	if maxSize <= 0 {
		maxSize = DefaultCertCacheSize
	}
	if ttl <= 0 {
		ttl = DefaultCertTTL
	}
	return &CertStore{
		maxSize: maxSize,
		ttl:     ttl,
		entries: make(map[string]*list.Element, maxSize),
		order:   list.New(),
		now:     time.Now,
	}
}

// Fetch returns the cached certificate for hostname, generating and storing one
// via gen on a miss or when the cached entry has expired.
//
// This is goproxy's CertStorage contract. gen is called with the lock held so
// concurrent CONNECTs to the same new host sign once rather than racing to
// produce duplicates — signing is the expensive operation this store exists to
// avoid.
func (s *CertStore) Fetch(hostname string, gen func() (*tls.Certificate, error)) (*tls.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if elem, ok := s.entries[hostname]; ok {
		entry := elem.Value.(*certEntry) //nolint:errcheck // stored type is always *certEntry
		if s.now().Before(entry.expiresAt) {
			s.order.MoveToFront(elem)
			return entry.cert, nil
		}
		// Expired: drop it and fall through to regenerate.
		s.order.Remove(elem)
		delete(s.entries, hostname)
	}

	cert, err := gen()
	if err != nil {
		return nil, err
	}

	elem := s.order.PushFront(&certEntry{
		hostname:  hostname,
		cert:      cert,
		expiresAt: s.now().Add(s.ttl),
	})
	s.entries[hostname] = elem

	for s.order.Len() > s.maxSize {
		oldest := s.order.Back()
		if oldest == nil {
			break
		}
		s.order.Remove(oldest)
		delete(s.entries, oldest.Value.(*certEntry).hostname) //nolint:errcheck // stored type is always *certEntry
	}

	return cert, nil
}

// Len reports how many certificates are currently cached.
func (s *CertStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.order.Len()
}

// Clear drops every cached certificate. Call when the signing CA changes, so
// leaves signed by the previous CA are not served afterwards.
func (s *CertStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = make(map[string]*list.Element, s.maxSize)
	s.order.Init()
}
