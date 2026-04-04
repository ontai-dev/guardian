package permissionservice

import (
	"sync"

	"github.com/ontai-dev/guardian/internal/epg"
)

// EPGStore is the read-write interface for the in-memory Effective Permission Graph.
// EPGReconciler calls Update after each successful computation; Service reads via
// GetLatestResult.
type EPGStore interface {
	// Update atomically replaces the stored EPGComputationResult with the provided
	// result. Called by EPGReconciler after each successful EPG computation.
	Update(result epg.EPGComputationResult)

	// GetLatestResult returns the latest EPGComputationResult and true, or nil and
	// false if no result has been stored yet.
	GetLatestResult() (*epg.EPGComputationResult, bool)
}

// InMemoryEPGStore is the production EPGStore implementation. It stores the latest
// EPGComputationResult in memory and is safe for concurrent access.
type InMemoryEPGStore struct {
	mu     sync.RWMutex
	latest *epg.EPGComputationResult
}

// NewInMemoryEPGStore allocates and returns an empty InMemoryEPGStore.
func NewInMemoryEPGStore() *InMemoryEPGStore {
	return &InMemoryEPGStore{}
}

// Update atomically replaces the stored result. Safe for concurrent calls.
func (s *InMemoryEPGStore) Update(result epg.EPGComputationResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.latest = &result
}

// GetLatestResult returns the latest stored result. Returns (nil, false) if
// no computation has completed yet.
func (s *InMemoryEPGStore) GetLatestResult() (*epg.EPGComputationResult, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.latest == nil {
		return nil, false
	}
	return s.latest, true
}
