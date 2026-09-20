package service

import (
	"slices"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/config"
	"github.com/go-appsec/toolbox/sectool/service/proxy"
	"github.com/go-appsec/toolbox/sectool/service/store"
)

// closeTrackingStorage wraps a Storage and records Close calls.
type closeTrackingStorage struct {
	store.Storage
	name       string
	closeCount *atomic.Int64
}

func (s *closeTrackingStorage) Close() error {
	s.closeCount.Add(1)
	return s.Storage.Close()
}

// trackingProvider returns distinct named stores over a shared memory backend and
// records each store's close count keyed by name.
type trackingProvider struct {
	mu         sync.RWMutex
	storages   map[string]*closeTrackingStorage
	allocNames []string // allocation order, for asserting which names were requested
}

func newTrackingProvider() *trackingProvider {
	return &trackingProvider{storages: make(map[string]*closeTrackingStorage)}
}

func (p *trackingProvider) provider(name string) (store.Storage, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if existing, ok := p.storages[name]; ok {
		return existing, nil
	}
	s := &closeTrackingStorage{Storage: store.NewMemStorage(), name: name, closeCount: new(atomic.Int64)}
	p.storages[name] = s
	p.allocNames = append(p.allocNames, name)
	return s, nil
}

func (p *trackingProvider) closeCount(name string) int64 {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if s, ok := p.storages[name]; ok {
		return s.closeCount.Load()
	}
	return -1 // not allocated: distinguish from closed-once
}

func (p *trackingProvider) allocated(name string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	_, ok := p.storages[name]
	return ok
}

// TestBackendsAllocateAndCloseSharedStore verifies each backend path allocates its
// named store from a shared provider and closes it exactly once on shutdown.
func TestBackendsAllocateAndCloseSharedStore(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	p := newTrackingProvider()

	oa, err := NewInteractshBackend("", "", p.provider)
	require.NoError(t, err)

	crawlCfg := config.DefaultConfig()
	crawler, err := NewCollyBackend(ctx, crawlCfg, store.NewReplayHistoryStore(store.NewMemStorage()), nil, p.provider)
	require.NoError(t, err)

	native, err := NewNativeProxyBackend(ctx, 0, t.TempDir(), crawlCfg.MaxBodyBytes, p.provider, proxy.TimeoutConfig{}, false)
	require.NoError(t, err)

	// All three paths requested their named store from the shared provider.
	for _, name := range []string{"oast", "crawl", "hist"} {
		assert.True(t, p.allocated(name), "%s store not allocated from provider", name)
	}

	require.NoError(t, oa.Close(ctx))
	require.NoError(t, crawler.Close(ctx))
	require.NoError(t, native.Close(ctx))

	// Each owned store is closed exactly once: no leak, no double-close.
	for _, name := range []string{"oast", "crawl"} {
		assert.EqualValues(t, 1, p.closeCount(name), "%s close count", name)
	}
}

// TestBackendsAllocateDistinctStores confirms the provider hands each backend its
// own named store so backends never share an allocation they would double-close.
func TestBackendsAllocateDistinctStores(t *testing.T) {
	t.Parallel()

	p := newTrackingProvider()
	if _, err := NewInteractshBackend("", "", p.provider); err != nil {
		t.Fatal(err)
	}
	crawlCfg := config.DefaultConfig()
	_, err := NewCollyBackend(t.Context(), crawlCfg, store.NewReplayHistoryStore(store.NewMemStorage()), nil, p.provider)
	require.NoError(t, err)

	p.mu.RLock()
	names := slices.Clone(p.allocNames)
	p.mu.RUnlock()

	assert.Equal(t, []string{"oast", "crawl"}, names)
}
