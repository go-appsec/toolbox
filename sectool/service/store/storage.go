package store

import (
	"errors"
	"slices"
	"strings"
	"sync"

	"github.com/go-analyze/bulk"
)

// Storage defines the interface for key-value blob storage.
type Storage interface {
	Set(key string, blob []byte) error
	Get(key string) ([]byte, bool, error)
	// Keys returns all keys beginning with prefix, in unspecified order.
	Keys(prefix string) []string
	KeySet() []string
	Size() int
	Delete(key string) error
	DeleteAll() error
	Close() error
}

// Provider allocates a named Storage instance.
// Backends call this in their constructor and own Close on returned stores.
// Names are storage addresses: durable implementations must map a given name
// to the same data across restarts.
type Provider func(name string) (Storage, error)

// MemProvider returns a fresh in-memory Storage for every name.
func MemProvider(string) (Storage, error) {
	return NewMemStorage(), nil
}

type memStorage struct {
	mu   sync.Mutex
	data map[string][]byte
}

// NewMemStorage returns an in-memory Storage implementation.
func NewMemStorage() Storage {
	return &memStorage{data: make(map[string][]byte)}
}

func (m *memStorage) Set(key string, blob []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.data[key] = append([]byte(nil), blob...) // copy the blob to avoid external mutation
	return nil
}

func (m *memStorage) Get(key string) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	blob, ok := m.data[key]
	if !ok {
		return nil, false, nil
	}
	return slices.Clone(blob), true, nil
}

func (m *memStorage) Keys(prefix string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	return bulk.SliceFilterInPlace(func(k string) bool {
		return strings.HasPrefix(k, prefix)
	}, bulk.MapKeysSlice(m.data))
}

func (m *memStorage) KeySet() []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	return bulk.MapKeysSlice(m.data)
}

func (m *memStorage) Size() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	return len(m.data)
}

func (m *memStorage) Delete(key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.data, key)
	return nil
}

func (m *memStorage) DeleteAll() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	clear(m.data)
	return nil
}

func (m *memStorage) Close() error {
	return m.DeleteAll()
}

// prefixedStorage namespaces every key under a fixed prefix within a base Storage.
type prefixedStorage struct {
	base   Storage
	prefix string
}

// NewPrefixedStorage returns a Storage that namespaces every key under prefix
// within base, isolating stores that share one backing implementation. Close
// is a no-op; the caller owns the base store's lifetime.
func NewPrefixedStorage(base Storage, prefix string) Storage {
	return &prefixedStorage{base: base, prefix: prefix}
}

func (s *prefixedStorage) Set(key string, blob []byte) error {
	return s.base.Set(s.prefix+key, blob)
}

func (s *prefixedStorage) Get(key string) ([]byte, bool, error) {
	return s.base.Get(s.prefix + key)
}

func (s *prefixedStorage) Keys(prefix string) []string {
	keys := s.base.Keys(s.prefix + prefix)
	for i, k := range keys {
		keys[i] = strings.TrimPrefix(k, s.prefix)
	}
	return keys
}

func (s *prefixedStorage) KeySet() []string {
	return s.Keys("")
}

func (s *prefixedStorage) Size() int {
	return len(s.KeySet())
}

func (s *prefixedStorage) Delete(key string) error {
	return s.base.Delete(s.prefix + key)
}

func (s *prefixedStorage) DeleteAll() error {
	for _, k := range s.base.Keys(s.prefix) {
		if err := s.base.Delete(k); err != nil {
			return err
		}
	}
	return nil
}

func (s *prefixedStorage) Close() error {
	return nil // base store is owned by the creator
}

// PrefixedProvider returns a Provider that serves every named store from one
// shared base Storage, namespacing each under "<name>:". The returned function
// closes the base; per-store Close calls are no-ops.
func PrefixedProvider(base Storage) (Provider, func() error) {
	return func(name string) (Storage, error) {
		if name == "" {
			return nil, errors.New("storage name required")
		}
		return NewPrefixedStorage(base, name+":"), nil
	}, base.Close
}
