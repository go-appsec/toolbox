package store

import (
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
