package store

import (
	"sync"

	"github.com/go-analyze/bulk"
)

// Storage defines the interface for key-value blob storage.
type Storage interface {
	Save(key string, blob []byte) error
	Load(key string) ([]byte, bool, error)
	Delete(key string) error
	ListKeys() ([]string, error)
	Clear() error
	Close()
}

type memStorage struct {
	mu   sync.Mutex
	data map[string][]byte
}

// NewMemStorage returns an in-memory Storage implementation.
func NewMemStorage() Storage {
	return &memStorage{data: make(map[string][]byte)}
}

func (m *memStorage) Save(key string, blob []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.data[key] = append([]byte(nil), blob...) // copy the blob to avoid external mutation
	return nil
}

func (m *memStorage) Load(key string) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	blob, ok := m.data[key]
	if !ok {
		return nil, false, nil
	}
	return append([]byte(nil), blob...), true, nil
}

func (m *memStorage) Delete(key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.data, key)
	return nil
}

func (m *memStorage) ListKeys() ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	return bulk.MapKeysSlice(m.data), nil
}

func (m *memStorage) Clear() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	clear(m.data)
	return nil
}

func (m *memStorage) Close() {
	// no resources to free
}
