package store

import (
	"fmt"
	"math/rand"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

const benchRecordCount = 2_000

// storageProvider creates a storage backend for benchmarking.
type storageProvider struct {
	name    string
	factory func(b *testing.B) Storage
}

var storageProviders = []storageProvider{
	{
		name: "memory",
		factory: func(b *testing.B) Storage {
			b.Helper()

			return NewMemStorage()
		},
	},
	{
		name: "spill",
		factory: func(b *testing.B) Storage {
			b.Helper()

			config := DefaultSpillStoreConfig()
			config.MaxHotBytes = 100 * 1024
			config.CompactionThreshold = 50 * 1024
			s, err := NewSpillStore(config)
			require.NoError(b, err)
			return s
		},
	},
}

var fakeBodyContent = makeFakeBody()

func makeFakeBody() []byte {
	r := rand.New(rand.NewSource(1337)) // deterministic seed
	respBody := []byte("BODY START\n\n")
	for i := 0; i < benchRecordCount; i++ {
		// create a body with content of some size and variations
		respBody = append(respBody, uuid.New().String()...)
		if r.Intn(2) == 0 {
			if i%4 == 0 {
				respBody = append(respBody, []byte(": This example is sorta shorter test response body content.")...)
			} else if i%2 == 0 {
				respBody = append(respBody, []byte(": This is much longer test response body content. ")...)
				respBody = append(respBody, []byte("The quick brown fox jumped over the lazy dog.")...)
			} else {
				respBody = append(respBody, []byte(": Alternative content in this case. ")...)
				respBody = append(respBody, []byte("It's another two sentence example to give similar length.")...)
			}
		} else {
			t := time.Now().Add((time.Hour * time.Duration(i)) + (time.Minute * time.Duration(r.Intn(60))))
			respBody = append(respBody, []byte(" == ")...)
			if i%2 == 0 {
				respBody = append(respBody, t.Format(time.RFC850)...)
			} else {
				respBody = append(respBody, t.Format(time.RFC3339Nano)...)
			}
			if i%4 == 0 {
				respBody = append(respBody, []byte(": Another set of examples, now prefixed with timestamps.")...)
			} else if i%2 == 0 {
				respBody = append(respBody, []byte(": We want to have some variety to our content,")...)
				respBody = append(respBody, []byte(" but be deterministic to evaluate in a regular and consistent way.")...)
			} else {
				respBody = append(respBody, []byte(": Final example content, just going to keep this short.")...)
			}
		}
		respBody = append(respBody, '\n', '\n')
	}
	return append(respBody, []byte("BODY END")...)
}

func BenchmarkReplayHistoryStore_AddGetRemove(b *testing.B) {
	for _, sp := range storageProviders {
		b.Run(sp.name, func(b *testing.B) {
			storage := sp.factory(b)
			b.Cleanup(func() { _ = storage.Close() })

			store := NewReplayHistoryStore(storage)
			b.Cleanup(store.Close)
			rawRequest := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
			respHeaders := []byte("HTTP/1.1 200 OK\r\n\r\n")

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Add records
				for j := 0; j < benchRecordCount; j++ {
					store.Store(&ReplayHistoryEntry{
						FlowID:          fmt.Sprintf("replay-%d", j),
						CreatedAt:       time.Now().Add(-time.Hour * time.Duration(j)),
						ReferenceOffset: uint32(j),
						RawRequest:      rawRequest,
						Method:          "GET",
						Host:            "example.com",
						Path:            "/",
						Protocol:        "http/1.1",
						RespHeaders:     respHeaders,
						RespBody:        fakeBodyContent,
						RespStatus:      200,
						Duration:        time.Duration(20+j) * time.Millisecond,
					})
				}
				for j := 0; j < benchRecordCount; j++ {
					_, _ = store.Get(fmt.Sprintf("replay-%d", j))
				}
				store.Clear()
			}
		})
	}
}

func BenchmarkReplayHistoryStore_List(b *testing.B) {
	for _, sp := range storageProviders {
		b.Run(sp.name, func(b *testing.B) {
			storage := sp.factory(b)
			b.Cleanup(func() { _ = storage.Close() })

			store := NewReplayHistoryStore(storage)
			b.Cleanup(store.Close)

			// Prepare records
			respHeaders := []byte("HTTP/1.1 200 OK\r\n\r\n")
			for j := 0; j < benchRecordCount; j++ {
				store.Store(&ReplayHistoryEntry{
					FlowID:          fmt.Sprintf("replay-%d", j),
					CreatedAt:       time.Now().Add(-time.Hour * time.Duration(j)),
					ReferenceOffset: uint32(j),
					RawRequest:      []byte("GET /path" + strconv.Itoa(j) + " HTTP/1.1\r\nHost: example.com\r\n\r\n"),
					Method:          "GET",
					Host:            "example.com",
					Path:            "/path" + strconv.Itoa(j),
					Protocol:        "http/1.1",
					RespHeaders:     respHeaders,
					RespBody:        fakeBodyContent,
					RespStatus:      200,
					Duration:        time.Duration(20+j) * time.Millisecond,
				})
			}
			if s, ok := storage.(*spillStore); ok && s.fileSize > 32 {
				b.Logf("spill file size: %d bytes", s.fileSize)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = store.List()
			}
		})
	}
}
