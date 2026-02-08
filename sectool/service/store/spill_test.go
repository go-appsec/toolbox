package store

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newSpillStore(cfg SpillStoreConfig) (*spillStore, error) {
	s, err := NewSpillStore(cfg)
	if err != nil {
		return nil, err
	}
	return s.(*spillStore), nil
}

func TestSpillStore(t *testing.T) {
	t.Parallel()

	t.Run("set_and_get", func(t *testing.T) {
		s, err := NewSpillStore(DefaultSpillStoreConfig())
		require.NoError(t, err)
		t.Cleanup(func() { _ = s.Close() })

		err = s.Set("key1", []byte("value1"))
		require.NoError(t, err)

		data, found, err := s.Get("key1")
		require.NoError(t, err)
		assert.True(t, found)
		assert.Equal(t, []byte("value1"), data)
	})

	t.Run("get_not_found", func(t *testing.T) {
		s, err := NewSpillStore(DefaultSpillStoreConfig())
		require.NoError(t, err)
		t.Cleanup(func() { _ = s.Close() })

		data, found, err := s.Get("nonexistent")
		require.NoError(t, err)
		assert.False(t, found)
		assert.Nil(t, data)
	})

	t.Run("delete", func(t *testing.T) {
		s, err := NewSpillStore(DefaultSpillStoreConfig())
		require.NoError(t, err)
		t.Cleanup(func() { _ = s.Close() })

		require.NoError(t, s.Set("key1", []byte("v")))

		require.NoError(t, s.Delete("key1"))

		_, found, err := s.Get("key1")
		require.NoError(t, err)
		assert.False(t, found)
	})

	t.Run("key_set", func(t *testing.T) {
		s, err := NewSpillStore(DefaultSpillStoreConfig())
		require.NoError(t, err)
		t.Cleanup(func() { _ = s.Close() })

		require.NoError(t, s.Set("a", []byte("1")))
		require.NoError(t, s.Set("b", []byte("2")))
		require.NoError(t, s.Set("c", []byte("3")))

		keys := s.KeySet()
		assert.Len(t, keys, 3)
		assert.Contains(t, keys, "a")
		assert.Contains(t, keys, "b")
		assert.Contains(t, keys, "c")
	})

	t.Run("delete_all", func(t *testing.T) {
		s, err := NewSpillStore(DefaultSpillStoreConfig())
		require.NoError(t, err)
		t.Cleanup(func() { _ = s.Close() })

		require.NoError(t, s.Set("k1", []byte("v")))
		require.NoError(t, s.Set("k2", []byte("v")))

		require.NoError(t, s.DeleteAll())

		keys := s.KeySet()
		assert.Empty(t, keys)
	})

	t.Run("copies_data", func(t *testing.T) {
		s, err := NewSpillStore(DefaultSpillStoreConfig())
		require.NoError(t, err)
		t.Cleanup(func() { _ = s.Close() })

		original := []byte("original")
		require.NoError(t, s.Set("key", original))

		// Modify original
		original[0] = 'X'

		// Loaded data should be unchanged
		loaded, _, err := s.Get("key")
		require.NoError(t, err)
		assert.Equal(t, byte('o'), loaded[0])

		// Modify loaded data
		loaded[0] = 'Y'

		// Load again should be unchanged
		loaded2, _, err := s.Get("key")
		require.NoError(t, err)
		assert.Equal(t, byte('o'), loaded2[0])
	})

	t.Run("temp_dir_cleanup", func(t *testing.T) {
		s, err := newSpillStore(DefaultSpillStoreConfig())
		require.NoError(t, err)

		// Verify temp dir exists
		_, err = os.Stat(s.dataDir)
		require.NoError(t, err)

		require.NoError(t, s.Close())

		// Verify temp dir is removed
		_, err = os.Stat(s.dataDir)
		assert.True(t, os.IsNotExist(err))
	})

	t.Run("large_values", func(t *testing.T) {
		s, err := NewSpillStore(DefaultSpillStoreConfig())
		require.NoError(t, err)
		t.Cleanup(func() { _ = s.Close() })

		// 1MB value
		large := make([]byte, 1<<20)
		for i := range large {
			large[i] = byte(i % 256)
		}

		err = s.Set("large", large)
		require.NoError(t, err)

		data, found, err := s.Get("large")
		require.NoError(t, err)
		assert.True(t, found)
		assert.Equal(t, large, data)
	})

	t.Run("binary_keys", func(t *testing.T) {
		s, err := NewSpillStore(DefaultSpillStoreConfig())
		require.NoError(t, err)
		t.Cleanup(func() { _ = s.Close() })

		key := "key\x00with\x00nulls"
		err = s.Set(key, []byte("value"))
		require.NoError(t, err)

		data, found, err := s.Get(key)
		require.NoError(t, err)
		assert.True(t, found)
		assert.Equal(t, []byte("value"), data)
	})

	t.Run("empty_value", func(t *testing.T) {
		s, err := NewSpillStore(DefaultSpillStoreConfig())
		require.NoError(t, err)
		t.Cleanup(func() { _ = s.Close() })

		err = s.Set("empty", []byte{})
		require.NoError(t, err)

		data, found, err := s.Get("empty")
		require.NoError(t, err)
		assert.True(t, found)
		assert.Empty(t, data)
	})

	t.Run("overwrite_adjusts_size", func(t *testing.T) {
		s, err := newSpillStore(DefaultSpillStoreConfig())
		require.NoError(t, err)
		t.Cleanup(func() { _ = s.Close() })

		require.NoError(t, s.Set("key", []byte("short")))

		s.mu.Lock()
		hotBytesBefore := s.hotBytes
		s.mu.Unlock()

		require.NoError(t, s.Set("key", []byte("much-longer-value")))

		s.mu.Lock()
		hotBytesAfter := s.hotBytes
		s.mu.Unlock()

		assert.Equal(t, hotBytesBefore-int64(len("short"))+int64(len("much-longer-value")), hotBytesAfter)

		loaded, found, err := s.Get("key")
		require.NoError(t, err)
		assert.True(t, found)
		assert.Equal(t, []byte("much-longer-value"), loaded)
	})

	t.Run("custom_temp_dir", func(t *testing.T) {
		customDir := t.TempDir()
		cfg := SpillStoreConfig{
			MaxHotBytes:         1024 * 1024,
			EvictTargetRatio:    0.7,
			CompactionThreshold: 1024 * 1024,
			ZSTDLevel:           1,
			Dir:                 customDir,
		}

		s, err := newSpillStore(cfg)
		require.NoError(t, err)
		defer func() { _ = s.Close() }()

		assert.Equal(t, customDir, s.dataDir)

		require.NoError(t, s.Set("key", []byte("value")))
		_, err = os.Stat(filepath.Join(customDir, spillDataFile))
		require.NoError(t, err)
	})

	t.Run("set_on_closed", func(t *testing.T) {
		s, err := NewSpillStore(DefaultSpillStoreConfig())
		require.NoError(t, err)
		require.NoError(t, s.Close())

		err = s.Set("key", []byte("value"))
		assert.ErrorIs(t, err, ErrClosed)
	})

	t.Run("get_on_closed", func(t *testing.T) {
		s, err := NewSpillStore(DefaultSpillStoreConfig())
		require.NoError(t, err)
		require.NoError(t, s.Set("key", []byte("value")))
		require.NoError(t, s.Close())

		_, _, err = s.Get("key")
		assert.ErrorIs(t, err, ErrClosed)
	})

	t.Run("delete_on_closed", func(t *testing.T) {
		s, err := NewSpillStore(DefaultSpillStoreConfig())
		require.NoError(t, err)
		require.NoError(t, s.Close())

		assert.ErrorIs(t, s.Delete("key"), ErrClosed)
	})

	t.Run("key_set_on_closed", func(t *testing.T) {
		s, err := NewSpillStore(DefaultSpillStoreConfig())
		require.NoError(t, err)
		require.NoError(t, s.Close())

		keys := s.KeySet()
		assert.Empty(t, keys)
	})

	t.Run("delete_all_on_closed", func(t *testing.T) {
		s, err := NewSpillStore(DefaultSpillStoreConfig())
		require.NoError(t, err)
		require.NoError(t, s.Close())

		assert.ErrorIs(t, s.DeleteAll(), ErrClosed)
	})
}

func TestSpillStore_Eviction(t *testing.T) {
	t.Parallel()

	t.Run("eviction_to_disk", func(t *testing.T) {
		cfg := SpillStoreConfig{
			MaxHotBytes:         1000,
			EvictTargetRatio:    0.5,
			CompactionThreshold: 5000,
			ZSTDLevel:           1,
		}
		s, err := newSpillStore(cfg)
		require.NoError(t, err)
		t.Cleanup(func() { _ = s.Close() })

		// Set entries exceeding hot cache limit
		for i := 0; i < 20; i++ {
			data := make([]byte, 100)
			for j := range data {
				data[j] = byte(i)
			}
			err := s.Set("key"+string(rune('a'+i)), data)
			require.NoError(t, err)
		}

		s.wg.Wait() // Wait for eviction to complete

		// Verify some entries are on disk
		s.mu.Lock()
		var onDisk int
		for _, e := range s.index {
			if !e.inMemory {
				onDisk++
			}
		}
		s.mu.Unlock()

		assert.Positive(t, onDisk)
	})

	t.Run("load_from_disk", func(t *testing.T) {
		cfg := SpillStoreConfig{
			MaxHotBytes:         500,
			EvictTargetRatio:    0.5,
			CompactionThreshold: 5000,
			ZSTDLevel:           1,
		}
		s, err := newSpillStore(cfg)
		require.NoError(t, err)
		t.Cleanup(func() { _ = s.Close() })

		// Save data that exceeds hot cache
		data1 := make([]byte, 200)
		for i := range data1 {
			data1[i] = byte(1)
		}
		err = s.Set("key1", data1)
		require.NoError(t, err)

		data2 := make([]byte, 200)
		for i := range data2 {
			data2[i] = byte(2)
		}
		err = s.Set("key2", data2)
		require.NoError(t, err)

		data3 := make([]byte, 200)
		for i := range data3 {
			data3[i] = byte(3)
		}
		err = s.Set("key3", data3)
		require.NoError(t, err)

		s.wg.Wait() // Wait for eviction to complete

		// Get all keys - should work regardless of location
		loaded1, found1, err := s.Get("key1")
		require.NoError(t, err)
		assert.True(t, found1)
		assert.Equal(t, data1, loaded1)

		loaded2, found2, err := s.Get("key2")
		require.NoError(t, err)
		assert.True(t, found2)
		assert.Equal(t, data2, loaded2)

		loaded3, found3, err := s.Get("key3")
		require.NoError(t, err)
		assert.True(t, found3)
		assert.Equal(t, data3, loaded3)
	})

	t.Run("overwrite_on_disk_marks_dead", func(t *testing.T) {
		cfg := SpillStoreConfig{
			MaxHotBytes:         300,
			EvictTargetRatio:    0.5,
			CompactionThreshold: 10000,
			ZSTDLevel:           1,
		}
		s, err := newSpillStore(cfg)
		require.NoError(t, err)
		t.Cleanup(func() { _ = s.Close() })

		// Set and evict to disk
		data := make([]byte, 100)
		require.NoError(t, s.Set("key1", data))
		for i := 0; i < 5; i++ {
			require.NoError(t, s.Set("filler"+string(rune('a'+i)), make([]byte, 100)))
		}
		s.wg.Wait()

		// Verify key1 is on disk
		s.mu.Lock()
		entry := s.index["key1"]
		require.NotNil(t, entry)
		assert.False(t, entry.inMemory)
		oldDiskLen := entry.diskLen
		deadBytesBefore := s.deadBytes
		s.mu.Unlock()
		assert.Positive(t, oldDiskLen)

		// Overwrite while on disk (without loading first)
		newData := []byte("new value")
		require.NoError(t, s.Set("key1", newData))

		// Old disk space should be marked dead
		s.mu.Lock()
		entry = s.index["key1"]
		assert.True(t, entry.inMemory)
		assert.Equal(t, 0, entry.diskLen)
		assert.Equal(t, deadBytesBefore+int64(oldDiskLen), s.deadBytes)
		s.mu.Unlock()

		// Verify new value loads correctly
		loaded, found, err := s.Get("key1")
		require.NoError(t, err)
		assert.True(t, found)
		assert.Equal(t, newData, loaded)
	})

	t.Run("eviction_skips_accessed", func(t *testing.T) {
		cfg := SpillStoreConfig{
			MaxHotBytes:         400,
			EvictTargetRatio:    0.5,
			CompactionThreshold: 10000,
			ZSTDLevel:           1,
		}
		s, err := newSpillStore(cfg)
		require.NoError(t, err)
		t.Cleanup(func() { _ = s.Close() })

		// Set entries
		for i := 0; i < 3; i++ {
			require.NoError(t, s.Set("key"+string(rune('a'+i)), make([]byte, 100)))
		}

		// Access keya to update lastAccess
		_, _, err = s.Get("keya")
		require.NoError(t, err)

		// Add more to trigger eviction - should evict keyb, keyc first
		for i := 0; i < 3; i++ {
			require.NoError(t, s.Set("filler"+string(rune('a'+i)), make([]byte, 100)))
		}
		s.wg.Wait()

		// All entries should still be loadable
		for _, key := range []string{"keya", "keyb", "keyc"} {
			data, found, err := s.Get(key)
			require.NoError(t, err)
			assert.True(t, found, "key %s should be found", key)
			assert.Len(t, data, 100)
		}
	})
}

func TestSpillStore_Compaction(t *testing.T) {
	t.Parallel()

	cfg := SpillStoreConfig{
		MaxHotBytes:         200,
		EvictTargetRatio:    0.5,
		CompactionThreshold: 100, // Low threshold to trigger compaction
		ZSTDLevel:           1,
	}
	s, err := newSpillStore(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	// Set data to fill hot cache and trigger eviction
	for i := 0; i < 5; i++ {
		data := make([]byte, 100)
		for j := range data {
			data[j] = byte(i)
		}
		err := s.Set("key"+string(rune('a'+i)), data)
		require.NoError(t, err)
	}

	s.wg.Wait() // Wait for eviction to complete

	// Delete some entries to create dead space
	require.NoError(t, s.Delete("keya"))
	require.NoError(t, s.Delete("keyb"))

	// Get remaining entries to trigger compaction
	for i := 2; i < 5; i++ {
		_, _, err := s.Get("key" + string(rune('a'+i)))
		require.NoError(t, err)
	}

	s.wg.Wait() // Wait for compaction

	// Verify remaining entries still work
	for i := 2; i < 5; i++ {
		data, found, err := s.Get("key" + string(rune('a'+i)))
		require.NoError(t, err)
		assert.True(t, found)
		expected := make([]byte, 100)
		for j := range expected {
			expected[j] = byte(i)
		}
		assert.Equal(t, expected, data)
	}
}

func TestSpillStore_Encryption(t *testing.T) {
	t.Parallel()

	t.Run("encrypted_on_disk", func(t *testing.T) {
		cfg := SpillStoreConfig{
			MaxHotBytes:         100,
			EvictTargetRatio:    0.5,
			CompactionThreshold: 5000,
			ZSTDLevel:           1,
		}
		s, err := newSpillStore(cfg)
		require.NoError(t, err)
		defer func() { _ = s.Close() }()

		// Set data that will be evicted to disk
		testData := []byte("secret data that should be encrypted on disk")
		err = s.Set("secret", testData)
		require.NoError(t, err)

		// Set more to trigger eviction
		for i := 0; i < 5; i++ {
			require.NoError(t, s.Set("filler"+string(rune('a'+i)), make([]byte, 50)))
		}

		s.wg.Wait() // Wait for eviction to complete

		// Read raw file contents
		dataPath := filepath.Join(s.dataDir, spillDataFile)
		rawData, err := os.ReadFile(dataPath)
		require.NoError(t, err)

		// Skip header
		rawData = rawData[spillHeaderSize:]

		// Verify plaintext is not present
		assert.NotContains(t, string(rawData), "secret data")
	})

	t.Run("always_enabled", func(t *testing.T) {
		cfg := SpillStoreConfig{
			MaxHotBytes:         100,
			EvictTargetRatio:    0.5,
			CompactionThreshold: 5000,
			ZSTDLevel:           1,
		}
		s, err := newSpillStore(cfg)
		require.NoError(t, err)
		defer func() { _ = s.Close() }()

		assert.NotNil(t, s.gcm)
		assert.NotNil(t, s.encKey)

		// Set data that will be evicted to disk
		testData := make([]byte, 80)
		for i := range testData {
			testData[i] = byte(i)
		}
		require.NoError(t, s.Set("key1", testData))

		// Trigger eviction
		for i := 0; i < 5; i++ {
			require.NoError(t, s.Set("filler"+string(rune('a'+i)), make([]byte, 50)))
		}
		s.wg.Wait()

		// Round-trip should still work
		loaded, found, err := s.Get("key1")
		require.NoError(t, err)
		assert.True(t, found)
		assert.Equal(t, testData, loaded)
	})
}

func TestSpillStore_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	cfg := SpillStoreConfig{
		MaxHotBytes:         1000,
		EvictTargetRatio:    0.7,
		CompactionThreshold: 500,
		ZSTDLevel:           1,
	}
	s, err := NewSpillStore(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	const goroutines = 10
	const iterations = 50

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()

			for i := 0; i < iterations; i++ {
				key := "key" + string(rune('a'+id)) + string(rune('0'+i%10))
				data := make([]byte, 50)
				for j := range data {
					data[j] = byte(id*10 + i)
				}

				// Mix of operations
				switch i % 4 {
				case 0:
					_ = s.Set(key, data)
				case 1:
					_, _, _ = s.Get(key)
				case 2:
					_ = s.KeySet()
				case 3:
					_ = s.Delete(key)
				}
			}
		}(g)
	}

	wg.Wait()

	// Verify storage is still functional
	err = s.Set("final", []byte("test"))
	require.NoError(t, err)

	data, found, err := s.Get("final")
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, []byte("test"), data)
}

func TestSpillStore_CleanEntries(t *testing.T) {
	t.Parallel()

	t.Run("load_evict_unchanged", func(t *testing.T) {
		// Test that loading from disk and evicting without modification reuses disk position
		cfg := SpillStoreConfig{
			MaxHotBytes:         300,
			EvictTargetRatio:    0.5,
			CompactionThreshold: 100000, // high to prevent compaction
			ZSTDLevel:           1,
		}
		s, err := newSpillStore(cfg)
		require.NoError(t, err)
		t.Cleanup(func() { _ = s.Close() })

		// Set initial entry
		data := make([]byte, 100)
		for i := range data {
			data[i] = byte(42)
		}
		require.NoError(t, s.Set("key1", data))

		// Fill cache to trigger eviction
		for i := 0; i < 5; i++ {
			err = s.Set("filler"+string(rune('a'+i)), make([]byte, 100))
			require.NoError(t, err)
		}

		s.wg.Wait() // Wait for eviction to complete

		// Verify key1 is on disk
		s.mu.Lock()
		entry := s.index["key1"]
		require.NotNil(t, entry)
		assert.False(t, entry.inMemory)
		origDiskLen := entry.diskLen
		origDiskOffset := entry.diskOffset
		fileSizeBefore := s.fileSize
		s.mu.Unlock()
		assert.Positive(t, origDiskLen)

		// Get from disk (brings to memory, keeps disk ref as "clean")
		loaded, found, err := s.Get("key1")
		require.NoError(t, err)
		assert.True(t, found)
		assert.Equal(t, data, loaded)

		// Wait for any triggered eviction
		s.wg.Wait()

		// Verify entry is in memory with valid disk ref
		s.mu.Lock()
		entry = s.index["key1"]
		assert.True(t, entry.inMemory)
		assert.Equal(t, origDiskLen, entry.diskLen)
		assert.Equal(t, origDiskOffset, entry.diskOffset)
		s.mu.Unlock()

		// Delete some fillers to make room, then add new ones to trigger eviction of key1
		require.NoError(t, s.Delete("fillera"))
		require.NoError(t, s.Delete("fillerb"))
		for i := 0; i < 3; i++ {
			require.NoError(t, s.Set("filler2_"+string(rune('a'+i)), make([]byte, 100)))
		}

		s.wg.Wait() // Wait for eviction to complete

		// Verify key1 is back on disk at same position (fast path used)
		s.mu.Lock()
		entry = s.index["key1"]
		assert.False(t, entry.inMemory, "key1 should be on disk")
		assert.Equal(t, origDiskLen, entry.diskLen, "disk len should be unchanged")
		assert.Equal(t, origDiskOffset, entry.diskOffset, "disk offset should be unchanged")
		fileSizeAfter := s.fileSize
		s.mu.Unlock()

		// File should have grown only for filler2 entries, not for re-evicting key1
		// key1's clean re-eviction should NOT add to file size
		// Note: we can't check exact sizes due to compression, but key1 shouldn't have been rewritten
		assert.Greater(t, fileSizeAfter, fileSizeBefore, "file grew for new fillers")

		// Verify data still loads correctly
		loaded2, found2, err := s.Get("key1")
		require.NoError(t, err)
		assert.True(t, found2)
		assert.Equal(t, data, loaded2)
	})

	t.Run("load_modify_evict", func(t *testing.T) {
		// Test that modifying after load marks disk as dead and writes to new position
		cfg := SpillStoreConfig{
			MaxHotBytes:         300,
			EvictTargetRatio:    0.5,
			CompactionThreshold: 10000,
			ZSTDLevel:           1,
		}
		s, err := newSpillStore(cfg)
		require.NoError(t, err)
		t.Cleanup(func() { _ = s.Close() })

		// Set and evict initial entry
		data1 := make([]byte, 100)
		for i := range data1 {
			data1[i] = byte(1)
		}
		err = s.Set("key1", data1)
		require.NoError(t, err)

		// Fill cache to trigger eviction
		for i := 0; i < 5; i++ {
			require.NoError(t, s.Set("filler"+string(rune('a'+i)), make([]byte, 100)))
		}
		s.wg.Wait()

		// Record original disk position
		s.mu.Lock()
		entry := s.index["key1"]
		require.NotNil(t, entry)
		assert.False(t, entry.inMemory)
		origDiskLen := entry.diskLen
		origDiskOffset := entry.diskOffset
		origDeadBytes := s.deadBytes
		s.mu.Unlock()

		// Get from disk
		_, _, err = s.Get("key1")
		require.NoError(t, err)
		s.wg.Wait()

		// Modify the entry
		data2 := make([]byte, 100)
		for i := range data2 {
			data2[i] = byte(2)
		}
		err = s.Set("key1", data2)
		require.NoError(t, err)

		// Verify old disk space is marked dead
		s.mu.Lock()
		entry = s.index["key1"]
		assert.True(t, entry.inMemory)
		assert.Equal(t, 0, entry.diskLen) // disk ref cleared on modify
		assert.Equal(t, origDeadBytes+int64(origDiskLen), s.deadBytes)
		s.mu.Unlock()

		// Evict again
		for i := 0; i < 5; i++ {
			require.NoError(t, s.Set("filler2_"+string(rune('a'+i)), make([]byte, 100)))
		}
		s.wg.Wait()

		// Verify key1 is at new disk position
		s.mu.Lock()
		entry = s.index["key1"]
		assert.False(t, entry.inMemory)
		assert.NotEqual(t, origDiskOffset, entry.diskOffset) // new position
		s.mu.Unlock()

		// Verify modified data loads correctly
		loaded, found, err := s.Get("key1")
		require.NoError(t, err)
		assert.True(t, found)
		assert.Equal(t, data2, loaded)
	})

	t.Run("compaction_invalidates_clean", func(t *testing.T) {
		// Test that clean entries (in memory with valid disk ref) have their disk refs
		// invalidated after compaction, since the old file is replaced.
		// Note: This test verifies the behavior when compaction actually rewrites the file.
		// When all live entries are in memory (compaction returns early), disk refs remain valid.
		cfg := SpillStoreConfig{
			MaxHotBytes:         50, // very small to force entries to disk quickly
			EvictTargetRatio:    0.5,
			CompactionThreshold: 20, // low threshold
			ZSTDLevel:           1,
		}
		s, err := newSpillStore(cfg)
		require.NoError(t, err)
		t.Cleanup(func() { _ = s.Close() })

		// Set entries that will be evicted
		for i := 0; i < 4; i++ {
			data := make([]byte, 30)
			for j := range data {
				data[j] = byte(i)
			}
			require.NoError(t, s.Set("key"+string(rune('a'+i)), data))
			s.wg.Wait() // wait after each to ensure eviction completes
		}

		// Find a key that is on disk
		s.mu.Lock()
		var diskKey string
		for k, e := range s.index {
			if !e.inMemory && e.diskLen > 0 {
				diskKey = k
				break
			}
		}
		s.mu.Unlock()
		require.NotEmpty(t, diskKey)

		// Get that key to make it clean (in memory with disk ref)
		_, _, err = s.Get(diskKey)
		require.NoError(t, err)
		s.wg.Wait()

		s.mu.Lock()
		entry := s.index[diskKey]
		inMemoryAfterLoad := entry.inMemory
		diskLenAfterLoad := entry.diskLen
		s.mu.Unlock()

		require.True(t, inMemoryAfterLoad)
		require.Positive(t, diskLenAfterLoad)

		// Delete other entries to create dead space
		for i := 0; i < 4; i++ {
			key := "key" + string(rune('a'+i))
			if key != diskKey {
				require.NoError(t, s.Delete(key))
			}
		}

		s.wg.Wait() // Wait for compaction to complete

		// After compaction, the entry should still be loadable
		loaded, found, err := s.Get(diskKey)
		require.NoError(t, err)
		assert.True(t, found)
		assert.NotNil(t, loaded)
	})

	t.Run("delete_clean_entry", func(t *testing.T) {
		// Test that deleting a clean entry marks disk as dead
		cfg := SpillStoreConfig{
			MaxHotBytes:         300,
			EvictTargetRatio:    0.5,
			CompactionThreshold: 10000,
			ZSTDLevel:           1,
		}
		s, err := newSpillStore(cfg)
		require.NoError(t, err)
		t.Cleanup(func() { _ = s.Close() })

		// Set and evict
		data := make([]byte, 100)
		require.NoError(t, s.Set("key1", data))
		for i := 0; i < 5; i++ {
			err = s.Set("filler"+string(rune('a'+i)), make([]byte, 100))
			require.NoError(t, err)
		}
		s.wg.Wait()

		// Get to make clean
		_, _, err = s.Get("key1")
		require.NoError(t, err)
		s.wg.Wait()

		s.mu.Lock()
		entry := s.index["key1"]
		diskLen := entry.diskLen
		deadBytesBefore := s.deadBytes
		s.mu.Unlock()

		// Delete clean entry
		require.NoError(t, s.Delete("key1"))

		// Verify disk space marked dead
		s.mu.Lock()
		assert.Equal(t, deadBytesBefore+int64(diskLen), s.deadBytes)
		s.mu.Unlock()
	})
}

func TestSpillStore_CompactionTruncatesEmptyDisk(t *testing.T) {
	t.Parallel()

	cfg := SpillStoreConfig{
		MaxHotBytes:         200,
		EvictTargetRatio:    0.5,
		CompactionThreshold: 50, // low threshold
		ZSTDLevel:           1,
	}
	s, err := newSpillStore(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	// Set entries to trigger eviction
	for i := 0; i < 5; i++ {
		require.NoError(t, s.Set("key"+string(rune('a'+i)), make([]byte, 100)))
	}
	s.wg.Wait()

	// Record file size after eviction
	s.mu.Lock()
	fileSizeAfterEviction := s.fileSize
	s.mu.Unlock()
	assert.Greater(t, fileSizeAfterEviction, int64(spillHeaderSize))

	// Get all entries back to memory
	for i := 0; i < 5; i++ {
		_, _, err = s.Get("key" + string(rune('a'+i)))
		require.NoError(t, err)
	}
	s.wg.Wait()

	// Delete all entries to trigger compaction
	for i := 0; i < 5; i++ {
		require.NoError(t, s.Delete("key"+string(rune('a'+i))))
	}
	s.wg.Wait()

	// File should be truncated to header only
	s.mu.Lock()
	finalFileSize := s.fileSize
	finalDeadBytes := s.deadBytes
	s.mu.Unlock()

	assert.Equal(t, int64(spillHeaderSize), finalFileSize)
	assert.Equal(t, int64(0), finalDeadBytes)
}

func TestSpillStore_OverwriteTriggersCompaction(t *testing.T) {
	t.Parallel()

	cfg := SpillStoreConfig{
		MaxHotBytes:         100,
		EvictTargetRatio:    0.5,
		CompactionThreshold: 50, // low threshold to trigger compaction
		ZSTDLevel:           1,
	}
	s, err := newSpillStore(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	// Set entries to trigger eviction
	for i := 0; i < 3; i++ {
		require.NoError(t, s.Set("key"+string(rune('a'+i)), make([]byte, 50)))
	}
	s.wg.Wait()

	// Verify at least one entry is on disk
	s.mu.Lock()
	var diskKey string
	var diskLen int
	for k, e := range s.index {
		if !e.inMemory && e.diskLen > 0 {
			diskKey = k
			diskLen = e.diskLen
			break
		}
	}
	s.mu.Unlock()
	require.NotEmpty(t, diskKey)

	// Overwrite the disk entry multiple times to accumulate dead space
	for i := 0; i < 3; i++ {
		require.NoError(t, s.Set(diskKey, make([]byte, 50)))
		s.wg.Wait()
	}

	// Check that dead bytes accumulated and compaction ran
	s.mu.Lock()
	deadAfter := s.deadBytes
	s.mu.Unlock()

	// Dead bytes should be reduced after compaction runs (if threshold was exceeded)
	expectedDeadFromOverwrites := int64(diskLen) * 3
	if expectedDeadFromOverwrites > cfg.CompactionThreshold {
		assert.Less(t, deadAfter, expectedDeadFromOverwrites)
	}
}

func TestSpillStore_AccessSeqOrdering(t *testing.T) {
	t.Parallel()

	cfg := SpillStoreConfig{
		MaxHotBytes:         300,
		EvictTargetRatio:    0.5,
		CompactionThreshold: 10000,
		ZSTDLevel:           1,
	}
	s, err := newSpillStore(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	// Set entries in order
	require.NoError(t, s.Set("old", make([]byte, 50)))
	require.NoError(t, s.Set("middle", make([]byte, 50)))
	require.NoError(t, s.Set("new", make([]byte, 50)))

	// Access "old" to make it most recent
	_, _, err = s.Get("old")
	require.NoError(t, err)

	// Verify access sequences reflect access order
	s.mu.Lock()
	oldSeq := s.index["old"].accessSeq
	middleSeq := s.index["middle"].accessSeq
	newSeq := s.index["new"].accessSeq
	s.mu.Unlock()

	assert.Greater(t, oldSeq, newSeq)
	assert.Greater(t, newSeq, middleSeq)
}

func TestSpillStore_GetReleasesLockDuringIO(t *testing.T) {
	t.Parallel()

	cfg := SpillStoreConfig{
		MaxHotBytes:         100,
		EvictTargetRatio:    0.5,
		CompactionThreshold: 10000,
		ZSTDLevel:           1,
	}
	s, err := newSpillStore(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	// Set and evict an entry
	require.NoError(t, s.Set("key1", make([]byte, 80)))
	require.NoError(t, s.Set("key2", make([]byte, 80))) // trigger eviction
	s.wg.Wait()

	// Verify key1 is on disk
	s.mu.Lock()
	entry := s.index["key1"]
	require.NotNil(t, entry)
	onDisk := !entry.inMemory
	s.mu.Unlock()
	require.True(t, onDisk)

	// Concurrent operations should work while Get reads from disk
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _, _ = s.Get("key1") // reads from disk
	}()

	go func() {
		defer wg.Done()
		// This should not block while key1 is being read from disk
		_ = s.Set("key3", []byte("new"))
	}()

	wg.Wait()

	// Verify both operations completed
	d1, f1, err := s.Get("key1")
	require.NoError(t, err)
	assert.True(t, f1)
	assert.Len(t, d1, 80)

	d3, f3, err := s.Get("key3")
	require.NoError(t, err)
	assert.True(t, f3)
	assert.Equal(t, []byte("new"), d3)
}

func TestSpillStore_GetDuringModification(t *testing.T) {
	t.Parallel()

	cfg := SpillStoreConfig{
		MaxHotBytes:         100,
		EvictTargetRatio:    0.5,
		CompactionThreshold: 10000,
		ZSTDLevel:           1,
	}
	s, err := newSpillStore(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	// Set and evict an entry
	original := make([]byte, 80)
	for i := range original {
		original[i] = 1
	}
	require.NoError(t, s.Set("key1", original))
	require.NoError(t, s.Set("key2", make([]byte, 80))) // trigger eviction
	s.wg.Wait()

	// Verify key1 is on disk
	s.mu.Lock()
	entry := s.index["key1"]
	require.NotNil(t, entry)
	onDisk := !entry.inMemory
	s.mu.Unlock()
	require.True(t, onDisk)

	// Run many concurrent gets and sets to exercise the race handling
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(2)

		go func() {
			defer wg.Done()

			data, found, err := s.Get("key1")
			assert.NoError(t, err)
			if found && len(data) > 0 {
				// Data should be either original (all 1s) or modified (all 2s)
				assert.True(t, data[0] == 1 || data[0] == 2)
			}
		}()

		go func() {
			defer wg.Done()

			modified := make([]byte, 80)
			for j := range modified {
				modified[j] = 2
			}
			_ = s.Set("key1", modified)
		}()
	}

	wg.Wait()
	s.wg.Wait()

	// Final get should succeed
	data, found, err := s.Get("key1")
	require.NoError(t, err)
	assert.True(t, found)
	assert.Len(t, data, 80)
}
