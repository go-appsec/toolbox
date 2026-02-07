package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"sync"

	"github.com/go-analyze/bulk"
	"github.com/klauspost/compress/zstd"
)

const (
	spillMagic      = "SPLSTOR\x00"
	spillVersion    = 1
	spillHeaderSize = 12 // magic(8) + version(4)
	spillDataFile   = "spill.bin"
	spillCompactTmp = "spill.compact"
)

var ErrClosed = errors.New("storage closed")

// SpillStoreConfig configures spillStore behavior.
type SpillStoreConfig struct {
	TempDir             string  // optional, auto-created if empty
	FilePrefix          string  // optional prefix for data file name (e.g. "hist" → "hist.spill.bin")
	MaxHotBytes         int64   // max value bytes in hot cache
	EvictTargetRatio    float64 // evict to this ratio, higher values evict less
	CompactionThreshold int64   // rewrite file when dead bytes exceed this
	ZSTDLevel           int     // compression level (1-21)
}

// DefaultSpillStoreConfig returns config with sensible defaults.
func DefaultSpillStoreConfig() SpillStoreConfig {
	return SpillStoreConfig{
		MaxHotBytes:         200 * 1024 * 1024,
		EvictTargetRatio:    0.5,
		CompactionThreshold: 100 * 1024 * 1024,
		ZSTDLevel:           10, // high compression level since mostly done in an async routine
	}
}

// spillIndexEntry tracks a single record's metadata (always in memory).
type spillIndexEntry struct {
	size      int    // uncompressed blob size
	accessSeq uint64 // monotonic access sequence for eviction ordering
	inMemory  bool   // true if in hot cache

	// Disk location (valid when !inMemory or clean entry)
	diskOffset int64 // offset in data file
	diskLen    int   // compressed+encrypted length
}

// spillStore is an in-memory map with disk paging for overflow.
type spillStore struct {
	mu sync.Mutex // protects all state

	// Index (always in memory for all records)
	index map[string]*spillIndexEntry

	// Hot cache (in-memory values)
	hotData   map[string][]byte
	hotBytes  int64
	accessSeq uint64 // monotonic counter for eviction ordering

	// Config
	maxHotBytes      int64
	evictTargetBytes int64
	compactThreshold int64

	// Disk storage
	dataDir    string
	filePrefix string // prefix for data/compact file names
	dataFile   *os.File
	fileSize   int64 // current file size
	deadBytes  int64 // bytes in file that are invalidated
	encKey     []byte
	gcm        cipher.AEAD

	// Compression (EncodeAll/DecodeAll are thread-safe)
	zstdEncoder *zstd.Encoder
	zstdDecoder *zstd.Decoder

	// Coordination
	wg             sync.WaitGroup // tracks background goroutines
	evictRunning   bool
	compactRunning bool
	closed         bool
	ownsDataDir    bool // true if this store created the temp dir
}

// NewSpillStore creates a new spillStore with the given config.
func NewSpillStore(cfg SpillStoreConfig) (Storage, error) {
	// Create temp directory
	tempDir := cfg.TempDir
	var ownsDataDir bool
	if tempDir == "" {
		var err error
		tempDir, err = os.MkdirTemp("", "sectool-spill-*")
		if err != nil {
			return nil, err
		}
		ownsDataDir = true
	} else {
		if err := os.MkdirAll(tempDir, 0700); err != nil {
			return nil, err
		}
	}

	// Generate ephemeral encryption key (unless disabled)
	encKey := make([]byte, 32)
	if _, err := rand.Read(encKey); err != nil {
		_ = os.RemoveAll(tempDir)
		return nil, err
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		_ = os.RemoveAll(tempDir)
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		_ = os.RemoveAll(tempDir)
		return nil, err
	}

	// Create data file
	dataPath := filepath.Join(tempDir, prefixedName(cfg.FilePrefix, spillDataFile))
	dataFile, err := os.OpenFile(dataPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		_ = os.RemoveAll(tempDir)
		return nil, err
	}

	// Write header
	header := make([]byte, spillHeaderSize)
	copy(header[0:8], spillMagic)
	binary.LittleEndian.PutUint32(header[8:12], spillVersion)
	if _, err := dataFile.Write(header); err != nil {
		_ = dataFile.Close()
		_ = os.RemoveAll(tempDir)
		return nil, err
	}

	// Initialize ZSTD encoder/decoder
	zstdEncoder, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(cfg.ZSTDLevel)))
	if err != nil {
		_ = dataFile.Close()
		_ = os.RemoveAll(tempDir)
		return nil, err
	}
	zstdDecoder, err := zstd.NewReader(nil)
	if err != nil {
		_ = zstdEncoder.Close()
		_ = dataFile.Close()
		_ = os.RemoveAll(tempDir)
		return nil, err
	}

	return &spillStore{
		index:            make(map[string]*spillIndexEntry),
		hotData:          make(map[string][]byte),
		maxHotBytes:      cfg.MaxHotBytes,
		evictTargetBytes: int64(float64(cfg.MaxHotBytes) * cfg.EvictTargetRatio),
		compactThreshold: cfg.CompactionThreshold,
		dataDir:          tempDir,
		filePrefix:       cfg.FilePrefix,
		dataFile:         dataFile,
		fileSize:         spillHeaderSize,
		encKey:           encKey,
		gcm:              gcm,
		zstdEncoder:      zstdEncoder,
		zstdDecoder:      zstdDecoder,
		ownsDataDir:      ownsDataDir,
	}, nil
}

func (s *spillStore) Set(key string, blob []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrClosed
	}

	var overwroteDiskCopy bool
	if existing, ok := s.index[key]; ok {
		// Mark old disk space as dead if valid disk copy existed
		if existing.diskLen > 0 {
			s.deadBytes += int64(existing.diskLen)
			overwroteDiskCopy = true
		}
		// Adjust hot bytes if was in memory
		if existing.inMemory {
			s.hotBytes -= int64(existing.size)
		}
	}

	// Store in hot cache with defensive copy
	s.accessSeq++
	s.hotData[key] = slices.Clone(blob)
	s.index[key] = &spillIndexEntry{
		size:      len(blob),
		accessSeq: s.accessSeq,
		inMemory:  true,
	}
	s.hotBytes += int64(len(blob))

	s.maybeStartEviction()
	if overwroteDiskCopy {
		s.maybeStartCompaction()
	}

	return nil
}

func (s *spillStore) Get(key string) ([]byte, bool, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, false, ErrClosed
	}
	entry, ok := s.index[key]
	if !ok {
		s.mu.Unlock()
		return nil, false, nil
	}

	s.accessSeq++
	entry.accessSeq = s.accessSeq

	if entry.inMemory {
		data := s.hotData[key]
		s.mu.Unlock()
		// Return defensive copy
		return slices.Clone(data), true, nil
	}

	// Read data from disk
	diskOffset := entry.diskOffset
	diskLen := entry.diskLen
	seq := entry.accessSeq
	encrypted := make([]byte, diskLen)
	if _, err := s.dataFile.ReadAt(encrypted, diskOffset); err != nil {
		s.mu.Unlock()
		return nil, false, err
	}
	s.mu.Unlock()

	// Decrypt and decompress without holding lock
	data, err := s.decryptAndDecompress(encrypted)
	if err != nil {
		return nil, false, err
	}

	// Relock and verify entry hasn't changed
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, false, ErrClosed
	}

	entry, ok = s.index[key]
	if ok && entry.accessSeq == seq {
		// Bring to memory (keep disk reference - entry is "clean" and can evict without rewrite)
		s.hotData[key] = data
		s.hotBytes += int64(len(data))
		entry.inMemory = true
		s.maybeStartEviction()
	}
	s.mu.Unlock()

	// Return defensive copy
	return slices.Clone(data), true, nil
}

func (s *spillStore) KeySet() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return bulk.MapKeysSlice(s.index)
}

func (s *spillStore) Size() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.index)
}

func (s *spillStore) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrClosed
	}

	delete(s.hotData, key)
	entry, ok := s.index[key]
	if !ok {
		return nil
	}
	delete(s.index, key)
	if entry.inMemory {
		s.hotBytes -= int64(entry.size)
	}
	if entry.diskLen > 0 {
		s.deadBytes += int64(entry.diskLen)
		s.maybeStartCompaction()
	}
	return nil
}

func (s *spillStore) DeleteAll() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrClosed
	}

	s.index = make(map[string]*spillIndexEntry)
	s.hotData = make(map[string][]byte)
	s.hotBytes = 0
	s.deadBytes = 0

	// Truncate data file. Always reset fileSize since the index is already
	// cleared and no entries reference the old file data.
	err := s.dataFile.Truncate(spillHeaderSize)
	s.fileSize = spillHeaderSize
	return err
}

func (s *spillStore) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()

	s.wg.Wait() // Wait for background goroutines to finish before closing resources

	// Clear in-memory state (skip truncate since the file is about to be removed)
	s.index = make(map[string]*spillIndexEntry)
	s.hotData = make(map[string][]byte)
	s.hotBytes = 0
	s.deadBytes = 0
	// Zero encryption key
	for i := range s.encKey {
		s.encKey[i] = 0
	}

	_ = s.zstdEncoder.Close()
	s.zstdDecoder.Close()

	dataPath := s.dataFile.Name()
	_ = s.dataFile.Close()
	if s.ownsDataDir {
		return os.RemoveAll(s.dataDir)
	}
	return os.Remove(dataPath)
}

// maybeStartEviction spawns eviction goroutine if needed and not already running.
// Must be called with s.mu held.
func (s *spillStore) maybeStartEviction() {
	if s.hotBytes >= s.maxHotBytes && !s.evictRunning {
		s.evictRunning = true
		s.wg.Add(1)
		go s.runEviction()
	}
}

// maybeStartCompaction spawns compaction goroutine if needed and not already running.
// Must be called with s.mu held.
func (s *spillStore) maybeStartCompaction() {
	if s.deadBytes > s.compactThreshold && !s.compactRunning {
		s.compactRunning = true
		s.wg.Add(1)
		go s.runCompaction()
	}
}

// runEviction evicts least-recently-used entries to disk until below target.
func (s *spillStore) runEviction() {
	defer s.wg.Done()

	for {
		s.mu.Lock()
		// select eviction entries
		type evictionKey struct {
			key       string
			size      int
			accessSeq uint64
		}
		entries := make([]evictionKey, 0, len(s.hotData))
		for k, e := range s.index {
			if e.inMemory {
				entries = append(entries, evictionKey{k, e.size, e.accessSeq})
			}
		}
		sort.Slice(entries, func(i, j int) bool { // oldest first (lower seq = older)
			return entries[i].accessSeq < entries[j].accessSeq
		})
		// Reduce entries to only what is needed to meet target
		bytesToEvict := s.hotBytes - s.evictTargetBytes
		for i, e := range entries {
			if bytesToEvict <= 0 {
				entries = entries[:i] // found full evict set
				break
			}
			bytesToEvict -= int64(e.size)
		}
		if len(entries) == 0 {
			s.evictRunning = false
			s.mu.Unlock()
			return
		}

		// evict each selected entry (if not accessed during eviction)
		for i, ek := range entries {
			if i != 0 { // first lock is retained from selection before loop start
				runtime.Gosched()
				s.mu.Lock()
			}
			if s.closed {
				s.evictRunning = false
				s.mu.Unlock()
				return
			}
			entry, exists := s.index[ek.key]
			if !exists || !entry.inMemory || entry.accessSeq != ek.accessSeq {
				s.mu.Unlock()
				continue
			}

			// Fast path: clean entry with valid disk copy
			if entry.diskLen > 0 {
				delete(s.hotData, ek.key)
				s.hotBytes -= int64(entry.size)
				entry.inMemory = false
				s.mu.Unlock()
				continue
			}

			// Dirty path: need to compress/encrypt/write
			data := s.hotData[ek.key]
			s.mu.Unlock()

			encrypted := s.compressAndEncrypt(data) // compress and encrypt without lock

			s.mu.Lock()
			if s.closed {
				s.evictRunning = false
				s.mu.Unlock()
				return
			}
			entry, exists = s.index[ek.key]
			if !exists || !entry.inMemory || entry.accessSeq != ek.accessSeq {
				s.mu.Unlock()
				continue
			}

			offset := s.fileSize
			n, err := s.dataFile.WriteAt(encrypted, offset)
			if err != nil {
				log.Printf("spill: eviction write error: %v", err)
				s.mu.Unlock()
				continue
			}

			// Success - atomically transition from memory to disk
			delete(s.hotData, ek.key)
			s.hotBytes -= int64(entry.size)
			entry.inMemory = false
			entry.diskOffset = offset
			entry.diskLen = n
			s.fileSize += int64(n)
			s.mu.Unlock()
		}

		// Loop to check if more eviction needed (new data added or skipped entries)
	}
}

// runCompaction reclaims dead space by rewriting the data file.
// Holds lock for entire operation to prevent races with eviction.
func (s *spillStore) runCompaction() {
	s.mu.Lock()
	defer func() {
		s.compactRunning = false
		s.mu.Unlock()
		s.wg.Done()
	}()

	if s.closed {
		return
	}

	// Collect entries that should remain on disk
	type diskEntry struct {
		key    string
		offset int64
		length int
	}
	entries := make([]diskEntry, 0, len(s.index)-len(s.hotData))
	for k, e := range s.index {
		if !e.inMemory {
			entries = append(entries, diskEntry{k, e.diskOffset, e.diskLen})
		}
	}
	if len(entries) == 0 {
		// No entries on disk - truncate file to header only
		if err := s.dataFile.Truncate(spillHeaderSize); err != nil {
			log.Printf("spill: compaction truncate error: %v", err)
			return
		}
		s.fileSize = spillHeaderSize
		s.deadBytes = 0
		return
	}

	// Create new temp file
	newPath := filepath.Join(s.dataDir, prefixedName(s.filePrefix, spillCompactTmp))
	newFile, err := os.OpenFile(newPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Printf("spill: compaction create error: %v", err)
		return
	}

	// Write header
	header := make([]byte, spillHeaderSize)
	copy(header[0:8], spillMagic)
	binary.LittleEndian.PutUint32(header[8:12], spillVersion)
	if _, err := newFile.Write(header); err != nil {
		log.Printf("spill: compaction header write error: %v", err)
		_ = newFile.Close()
		_ = os.Remove(newPath)
		return
	}

	// Process entries one at a time to limit memory usage
	newOffset := int64(spillHeaderSize)
	for _, entry := range entries {
		// Read one entry
		data := make([]byte, entry.length)
		if _, err := s.dataFile.ReadAt(data, entry.offset); err != nil {
			log.Printf("spill: compaction read error for %s: %v, aborting", entry.key, err)
			_ = newFile.Close()
			_ = os.Remove(newPath)
			return
		}

		// Write to new file
		if _, err := newFile.Write(data); err != nil {
			log.Printf("spill: compaction write error: %v", err)
			_ = newFile.Close()
			_ = os.Remove(newPath)
			return
		}

		// update location in index
		s.index[entry.key].diskOffset = newOffset

		newOffset += int64(entry.length)
	}

	// Swap files
	_ = s.dataFile.Close()
	s.dataFile = newFile
	s.fileSize = newOffset
	s.deadBytes = 0

	// Invalidate disk refs for in-memory entries (old file is gone)
	for _, e := range s.index {
		if e.inMemory && e.diskLen > 0 {
			e.diskOffset = 0
			e.diskLen = 0
		}
	}

	if err := os.Rename(newPath, filepath.Join(s.dataDir, prefixedName(s.filePrefix, spillDataFile))); err != nil {
		log.Printf("spill: compaction rename error: %v", err)
	}
}

// compressAndEncrypt compresses with ZSTD then encrypts with AES-GCM.
// Thread-safe: can be called without holding s.mu.
func (s *spillStore) compressAndEncrypt(data []byte) []byte {
	compressed := s.zstdEncoder.EncodeAll(data, nil)

	// Encrypt with unique nonce
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		panic(err) // rand.Read is documented to never return an error
	}

	// Prepend nonce to ciphertext
	ciphertext := s.gcm.Seal(nil, nonce, compressed, nil)
	result := make([]byte, 12+len(ciphertext))
	copy(result[:12], nonce)
	copy(result[12:], ciphertext)
	return result
}

// decryptAndDecompress decrypts with AES-GCM then decompresses with ZSTD.
// Thread-safe: can be called without holding s.mu.
func (s *spillStore) decryptAndDecompress(data []byte) ([]byte, error) {
	if len(data) < 12 {
		return nil, errors.New("ciphertext too short")
	}

	nonce := data[:12]
	ciphertext := data[12:]
	data, err := s.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return s.zstdDecoder.DecodeAll(data, nil)
}

func prefixedName(prefix, name string) string {
	if prefix == "" {
		return name
	}
	return prefix + "." + name
}
