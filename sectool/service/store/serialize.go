package store

import (
	"github.com/vmihailenco/msgpack/v5"
)

// Serialize encodes a value to msgpack bytes.
func Serialize(v any) ([]byte, error) {
	return msgpack.Marshal(v)
}

// Deserialize decodes msgpack bytes into the provided value.
func Deserialize(data []byte, v any) error {
	return msgpack.Unmarshal(data, v)
}
