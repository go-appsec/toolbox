package hash

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
)

func ComputeHash(input, algorithm, key string) (string, error) {
	fn, err := hashFunc(algorithm)
	if err != nil {
		return "", err
	}

	var h hash.Hash
	if key != "" {
		h = hmac.New(fn, []byte(key))
	} else {
		h = fn()
	}

	h.Write([]byte(input))
	return hex.EncodeToString(h.Sum(nil)), nil
}

func hashFunc(algorithm string) (func() hash.Hash, error) {
	switch algorithm {
	case "md5":
		return md5.New, nil
	case "sha1":
		return sha1.New, nil
	case "sha256":
		return sha256.New, nil
	case "sha512":
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s (valid: md5, sha1, sha256, sha512)", algorithm)
	}
}
