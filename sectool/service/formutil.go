package service

import (
	"bytes"
	"fmt"
	"net/url"
	"sort"

	"github.com/go-analyze/bulk"
)

// modifyFormBodyMap applies set/remove edits to an application/x-www-form-urlencoded
// body and returns the re-encoded result. Output is key-sorted for stable diffing.
func modifyFormBodyMap(body []byte, setForm map[string]string, removeForm []string) ([]byte, error) {
	if len(setForm) == 0 && len(removeForm) == 0 {
		return body, nil
	}

	values, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, fmt.Errorf("body is not valid form-encoded: %w", err)
	}

	for _, key := range removeForm {
		values.Del(key)
	}
	for key, val := range setForm {
		values.Set(key, val)
	}

	keys := bulk.MapKeysSlice(values)
	sort.Strings(keys)

	var bb bytes.Buffer
	for _, k := range keys {
		ek := url.QueryEscape(k)
		for _, v := range values[k] {
			if bb.Len() > 0 {
				bb.WriteByte('&')
			}
			bb.WriteString(ek)
			bb.WriteByte('=')
			bb.WriteString(url.QueryEscape(v))
		}
	}
	return bb.Bytes(), nil
}
