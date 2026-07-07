package types

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRawHTTP1Request_SerializeRaw(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		req  *RawHTTP1Request
		want string
	}{
		{
			name: "query_and_body",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/x",
				Query:   "a=1",
				Version: "HTTP/1.1",
				Headers: Headers{{Name: "Host", Value: "h"}},
				Body:    []byte("hi"),
			},
			want: "GET /x?a=1 HTTP/1.1\r\nHost: h\r\n\r\nhi",
		},
		{
			name: "no_query",
			req: &RawHTTP1Request{
				Method:  "POST",
				Path:    "/p",
				Version: "HTTP/1.1",
				Headers: Headers{{Name: "Host", Value: "h"}},
			},
			want: "POST /p HTTP/1.1\r\nHost: h\r\n\r\n",
		},
		{
			name: "raw_line_verbatim",
			req: &RawHTTP1Request{
				Method:            "GET",
				Path:              "/",
				Version:           "HTTP/1.1",
				Headers:           Headers{{Name: "X", Value: "y", RawLine: []byte("X:   y  "), LineEnding: EndingBareLF}},
				RequestLineEnding: EndingBareLF,
				HeaderBlockEnding: EndingCRLF,
			},
			want: "GET / HTTP/1.1\nX:   y  \n\r\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			assert.Equal(t, tt.want, string(tt.req.SerializeRaw(&buf)))
		})
	}
}

func TestRawHTTP1Response_SerializeRaw(t *testing.T) {
	t.Parallel()

	t.Run("status_text", func(t *testing.T) {
		r := &RawHTTP1Response{
			Version:    "HTTP/1.1",
			StatusCode: 404,
			StatusText: "Not Found",
			Headers:    Headers{{Name: "Content-Length", Value: "3"}},
			Body:       []byte("abc"),
		}
		var buf bytes.Buffer
		assert.Equal(t, "HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\n\r\nabc", string(r.SerializeRaw(&buf)))
	})

	t.Run("no_status_text", func(t *testing.T) {
		r := &RawHTTP1Response{Version: "HTTP/1.1", StatusCode: 204}
		var buf bytes.Buffer
		assert.Equal(t, "HTTP/1.1 204\r\n\r\n", string(r.SerializeRaw(&buf)))
	})

	t.Run("chunked_reuses_frames", func(t *testing.T) {
		r := &RawHTTP1Response{
			Version:    "HTTP/1.1",
			StatusCode: 200,
			StatusText: "OK",
			Headers:    Headers{{Name: "Transfer-Encoding", Value: "chunked"}},
			Body:       []byte("Wiki"),
			Chunks: []ChunkFrame{
				{SizeLine: []byte("4"), SizeEnding: EndingCRLF, Size: 4, DataEnding: EndingCRLF},
				{SizeLine: []byte("0"), SizeEnding: EndingCRLF, Size: 0, DataEnding: EndingCRLF},
			},
			Wire: &WireFormat{WasChunked: true},
		}
		var buf bytes.Buffer
		assert.Equal(t, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n0\r\n\r\n", string(r.SerializeRaw(&buf)))
	})

	t.Run("chunked_reencodes_without_frames", func(t *testing.T) {
		r := &RawHTTP1Response{
			Version:    "HTTP/1.1",
			StatusCode: 200,
			StatusText: "OK",
			Headers:    Headers{{Name: "Transfer-Encoding", Value: "chunked"}},
			Body:       []byte("0123456789ABCDEF"), // 16 bytes -> hex "10"
			Wire:       &WireFormat{WasChunked: true},
		}
		var buf bytes.Buffer
		assert.Equal(t, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10\r\n0123456789ABCDEF\r\n0\r\n\r\n", string(r.SerializeRaw(&buf)))
	})
}

func TestRawHTTP1Response_SerializeHeaders(t *testing.T) {
	t.Parallel()

	// Transfer-Encoding: chunked and the original Content-Length are dropped
	// A fresh Content-Length is derived from the body length
	r := &RawHTTP1Response{
		Version:    "HTTP/1.1",
		StatusCode: 200,
		StatusText: "OK",
		Headers: Headers{
			{Name: "Transfer-Encoding", Value: "chunked"},
			{Name: "Content-Length", Value: "99"},
			{Name: "X-Test", Value: "1"},
		},
		Body: []byte("hello"),
	}
	var buf bytes.Buffer
	assert.Equal(t, "HTTP/1.1 200 OK\r\nX-Test: 1\r\nContent-Length: 5\r\n\r\n", string(r.SerializeHeaders(&buf)))
}

func TestEncodeStandardChunkedBody(t *testing.T) {
	t.Parallel()

	t.Run("no_trailers", func(t *testing.T) {
		var buf bytes.Buffer
		EncodeStandardChunkedBody(&buf, []byte("hello"), nil)
		assert.Equal(t, "5\r\nhello\r\n0\r\n\r\n", buf.String())
	})

	t.Run("with_trailers", func(t *testing.T) {
		var buf bytes.Buffer
		EncodeStandardChunkedBody(&buf, []byte("hello"), []byte("X-T: 1\r\n"))
		assert.Equal(t, "5\r\nhello\r\n0\r\nX-T: 1\r\n\r\n", buf.String())
	})

	t.Run("empty_body", func(t *testing.T) {
		var buf bytes.Buffer
		EncodeStandardChunkedBody(&buf, nil, nil)
		assert.Equal(t, "0\r\n\r\n", buf.String())
	})
}
