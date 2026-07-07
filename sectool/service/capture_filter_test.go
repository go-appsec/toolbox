package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/config"
	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
)

func TestBuildCaptureFilter(t *testing.T) {
	t.Parallel()

	strPtr := func(s string) *string { return &s }

	t.Run("no_filters_returns_nil", func(t *testing.T) {
		cfg := config.ProxyConfig{
			ExcludeExtensions: strPtr(""),
		}
		f, err := BuildCaptureFilter(cfg)
		require.NoError(t, err)
		assert.Nil(t, f)
	})

	t.Run("extension_excludes", func(t *testing.T) {
		cfg := config.ProxyConfig{
			ExcludeExtensions: strPtr("css|js"),
		}
		f, err := BuildCaptureFilter(cfg)
		require.NoError(t, err)
		require.NotNil(t, f)

		assert.False(t, f(h1Entry("GET", "/style.css")))
		assert.False(t, f(h1Entry("GET", "/app.js")))
		assert.True(t, f(h1Entry("GET", "/api/data")))
	})

	t.Run("extension_anchored", func(t *testing.T) {
		cfg := config.ProxyConfig{
			ExcludeExtensions: strPtr("css"),
		}
		f, err := BuildCaptureFilter(cfg)
		require.NoError(t, err)
		require.NotNil(t, f)

		// "scss" should NOT be excluded because the pattern is anchored
		assert.True(t, f(h1Entry("GET", "/style.scss")))
		assert.False(t, f(h1Entry("GET", "/style.css")))
	})

	t.Run("no_extension_allowed", func(t *testing.T) {
		cfg := config.ProxyConfig{
			ExcludeExtensions: strPtr("png|gif"),
		}
		f, err := BuildCaptureFilter(cfg)
		require.NoError(t, err)
		require.NotNil(t, f)

		assert.True(t, f(h1Entry("GET", "/api/data")))
		assert.True(t, f(h1Entry("GET", "/")))
	})

	t.Run("h2_entry", func(t *testing.T) {
		cfg := config.ProxyConfig{
			ExcludeExtensions: strPtr("png"),
		}
		f, err := BuildCaptureFilter(cfg)
		require.NoError(t, err)
		require.NotNil(t, f)

		assert.False(t, f(h2Entry("GET", "/logo.png?v=2")))
		assert.True(t, f(h2Entry("GET", "/api/users")))
	})

	t.Run("invalid_regex", func(t *testing.T) {
		cfg := config.ProxyConfig{
			ExcludeExtensions: strPtr("[invalid"),
		}
		_, err := BuildCaptureFilter(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exclude_extensions")
	})

	t.Run("default_config_excludes_static", func(t *testing.T) {
		defaults := config.DefaultConfig()
		f, err := BuildCaptureFilter(defaults.Proxy)
		require.NoError(t, err)
		require.NotNil(t, f)

		assert.False(t, f(h1Entry("GET", "/logo.png")))
		assert.False(t, f(h1Entry("GET", "/logo.jpeg")))
		assert.False(t, f(h1Entry("GET", "/font.ttf")))
		assert.False(t, f(h1Entry("GET", "/favicon.ico")))
		assert.True(t, f(h1Entry("GET", "/api/data")))
		assert.True(t, f(h1Entry("POST", "/login")))
	})
}

// h1Entry creates an HTTP/1.1 Flow for testing.
func h1Entry(method, urlPath string) *types.Flow {
	return &types.Flow{
		ProtocolTag: "http/1.1",
		Request: &types.Message{
			Method: method,
			Path:   urlPath,
		},
	}
}

// h2Entry creates an HTTP/2 Flow with the path folded into the :path pseudo-header.
func h2Entry(method, urlPath string) *types.Flow {
	return &types.Flow{
		ProtocolTag: "http/2",
		Request: &types.Message{
			Headers: types.Headers{
				{Name: ":method", Value: method},
				{Name: ":path", Value: urlPath},
			},
		},
	}
}
