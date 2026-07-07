package service

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/go-appsec/toolbox/sectool/config"
	"github.com/go-appsec/toolbox/sectool/service/proxy"
	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
)

// BuildCaptureFilter compiles proxy exclusion patterns from config into a CaptureFilter.
func BuildCaptureFilter(cfg config.ProxyConfig) (proxy.CaptureFilter, error) {
	if cfg.ExcludeExtensions == nil || *cfg.ExcludeExtensions == "" {
		return nil, nil
	}

	extRe, err := regexp.Compile("^(?:" + *cfg.ExcludeExtensions + ")$")
	if err != nil {
		return nil, fmt.Errorf("exclude_extensions: %w", err)
	}

	return func(flow *types.Flow) bool {
		ext := strings.ToLower(strings.TrimPrefix(path.Ext(flow.GetPath()), "."))
		return ext == "" || !extRe.MatchString(ext)
	}, nil
}
