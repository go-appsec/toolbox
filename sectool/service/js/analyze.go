package js

import (
	"github.com/go-appsec/toolbox/sectool/protocol"
	"github.com/go-appsec/toolbox/sectool/service/dedupe"
)

// Source labels for the response.
const (
	SourceJavaScript = "javascript"
	SourceHTMLInline = "html-inline"
	SourceHTML       = "html"
)

// Result is the deduplicated extraction plus parse-state metadata.
type Result struct {
	Source       string
	ScriptBlocks int
	ParseErrors  int
	Endpoints    []protocol.ExtractedEndpoint
	Routes       []protocol.ExtractedRoute
	Secrets      []protocol.ExtractedSecret
	ScriptSrc    []string
	SourceMaps   []string
	Warnings     []string
}

// AnalyzeJS analyzes a JavaScript bundle body.
func AnalyzeJS(src []byte) Result {
	res := analyzeBlocks([][]byte{src})
	res.Source = SourceJavaScript
	return res
}

// AnalyzeHTML extracts inline <script> blocks and external <script src=...> URLs from src.
func AnalyzeHTML(src []byte) Result {
	scripts := ParseHTMLScripts(src)
	res := analyzeBlocks(scripts.Inline)
	res.ScriptSrc = dedupe.Slice(append(res.ScriptSrc, scripts.External...))
	if len(scripts.Inline) > 0 {
		res.Source = SourceHTMLInline
	} else {
		res.Source = SourceHTML
	}
	return res
}

func analyzeBlocks(blocks [][]byte) Result {
	var (
		merged     Extracted
		secrets    []protocol.ExtractedSecret
		parseErrs  int
		blocksUsed int
	)

	for _, src := range blocks {
		if len(src) == 0 {
			continue
		}

		blocksUsed++
		pr := parseSource(src)
		if pr.err != nil {
			// tdewolff fails on most real minified bundles; this is expected and
			// not surfaced to the agent. The raw-byte URL scan in extractFromSource
			// is the primary extractor; the AST only enriches when it succeeds.
			parseErrs++
		}
		ext, literals := extractFromSource(src, pr.ast)
		merged.Endpoints = append(merged.Endpoints, ext.Endpoints...)
		merged.Routes = append(merged.Routes, ext.Routes...)
		merged.SourceMaps = append(merged.SourceMaps, ext.SourceMaps...)
		secrets = append(secrets, extractSecrets(src, literals)...)
	}

	d := dedupeExtracted(merged)

	return Result{
		ScriptBlocks: blocksUsed,
		ParseErrors:  parseErrs,
		Endpoints:    d.Endpoints,
		Routes:       d.Routes,
		Secrets:      dedupeSecrets(secrets),
		SourceMaps:   d.SourceMaps,
	}
}
