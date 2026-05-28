package js

import "github.com/go-appsec/toolbox/sectool/protocol"

// Source labels for the response.
const (
	SourceJavaScript = "javascript"
	SourceHTMLInline = "html-inline"
	SourceHTML       = "html"
)

// Result is the deduplicated extraction plus parse-state metadata.
type Result struct {
	Source          string
	ScriptBlocks    int
	ParseErrors     int
	Endpoints       []protocol.ExtractedEndpoint
	Routes          []protocol.ExtractedRoute
	Secrets         []protocol.ExtractedSecret
	ExternalScripts []string
	SourceMaps      []string
	Warnings        []string
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
	res.ExternalScripts = append(res.ExternalScripts, scripts.External...)
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
		errors     int
		blocksUsed int
	)

	for _, src := range blocks {
		if len(src) == 0 {
			continue
		}

		blocksUsed++
		pr := parseSource(src)
		if pr.err != nil {
			errors++
		}
		ext, literals := extractFromSource(src, pr.ast)
		merged.Endpoints = append(merged.Endpoints, ext.Endpoints...)
		merged.Routes = append(merged.Routes, ext.Routes...)
		merged.SourceMaps = append(merged.SourceMaps, ext.SourceMaps...)
		secrets = append(secrets, extractSecrets(src, literals)...)
	}

	d := dedupeExtracted(merged)

	r := Result{
		ScriptBlocks: blocksUsed,
		ParseErrors:  errors,
		Endpoints:    d.Endpoints,
		Routes:       d.Routes,
		Secrets:      dedupeSecrets(secrets),
		SourceMaps:   d.SourceMaps,
	}
	if errors > 0 {
		r.Warnings = append(r.Warnings, "JS parser reported errors; extraction may be incomplete")
	}
	return r
}
