package sidecar

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/go-analyze/bulk"

	"github.com/go-appsec/toolbox/pkg/mutate"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

// InvokeAdapter routes an outbound message through another registered adapter's
// injection_target and returns the flows it produced. Scope policy and the
// destination adapter's own validation apply.
func (c *Conn) InvokeAdapter(ctx context.Context, p wire.InvokeAdapterParams) (wire.InvokeAdapterResult, error) {
	var res wire.InvokeAdapterResult
	if rpcErr := c.peer.Call(ctx, wire.MethodInvokeAdapter, p, &res); rpcErr != nil {
		return wire.InvokeAdapterResult{}, rpcErr
	}
	return res, nil
}

// ApplyMutations applies the ordered mutation ops to msg in place. Ops run in
// slice order so later edits observe earlier ones. An unknown op or a body edit
// against an incompatible body errors.
func ApplyMutations(msg *wire.FlowMessage, muts []wire.Mutation) error {
	for _, m := range muts {
		switch m.Op {
		case "set_header":
			if i := slices.IndexFunc(msg.Headers, func(h wire.Header) bool {
				return strings.EqualFold(h.Name, m.Name)
			}); i >= 0 {
				msg.Headers[i].Value = m.Value
			} else {
				msg.Headers = append(msg.Headers, wire.Header{Name: m.Name, Value: m.Value})
			}
		case "remove_header":
			name := m.Name
			msg.Headers = bulk.SliceFilterInPlace(func(h wire.Header) bool { return !strings.EqualFold(h.Name, name) }, msg.Headers)
		case "set_json":
			b, err := mutate.JSON(msg.Body, map[string]interface{}{m.Name: m.Value}, nil)
			if err != nil {
				return fmt.Errorf("set_json %q: %w", m.Name, err)
			}
			msg.Body = b
		case "remove_json":
			b, err := mutate.JSON(msg.Body, nil, []string{m.Name})
			if err != nil {
				return fmt.Errorf("remove_json %q: %w", m.Name, err)
			}
			msg.Body = b
		case "set_form":
			b, err := mutate.Form(msg.Body, map[string]string{m.Name: m.Value}, nil)
			if err != nil {
				return fmt.Errorf("set_form %q: %w", m.Name, err)
			}
			msg.Body = b
		case "remove_form":
			b, err := mutate.Form(msg.Body, nil, []string{m.Name})
			if err != nil {
				return fmt.Errorf("remove_form %q: %w", m.Name, err)
			}
			msg.Body = b
		case "set_query":
			vals, _ := url.ParseQuery(msg.Query)
			vals.Set(m.Name, m.Value)
			msg.Query = vals.Encode()
		case "remove_query":
			vals, _ := url.ParseQuery(msg.Query)
			vals.Del(m.Name)
			msg.Query = vals.Encode()
		case "query":
			msg.Query = m.Value
		case "method":
			msg.Method = m.Value
		case "path":
			msg.Path = m.Value
		case "body":
			msg.Body = []byte(m.Value)
		default:
			return fmt.Errorf("unknown mutation op %q", m.Op)
		}
	}
	return nil
}
