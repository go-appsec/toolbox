package proxy

import (
	"context"
	"fmt"
	"time"

	"github.com/go-appsec/llm-security-toolbox/sectool/bundle"
	"github.com/go-appsec/llm-security-toolbox/sectool/mcpclient"
)

func export(mcpURL string, timeout time.Duration, flowID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client, err := mcpclient.Connect(ctx, mcpURL)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	resp, err := client.ProxyGet(ctx, flowID)
	if err != nil {
		return fmt.Errorf("get flow: %w", err)
	}

	reqBody, err := bundle.DecodeBase64Body(resp.ReqBody)
	if err != nil {
		return fmt.Errorf("decode request body: %w", err)
	}

	respBody, err := bundle.DecodeBase64Body(resp.RespBody)
	if err != nil {
		return fmt.Errorf("decode response body: %w", err)
	}

	bundleDir, err := bundle.Write(flowID,
		resp.URL, resp.Method, resp.ReqHeaders, reqBody,
		resp.RespHeaders, respBody)
	if err != nil {
		return fmt.Errorf("write bundle: %w", err)
	}

	fmt.Printf("Exported flow `%s` to `%s/`\n", flowID, bundleDir)
	fmt.Println()
	fmt.Println("Files:")
	fmt.Println("- request.http - HTTP request headers")
	fmt.Println("- body - request body (edit this)")
	fmt.Println("- request.meta.json - metadata")
	if resp.RespHeaders != "" {
		fmt.Println("- response.http - response headers")
		fmt.Println("- response.body - response body")
	}
	fmt.Println()
	fmt.Printf("To replay: `sectool replay send --bundle %s`\n", flowID)

	return nil
}
