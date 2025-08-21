package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/anchore-engine-api-server/mcp-server/config"
	"github.com/anchore-engine-api-server/mcp-server/models"
	"github.com/mark3labs/mcp-go/mcp"
)

func Test_webhookHandler(cfg *config.APIConfig) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, ok := request.Params.Arguments.(map[string]any)
		if !ok {
			return mcp.NewToolResultError("Invalid arguments object"), nil
		}
		webhook_typeVal, ok := args["webhook_type"]
		if !ok {
			return mcp.NewToolResultError("Missing required path parameter: webhook_type"), nil
		}
		webhook_type, ok := webhook_typeVal.(string)
		if !ok {
			return mcp.NewToolResultError("Invalid path parameter: webhook_type"), nil
		}
		queryParams := make([]string, 0)
		if val, ok := args["notification_type"]; ok {
			queryParams = append(queryParams, fmt.Sprintf("notification_type=%v", val))
		}
		queryString := ""
		if len(queryParams) > 0 {
			queryString = "?" + strings.Join(queryParams, "&")
		}
		url := fmt.Sprintf("%s/system/webhooks/%s/test%s", cfg.BaseURL, webhook_type, queryString)
		req, err := http.NewRequest("POST", url, nil)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("Failed to create request", err), nil
		}
		// No authentication required for this endpoint
		req.Header.Set("Accept", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("Request failed", err), nil
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("Failed to read response body", err), nil
		}

		if resp.StatusCode >= 400 {
			return mcp.NewToolResultError(fmt.Sprintf("API error: %s", body)), nil
		}
		// Use properly typed response
		var result map[string]interface{}
		if err := json.Unmarshal(body, &result); err != nil {
			// Fallback to raw text if unmarshaling fails
			return mcp.NewToolResultText(string(body)), nil
		}

		prettyJSON, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return mcp.NewToolResultErrorFromErr("Failed to format JSON", err), nil
		}

		return mcp.NewToolResultText(string(prettyJSON)), nil
	}
}

func CreateTest_webhookTool(cfg *config.APIConfig) models.Tool {
	tool := mcp.NewTool("post_system_webhooks_webhook_type_test",
		mcp.WithDescription("Adds the capabilities to test a webhook delivery for the given notification type"),
		mcp.WithString("webhook_type", mcp.Required(), mcp.Description("The Webhook Type that we should test")),
		mcp.WithString("notification_type", mcp.Description("What kind of Notification to send")),
	)

	return models.Tool{
		Definition: tool,
		Handler:    Test_webhookHandler(cfg),
	}
}
