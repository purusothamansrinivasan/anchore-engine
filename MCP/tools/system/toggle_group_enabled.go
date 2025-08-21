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

func Toggle_group_enabledHandler(cfg *config.APIConfig) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, ok := request.Params.Arguments.(map[string]any)
		if !ok {
			return mcp.NewToolResultError("Invalid arguments object"), nil
		}
		feedVal, ok := args["feed"]
		if !ok {
			return mcp.NewToolResultError("Missing required path parameter: feed"), nil
		}
		feed, ok := feedVal.(string)
		if !ok {
			return mcp.NewToolResultError("Invalid path parameter: feed"), nil
		}
		groupVal, ok := args["group"]
		if !ok {
			return mcp.NewToolResultError("Missing required path parameter: group"), nil
		}
		group, ok := groupVal.(string)
		if !ok {
			return mcp.NewToolResultError("Invalid path parameter: group"), nil
		}
		queryParams := make([]string, 0)
		if val, ok := args["enabled"]; ok {
			queryParams = append(queryParams, fmt.Sprintf("enabled=%v", val))
		}
		queryString := ""
		if len(queryParams) > 0 {
			queryString = "?" + strings.Join(queryParams, "&")
		}
		url := fmt.Sprintf("%s/system/feeds/%s/%s%s", cfg.BaseURL, feed, group, queryString)
		req, err := http.NewRequest("PUT", url, nil)
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
		var result []FeedMetadata
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

func CreateToggle_group_enabledTool(cfg *config.APIConfig) models.Tool {
	tool := mcp.NewTool("put_system_feeds_feed_group",
		mcp.WithDescription("Disable a specific group within a feed to not sync"),
		mcp.WithString("feed", mcp.Required(), mcp.Description("")),
		mcp.WithString("group", mcp.Required(), mcp.Description("")),
		mcp.WithBoolean("enabled", mcp.Required(), mcp.Description("")),
	)

	return models.Tool{
		Definition: tool,
		Handler:    Toggle_group_enabledHandler(cfg),
	}
}
