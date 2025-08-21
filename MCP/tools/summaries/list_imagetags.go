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

func List_imagetagsHandler(cfg *config.APIConfig) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, ok := request.Params.Arguments.(map[string]any)
		if !ok {
			return mcp.NewToolResultError("Invalid arguments object"), nil
		}
		queryParams := make([]string, 0)
		if val, ok := args["image_status"]; ok {
			queryParams = append(queryParams, fmt.Sprintf("image_status=%v", val))
		}
		queryString := ""
		if len(queryParams) > 0 {
			queryString = "?" + strings.Join(queryParams, "&")
		}
		url := fmt.Sprintf("%s/summaries/imagetags%s", cfg.BaseURL, queryString)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("Failed to create request", err), nil
		}
		// No authentication required for this endpoint
		req.Header.Set("Accept", "application/json")
		if val, ok := args["x-anchore-account"]; ok {
			req.Header.Set("x-anchore-account", fmt.Sprintf("%v", val))
		}

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
		var result []AnchoreImageTagSummary
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

func CreateList_imagetagsTool(cfg *config.APIConfig) models.Tool {
	tool := mcp.NewTool("get_summaries_imagetags",
		mcp.WithDescription("List all visible image digests and tags"),
		mcp.WithArray("image_status", mcp.Description("Filter images in one or more states such as active, deleting. Defaults to active images only if unspecified")),
		mcp.WithString("x-anchore-account", mcp.Description("An account name to change the resource scope of the request to that account, if permissions allow (admin only)")),
	)

	return models.Tool{
		Definition: tool,
		Handler:    List_imagetagsHandler(cfg),
	}
}
