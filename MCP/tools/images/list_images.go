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

func List_imagesHandler(cfg *config.APIConfig) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, ok := request.Params.Arguments.(map[string]any)
		if !ok {
			return mcp.NewToolResultError("Invalid arguments object"), nil
		}
		queryParams := make([]string, 0)
		if val, ok := args["history"]; ok {
			queryParams = append(queryParams, fmt.Sprintf("history=%v", val))
		}
		if val, ok := args["fulltag"]; ok {
			queryParams = append(queryParams, fmt.Sprintf("fulltag=%v", val))
		}
		if val, ok := args["image_status"]; ok {
			queryParams = append(queryParams, fmt.Sprintf("image_status=%v", val))
		}
		if val, ok := args["analysis_status"]; ok {
			queryParams = append(queryParams, fmt.Sprintf("analysis_status=%v", val))
		}
		queryString := ""
		if len(queryParams) > 0 {
			queryString = "?" + strings.Join(queryParams, "&")
		}
		url := fmt.Sprintf("%s/images%s", cfg.BaseURL, queryString)
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
		var result []AnchoreImage
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

func CreateList_imagesTool(cfg *config.APIConfig) models.Tool {
	tool := mcp.NewTool("get_images",
		mcp.WithDescription("List all visible images"),
		mcp.WithBoolean("history", mcp.Description("Include image history in the response")),
		mcp.WithString("fulltag", mcp.Description("Full docker-pull string to filter results by (e.g. docker.io/library/nginx:latest, or myhost.com:5000/testimages:v1.1.1)")),
		mcp.WithString("image_status", mcp.Description("Filter by image_status value on the record. Default if omitted is 'active'.")),
		mcp.WithString("analysis_status", mcp.Description("Filter by analysis_status value on the record.")),
		mcp.WithString("x-anchore-account", mcp.Description("An account name to change the resource scope of the request to that account, if permissions allow (admin only)")),
	)

	return models.Tool{
		Definition: tool,
		Handler:    List_imagesHandler(cfg),
	}
}
