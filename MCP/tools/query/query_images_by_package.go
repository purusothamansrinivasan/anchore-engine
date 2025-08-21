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

func Query_images_by_packageHandler(cfg *config.APIConfig) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, ok := request.Params.Arguments.(map[string]any)
		if !ok {
			return mcp.NewToolResultError("Invalid arguments object"), nil
		}
		queryParams := make([]string, 0)
		if val, ok := args["name"]; ok {
			queryParams = append(queryParams, fmt.Sprintf("name=%v", val))
		}
		if val, ok := args["package_type"]; ok {
			queryParams = append(queryParams, fmt.Sprintf("package_type=%v", val))
		}
		if val, ok := args["version"]; ok {
			queryParams = append(queryParams, fmt.Sprintf("version=%v", val))
		}
		if val, ok := args["page"]; ok {
			queryParams = append(queryParams, fmt.Sprintf("page=%v", val))
		}
		if val, ok := args["limit"]; ok {
			queryParams = append(queryParams, fmt.Sprintf("limit=%v", val))
		}
		queryString := ""
		if len(queryParams) > 0 {
			queryString = "?" + strings.Join(queryParams, "&")
		}
		url := fmt.Sprintf("%s/query/images/by_package%s", cfg.BaseURL, queryString)
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
		var result models.PaginatedImageList
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

func CreateQuery_images_by_packageTool(cfg *config.APIConfig) models.Tool {
	tool := mcp.NewTool("get_query_images_by_package",
		mcp.WithDescription("List of images containing given package"),
		mcp.WithString("name", mcp.Required(), mcp.Description("Name of package to search for (e.g. sed)")),
		mcp.WithString("package_type", mcp.Description("Type of package to filter on (e.g. dpkg)")),
		mcp.WithString("version", mcp.Description("Version of named package to filter on (e.g. 4.4-1)")),
		mcp.WithString("page", mcp.Description("The page of results to fetch. Pages start at 1")),
		mcp.WithNumber("limit", mcp.Description("Limit the number of records for the requested page. If omitted or set to 0, return all results in a single page")),
		mcp.WithString("x-anchore-account", mcp.Description("An account name to change the resource scope of the request to that account, if permissions allow (admin only)")),
	)

	return models.Tool{
		Definition: tool,
		Handler:    Query_images_by_packageHandler(cfg),
	}
}
