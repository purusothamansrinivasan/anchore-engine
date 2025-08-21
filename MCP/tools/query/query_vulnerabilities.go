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

func Query_vulnerabilitiesHandler(cfg *config.APIConfig) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, ok := request.Params.Arguments.(map[string]any)
		if !ok {
			return mcp.NewToolResultError("Invalid arguments object"), nil
		}
		queryParams := make([]string, 0)
		if val, ok := args["id"]; ok {
			queryParams = append(queryParams, fmt.Sprintf("id=%v", val))
		}
		if val, ok := args["affected_package"]; ok {
			queryParams = append(queryParams, fmt.Sprintf("affected_package=%v", val))
		}
		if val, ok := args["affected_package_version"]; ok {
			queryParams = append(queryParams, fmt.Sprintf("affected_package_version=%v", val))
		}
		if val, ok := args["page"]; ok {
			queryParams = append(queryParams, fmt.Sprintf("page=%v", val))
		}
		if val, ok := args["limit"]; ok {
			queryParams = append(queryParams, fmt.Sprintf("limit=%v", val))
		}
		if val, ok := args["namespace"]; ok {
			queryParams = append(queryParams, fmt.Sprintf("namespace=%v", val))
		}
		queryString := ""
		if len(queryParams) > 0 {
			queryString = "?" + strings.Join(queryParams, "&")
		}
		url := fmt.Sprintf("%s/query/vulnerabilities%s", cfg.BaseURL, queryString)
		req, err := http.NewRequest("GET", url, nil)
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
		var result models.PaginatedVulnerabilityList
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

func CreateQuery_vulnerabilitiesTool(cfg *config.APIConfig) models.Tool {
	tool := mcp.NewTool("get_query_vulnerabilities",
		mcp.WithDescription("Listing information about given vulnerability"),
		mcp.WithArray("id", mcp.Required(), mcp.Description("The ID of the vulnerability (e.g. CVE-1999-0001)")),
		mcp.WithString("affected_package", mcp.Description("Filter results by specified package name (e.g. sed)")),
		mcp.WithString("affected_package_version", mcp.Description("Filter results by specified package version (e.g. 4.4-1)")),
		mcp.WithString("page", mcp.Description("The page of results to fetch. Pages start at 1")),
		mcp.WithNumber("limit", mcp.Description("Limit the number of records for the requested page. If omitted or set to 0, return all results in a single page")),
		mcp.WithArray("namespace", mcp.Description("Namespace(s) to filter vulnerability records by")),
	)

	return models.Tool{
		Definition: tool,
		Handler:    Query_vulnerabilitiesHandler(cfg),
	}
}
