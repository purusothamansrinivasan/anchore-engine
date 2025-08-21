package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/anchore-engine-api-server/mcp-server/config"
	"github.com/anchore-engine-api-server/mcp-server/models"
	"github.com/mark3labs/mcp-go/mcp"
)

func Delete_serviceHandler(cfg *config.APIConfig) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, ok := request.Params.Arguments.(map[string]any)
		if !ok {
			return mcp.NewToolResultError("Invalid arguments object"), nil
		}
		servicenameVal, ok := args["servicename"]
		if !ok {
			return mcp.NewToolResultError("Missing required path parameter: servicename"), nil
		}
		servicename, ok := servicenameVal.(string)
		if !ok {
			return mcp.NewToolResultError("Invalid path parameter: servicename"), nil
		}
		hostidVal, ok := args["hostid"]
		if !ok {
			return mcp.NewToolResultError("Missing required path parameter: hostid"), nil
		}
		hostid, ok := hostidVal.(string)
		if !ok {
			return mcp.NewToolResultError("Invalid path parameter: hostid"), nil
		}
		url := fmt.Sprintf("%s/system/services/%s/%s", cfg.BaseURL, servicename, hostid)
		req, err := http.NewRequest("DELETE", url, nil)
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

func CreateDelete_serviceTool(cfg *config.APIConfig) models.Tool {
	tool := mcp.NewTool("delete_system_services_servicename_hostid",
		mcp.WithDescription("Delete the service config"),
		mcp.WithString("servicename", mcp.Required(), mcp.Description("")),
		mcp.WithString("hostid", mcp.Required(), mcp.Description("")),
	)

	return models.Tool{
		Definition: tool,
		Handler:    Delete_serviceHandler(cfg),
	}
}
