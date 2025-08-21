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

func List_eventsHandler(cfg *config.APIConfig) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, ok := request.Params.Arguments.(map[string]any)
		if !ok {
			return mcp.NewToolResultError("Invalid arguments object"), nil
		}
		queryParams := make([]string, 0)
		if val, ok := args["source_servicename"]; ok {
			queryParams = append(queryParams, fmt.Sprintf("source_servicename=%v", val))
		}
		if val, ok := args["source_hostid"]; ok {
			queryParams = append(queryParams, fmt.Sprintf("source_hostid=%v", val))
		}
		if val, ok := args["event_type"]; ok {
			queryParams = append(queryParams, fmt.Sprintf("event_type=%v", val))
		}
		if val, ok := args["resource_type"]; ok {
			queryParams = append(queryParams, fmt.Sprintf("resource_type=%v", val))
		}
		if val, ok := args["resource_id"]; ok {
			queryParams = append(queryParams, fmt.Sprintf("resource_id=%v", val))
		}
		if val, ok := args["level"]; ok {
			queryParams = append(queryParams, fmt.Sprintf("level=%v", val))
		}
		if val, ok := args["since"]; ok {
			queryParams = append(queryParams, fmt.Sprintf("since=%v", val))
		}
		if val, ok := args["before"]; ok {
			queryParams = append(queryParams, fmt.Sprintf("before=%v", val))
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
		url := fmt.Sprintf("%s/events%s", cfg.BaseURL, queryString)
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
		var result models.EventsList
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

func CreateList_eventsTool(cfg *config.APIConfig) models.Tool {
	tool := mcp.NewTool("get_events",
		mcp.WithDescription("List Events"),
		mcp.WithString("source_servicename", mcp.Description("Filter events by the originating service")),
		mcp.WithString("source_hostid", mcp.Description("Filter events by the originating host ID")),
		mcp.WithString("event_type", mcp.Description("Filter events by a prefix match on the event type (e.g. \"user.image.\")")),
		mcp.WithString("resource_type", mcp.Description("Filter events by the type of resource - tag, imageDigest, repository etc")),
		mcp.WithString("resource_id", mcp.Description("Filter events by the id of the resource")),
		mcp.WithString("level", mcp.Description("Filter events by the level - INFO or ERROR")),
		mcp.WithString("since", mcp.Description("Return events that occurred after the timestamp")),
		mcp.WithString("before", mcp.Description("Return events that occurred before the timestamp")),
		mcp.WithNumber("page", mcp.Description("Pagination controls - return the nth page of results. Defaults to first page if left empty")),
		mcp.WithNumber("limit", mcp.Description("Number of events in the result set. Defaults to 100 if left empty")),
		mcp.WithString("x-anchore-account", mcp.Description("An account name to change the resource scope of the request to that account, if permissions allow (admin only)")),
	)

	return models.Tool{
		Definition: tool,
		Handler:    List_eventsHandler(cfg),
	}
}
