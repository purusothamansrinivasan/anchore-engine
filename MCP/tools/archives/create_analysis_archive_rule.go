package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"bytes"

	"github.com/anchore-engine-api-server/mcp-server/config"
	"github.com/anchore-engine-api-server/mcp-server/models"
	"github.com/mark3labs/mcp-go/mcp"
)

func Create_analysis_archive_ruleHandler(cfg *config.APIConfig) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, ok := request.Params.Arguments.(map[string]any)
		if !ok {
			return mcp.NewToolResultError("Invalid arguments object"), nil
		}
		// Create properly typed request body using the generated schema
		var requestBody models.AnalysisArchiveTransitionRule
		
		// Optimized: Single marshal/unmarshal with JSON tags handling field mapping
		if argsJSON, err := json.Marshal(args); err == nil {
			if err := json.Unmarshal(argsJSON, &requestBody); err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Failed to convert arguments to request type: %v", err)), nil
			}
		} else {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to marshal arguments: %v", err)), nil
		}
		
		bodyBytes, err := json.Marshal(requestBody)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("Failed to encode request body", err), nil
		}
		url := fmt.Sprintf("%s/archives/rules", cfg.BaseURL)
		req, err := http.NewRequest("POST", url, bytes.NewBuffer(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
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
		var result models.AnalysisArchiveTransitionRule
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

func CreateCreate_analysis_archive_ruleTool(cfg *config.APIConfig) models.Tool {
	tool := mcp.NewTool("post_archives_rules",
		mcp.WithDescription(""),
		mcp.WithBoolean("system_global", mcp.Description("Input parameter: True if the rule applies to all accounts in the system. This is only available to admin users to update/modify, but all users with permission to list rules can see them")),
		mcp.WithNumber("tag_versions_newer", mcp.Description("Input parameter: Number of images mapped to the tag that are newer")),
		mcp.WithObject("exclude", mcp.Description("Input parameter: Which Images to exclude from auto-archiving logic")),
		mcp.WithString("transition", mcp.Required(), mcp.Description("Input parameter: The type of transition to make. If \"archive\", then archive an image from the working set and remove it from the working set. If \"delete\", then match against archived images and delete from the archive if match.")),
		mcp.WithString("last_updated", mcp.Description("")),
		mcp.WithNumber("max_images_per_account", mcp.Description("Input parameter: This is the maximum number of image analyses an account can have. Can only be set on system_global rules")),
		mcp.WithNumber("analysis_age_days", mcp.Description("Input parameter: Matches if the analysis is strictly older than this number of days")),
		mcp.WithString("created_at", mcp.Description("")),
		mcp.WithString("rule_id", mcp.Description("Input parameter: Unique identifier for archive rule")),
		mcp.WithObject("selector", mcp.Description("Input parameter: A set of selection criteria to match an image by a tagged pullstring based on its components, with regex support in each field")),
	)

	return models.Tool{
		Definition: tool,
		Handler:    Create_analysis_archive_ruleHandler(cfg),
	}
}
