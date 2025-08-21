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

func Add_policyHandler(cfg *config.APIConfig) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, ok := request.Params.Arguments.(map[string]any)
		if !ok {
			return mcp.NewToolResultError("Invalid arguments object"), nil
		}
		// Create properly typed request body using the generated schema
		var requestBody models.PolicyBundle
		
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
		url := fmt.Sprintf("%s/policies", cfg.BaseURL)
		req, err := http.NewRequest("POST", url, bytes.NewBuffer(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
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
		var result models.PolicyBundleRecord
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

func CreateAdd_policyTool(cfg *config.APIConfig) models.Tool {
	tool := mcp.NewTool("post_policies",
		mcp.WithDescription("Add a new policy"),
		mcp.WithString("x-anchore-account", mcp.Description("An account name to change the resource scope of the request to that account, if permissions allow (admin only)")),
		mcp.WithString("comment", mcp.Description("Input parameter: Description of the bundle, human readable")),
		mcp.WithString("id", mcp.Required(), mcp.Description("Input parameter: Id of the bundle")),
		mcp.WithArray("mappings", mcp.Required(), mcp.Description("Input parameter: Mapping rules for defining which policy and whitelist(s) to apply to an image based on a match of the image tag or id. Evaluated in order.")),
		mcp.WithArray("policies", mcp.Required(), mcp.Description("Input parameter: Policies which define the go/stop/warn status of an image using rule matches on image properties")),
		mcp.WithArray("whitelists", mcp.Description("Input parameter: Whitelists which define which policy matches to disregard explicitly in the final policy decision")),
		mcp.WithString("name", mcp.Description("Input parameter: Human readable name for the bundle")),
		mcp.WithArray("whitelisted_images", mcp.Description("Input parameter: List of mapping rules that define which images should always be passed (unless also on the blacklist), regardless of policy result.")),
		mcp.WithArray("blacklisted_images", mcp.Description("Input parameter: List of mapping rules that define which images should always result in a STOP/FAIL policy result regardless of policy content or presence in whitelisted_images")),
		mcp.WithString("version", mcp.Required(), mcp.Description("Input parameter: Version id for this bundle format")),
	)

	return models.Tool{
		Definition: tool,
		Handler:    Add_policyHandler(cfg),
	}
}
