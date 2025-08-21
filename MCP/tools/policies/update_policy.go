package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"bytes"

	"github.com/anchore-engine-api-server/mcp-server/config"
	"github.com/anchore-engine-api-server/mcp-server/models"
	"github.com/mark3labs/mcp-go/mcp"
)

func Update_policyHandler(cfg *config.APIConfig) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, ok := request.Params.Arguments.(map[string]any)
		if !ok {
			return mcp.NewToolResultError("Invalid arguments object"), nil
		}
		policyIdVal, ok := args["policyId"]
		if !ok {
			return mcp.NewToolResultError("Missing required path parameter: policyId"), nil
		}
		policyId, ok := policyIdVal.(string)
		if !ok {
			return mcp.NewToolResultError("Invalid path parameter: policyId"), nil
		}
		queryParams := make([]string, 0)
		if val, ok := args["active"]; ok {
			queryParams = append(queryParams, fmt.Sprintf("active=%v", val))
		}
		queryString := ""
		if len(queryParams) > 0 {
			queryString = "?" + strings.Join(queryParams, "&")
		}
		// Create properly typed request body using the generated schema
		var requestBody models.PolicyBundleRecord
		
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
		url := fmt.Sprintf("%s/policies/%s%s", cfg.BaseURL, policyId, queryString)
		req, err := http.NewRequest("PUT", url, bytes.NewBuffer(bodyBytes))
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
		var result []PolicyBundleRecord
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

func CreateUpdate_policyTool(cfg *config.APIConfig) models.Tool {
	tool := mcp.NewTool("put_policies_policyId",
		mcp.WithDescription("Update policy"),
		mcp.WithString("policyId", mcp.Required(), mcp.Description("")),
		mcp.WithBoolean("active", mcp.Description("Mark policy as active")),
		mcp.WithString("x-anchore-account", mcp.Description("An account name to change the resource scope of the request to that account, if permissions allow (admin only)")),
		mcp.WithString("policyId", mcp.Description("Input parameter: The bundle's identifier")),
		mcp.WithString("policy_source", mcp.Description("Input parameter: Source location of where the policy bundle originated")),
		mcp.WithObject("policybundle", mcp.Description("Input parameter: A bundle containing a set of policies, whitelists, and rules for mapping them to specific images")),
		mcp.WithString("userId", mcp.Description("Input parameter: UserId of the user that owns the bundle")),
		mcp.WithBoolean("active", mcp.Description("Input parameter: True if the bundle is currently defined to be used automatically")),
		mcp.WithString("created_at", mcp.Description("")),
		mcp.WithString("last_updated", mcp.Description("")),
	)

	return models.Tool{
		Definition: tool,
		Handler:    Update_policyHandler(cfg),
	}
}
