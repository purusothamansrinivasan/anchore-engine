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

func Update_registryHandler(cfg *config.APIConfig) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, ok := request.Params.Arguments.(map[string]any)
		if !ok {
			return mcp.NewToolResultError("Invalid arguments object"), nil
		}
		registryVal, ok := args["registry"]
		if !ok {
			return mcp.NewToolResultError("Missing required path parameter: registry"), nil
		}
		registry, ok := registryVal.(string)
		if !ok {
			return mcp.NewToolResultError("Invalid path parameter: registry"), nil
		}
		queryParams := make([]string, 0)
		if val, ok := args["validate"]; ok {
			queryParams = append(queryParams, fmt.Sprintf("validate=%v", val))
		}
		queryString := ""
		if len(queryParams) > 0 {
			queryString = "?" + strings.Join(queryParams, "&")
		}
		// Create properly typed request body using the generated schema
		var requestBody models.RegistryConfigurationRequest
		
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
		url := fmt.Sprintf("%s/registries/%s%s", cfg.BaseURL, registry, queryString)
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
		var result []RegistryConfiguration
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

func CreateUpdate_registryTool(cfg *config.APIConfig) models.Tool {
	tool := mcp.NewTool("put_registries_registry",
		mcp.WithDescription("Update/replace a registry configuration"),
		mcp.WithString("registry", mcp.Required(), mcp.Description("")),
		mcp.WithBoolean("validate", mcp.Description("flag to determine whether or not to validate registry/credential at registry update time")),
		mcp.WithString("x-anchore-account", mcp.Description("An account name to change the resource scope of the request to that account, if permissions allow (admin only)")),
		mcp.WithBoolean("registry_verify", mcp.Description("Input parameter: Use TLS/SSL verification for the registry URL")),
		mcp.WithString("registry", mcp.Description("Input parameter: hostname:port string for accessing the registry, as would be used in a docker pull operation. May include some or all of a repository and wildcards (e.g. docker.io/library/* or gcr.io/myproject/myrepository)")),
		mcp.WithString("registry_name", mcp.Description("Input parameter: human readable name associated with registry record")),
		mcp.WithString("registry_pass", mcp.Description("Input parameter: Password portion of credential to use for this registry")),
		mcp.WithString("registry_type", mcp.Description("Input parameter: Type of registry")),
		mcp.WithString("registry_user", mcp.Description("Input parameter: Username portion of credential to use for this registry")),
	)

	return models.Tool{
		Definition: tool,
		Handler:    Update_registryHandler(cfg),
	}
}
