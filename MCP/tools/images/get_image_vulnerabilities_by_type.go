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

func Get_image_vulnerabilities_by_typeHandler(cfg *config.APIConfig) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, ok := request.Params.Arguments.(map[string]any)
		if !ok {
			return mcp.NewToolResultError("Invalid arguments object"), nil
		}
		imageDigestVal, ok := args["imageDigest"]
		if !ok {
			return mcp.NewToolResultError("Missing required path parameter: imageDigest"), nil
		}
		imageDigest, ok := imageDigestVal.(string)
		if !ok {
			return mcp.NewToolResultError("Invalid path parameter: imageDigest"), nil
		}
		vtypeVal, ok := args["vtype"]
		if !ok {
			return mcp.NewToolResultError("Missing required path parameter: vtype"), nil
		}
		vtype, ok := vtypeVal.(string)
		if !ok {
			return mcp.NewToolResultError("Invalid path parameter: vtype"), nil
		}
		queryParams := make([]string, 0)
		if val, ok := args["force_refresh"]; ok {
			queryParams = append(queryParams, fmt.Sprintf("force_refresh=%v", val))
		}
		if val, ok := args["vendor_only"]; ok {
			queryParams = append(queryParams, fmt.Sprintf("vendor_only=%v", val))
		}
		queryString := ""
		if len(queryParams) > 0 {
			queryString = "?" + strings.Join(queryParams, "&")
		}
		url := fmt.Sprintf("%s/images/%s/vuln/%s%s", cfg.BaseURL, imageDigest, vtype, queryString)
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
		var result models.VulnerabilityResponse
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

func CreateGet_image_vulnerabilities_by_typeTool(cfg *config.APIConfig) models.Tool {
	tool := mcp.NewTool("get_images_imageDigest_vuln_vtype",
		mcp.WithDescription("Get vulnerabilities by type"),
		mcp.WithString("imageDigest", mcp.Required(), mcp.Description("")),
		mcp.WithString("vtype", mcp.Required(), mcp.Description("")),
		mcp.WithBoolean("force_refresh", mcp.Description("")),
		mcp.WithBoolean("vendor_only", mcp.Description("Filter results to include only vulnerabilities that are not marked as invalid by upstream OS vendor data. When set to true, it will filter out all vulnerabilities where `will_not_fix` is False. If false all vulnerabilities are returned regardless of `will_not_fix`")),
		mcp.WithString("x-anchore-account", mcp.Description("An account name to change the resource scope of the request to that account, if permissions allow (admin only)")),
	)

	return models.Tool{
		Definition: tool,
		Handler:    Get_image_vulnerabilities_by_typeHandler(cfg),
	}
}
