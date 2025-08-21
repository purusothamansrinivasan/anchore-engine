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

func Get_image_policy_check_by_imageidHandler(cfg *config.APIConfig) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, ok := request.Params.Arguments.(map[string]any)
		if !ok {
			return mcp.NewToolResultError("Invalid arguments object"), nil
		}
		imageIdVal, ok := args["imageId"]
		if !ok {
			return mcp.NewToolResultError("Missing required path parameter: imageId"), nil
		}
		imageId, ok := imageIdVal.(string)
		if !ok {
			return mcp.NewToolResultError("Invalid path parameter: imageId"), nil
		}
		queryParams := make([]string, 0)
		if val, ok := args["policyId"]; ok {
			queryParams = append(queryParams, fmt.Sprintf("policyId=%v", val))
		}
		if val, ok := args["tag"]; ok {
			queryParams = append(queryParams, fmt.Sprintf("tag=%v", val))
		}
		if val, ok := args["detail"]; ok {
			queryParams = append(queryParams, fmt.Sprintf("detail=%v", val))
		}
		if val, ok := args["history"]; ok {
			queryParams = append(queryParams, fmt.Sprintf("history=%v", val))
		}
		queryString := ""
		if len(queryParams) > 0 {
			queryString = "?" + strings.Join(queryParams, "&")
		}
		url := fmt.Sprintf("%s/images/by_id/%s/check%s", cfg.BaseURL, imageId, queryString)
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
		var result []PolicyEvaluation
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

func CreateGet_image_policy_check_by_imageidTool(cfg *config.APIConfig) models.Tool {
	tool := mcp.NewTool("get_images_by_id_imageId_check",
		mcp.WithDescription("Check policy evaluation status for image"),
		mcp.WithString("imageId", mcp.Required(), mcp.Description("")),
		mcp.WithString("policyId", mcp.Description("")),
		mcp.WithString("tag", mcp.Required(), mcp.Description("")),
		mcp.WithBoolean("detail", mcp.Description("")),
		mcp.WithBoolean("history", mcp.Description("")),
		mcp.WithString("x-anchore-account", mcp.Description("An account name to change the resource scope of the request to that account, if permissions allow (admin only)")),
	)

	return models.Tool{
		Definition: tool,
		Handler:    Get_image_policy_check_by_imageidHandler(cfg),
	}
}
