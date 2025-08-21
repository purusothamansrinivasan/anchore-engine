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

func Add_imageHandler(cfg *config.APIConfig) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, ok := request.Params.Arguments.(map[string]any)
		if !ok {
			return mcp.NewToolResultError("Invalid arguments object"), nil
		}
		queryParams := make([]string, 0)
		if val, ok := args["force"]; ok {
			queryParams = append(queryParams, fmt.Sprintf("force=%v", val))
		}
		if val, ok := args["autosubscribe"]; ok {
			queryParams = append(queryParams, fmt.Sprintf("autosubscribe=%v", val))
		}
		queryString := ""
		if len(queryParams) > 0 {
			queryString = "?" + strings.Join(queryParams, "&")
		}
		// Create properly typed request body using the generated schema
		var requestBody models.ImageAnalysisRequest
		
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
		url := fmt.Sprintf("%s/images%s", cfg.BaseURL, queryString)
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
		var result []AnchoreImage
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

func CreateAdd_imageTool(cfg *config.APIConfig) models.Tool {
	tool := mcp.NewTool("post_images",
		mcp.WithDescription("Submit a new image for analysis by the engine"),
		mcp.WithBoolean("force", mcp.Description("Override any existing entry in the system")),
		mcp.WithBoolean("autosubscribe", mcp.Description("Instruct engine to automatically begin watching the added tag for updates from registry")),
		mcp.WithString("x-anchore-account", mcp.Description("An account name to change the resource scope of the request to that account, if permissions allow (admin only)")),
		mcp.WithObject("source", mcp.Description("Input parameter: A set of analysis source types. Only one may be set in any given request.")),
		mcp.WithString("tag", mcp.Description("Input parameter: Full pullable tag reference for image. e.g. docker.io/nginx:latest. Deprecated in favor of the 'source' field")),
		mcp.WithObject("annotations", mcp.Description("Input parameter: Annotations to be associated with the added image in key/value form")),
		mcp.WithString("created_at", mcp.Description("Input parameter: Optional override of the image creation time, only honored when both tag and digest are also supplied  e.g. 2018-10-17T18:14:00Z. Deprecated in favor of the 'source' field")),
		mcp.WithString("digest", mcp.Description("Input parameter: A digest string for an image, maybe a pull string or just a digest. e.g. nginx@sha256:123 or sha256:abc123. If a pull string, it must have same regisry/repo as the tag field. Deprecated in favor of the 'source' field")),
		mcp.WithString("dockerfile", mcp.Description("Input parameter: Base64 encoded content of the dockerfile for the image, if available. Deprecated in favor of the 'source' field.")),
		mcp.WithString("image_type", mcp.Description("Input parameter: Optional. The type of image this is adding, defaults to \"docker\". This can be ommitted until multiple image types are supported.")),
	)

	return models.Tool{
		Definition: tool,
		Handler:    Add_imageHandler(cfg),
	}
}
