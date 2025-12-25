package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// PostmanCollection represents a Postman collection structure
type PostmanCollection struct {
	Info PostmanInfo   `json:"info"`
	Item []PostmanItem `json:"item"`
}

type PostmanInfo struct {
	Name   string `json:"name"`
	Schema string `json:"schema"`
}

type PostmanItem struct {
	Name    string        `json:"name"`
	Item    []PostmanItem `json:"item,omitempty"`
	Request *Request      `json:"request,omitempty"`
}

type Request struct {
	Method string   `json:"method"`
	Header []Header `json:"header"`
	Body   *Body    `json:"body,omitempty"`
	URL    URL      `json:"url"`
}

type Header struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	Type  string `json:"type"`
}

type Body struct {
	Mode    string       `json:"mode"`
	Raw     string       `json:"raw"`
	Options *BodyOptions `json:"options,omitempty"`
}

type BodyOptions struct {
	Raw RawOptions `json:"raw"`
}

type RawOptions struct {
	Language string `json:"language"`
}

type URL struct {
	Raw      string   `json:"raw"`
	Protocol string   `json:"protocol"`
	Host     []string `json:"host"`
	Port     string   `json:"port"`
	Path     []string `json:"path"`
}

// Endpoint represents a parsed handler endpoint
type Endpoint struct {
	Handler     string
	Method      string
	Path        string
	Description string
	RequestType string
	HasBody     bool
}

// Request body templates based on DTO types
var requestBodies = map[string]string{
	"dto.RegisterRequest": `{
  "email": "user@example.com",
  "password": "securepassword123"
}`,
	"dto.LoginRequest": `{
  "email": "user@example.com",
  "password": "securepassword123",
  "client_id": "your-client-id"
}`,
	"dto.RefreshTokenRequest": `{
  "refresh_token": "your-refresh-token",
  "client_id": "your-client-id",
  "device_id": "your-device-id"
}`,
	"dto.RevokeTokenRequest": `{
  "token": "token-to-revoke",
  "token_type_hint": "refresh_token"
}`,
	"dto.CreateClientRequest": `{
  "name": "My Application",
  "redirect_uris": ["http://localhost:8080/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "scopes": ["openid", "profile", "email"],
  "is_confidential": true
}`,
	"dto.RegisterFCMTokenRequest": `{
  "refresh_token": "your-refresh-token",
  "fcm_token": "your-fcm-token"
}`,
	"dto.TokenRequest":     `grant_type=authorization_code&code=auth-code&redirect_uri=http://localhost:8080/callback&client_id=your-client-id&code_verifier=your-code-verifier`,
	"dto.AuthorizeRequest": ``,
}

func main() {
	handlersPath := flag.String("path", "./internal/interfaces/http/handlers", "Path to handlers directory")
	output := flag.String("output", "postman_collection.json", "Output file path")
	collectionName := flag.String("name", "API Collection", "Collection name")
	baseURL := flag.String("base-url", "http://localhost:8080", "Base URL for the API")
	flag.Parse()

	endpoints, err := parseHandlers(*handlersPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing handlers: %v\n", err)
		os.Exit(1)
	}

	collection := generatePostmanCollection(endpoints, *collectionName, *baseURL)

	jsonData, err := json.MarshalIndent(collection, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating JSON: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*output, jsonData, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Generated Postman collection: %s\n", *output)
	fmt.Printf("Total endpoints: %d\n", len(endpoints))
}

func parseHandlers(dir string) ([]Endpoint, error) {
	var endpoints []Endpoint

	files, err := filepath.Glob(filepath.Join(dir, "*_handler.go"))
	if err != nil {
		return nil, err
	}

	// Route comment pattern: // METHOD /path
	routePattern := regexp.MustCompile(`^//\s*(GET|POST|PUT|DELETE|PATCH)\s+(/\S+)`)

	for _, file := range files {
		fset := token.NewFileSet()
		node, err := parser.ParseFile(fset, file, nil, parser.ParseComments)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to parse %s: %v\n", file, err)
			continue
		}

		handlerName := extractHandlerName(filepath.Base(file))

		ast.Inspect(node, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Doc == nil {
				return true
			}

			// Check if this is a method on a handler type
			if fn.Recv == nil || len(fn.Recv.List) == 0 {
				return true
			}

			var method, path, description, requestType string
			var hasBody bool

			for _, comment := range fn.Doc.List {
				text := comment.Text

				// Check for route definition
				if matches := routePattern.FindStringSubmatch(text); matches != nil {
					method = matches[1]
					path = matches[2]
				} else if strings.HasPrefix(text, "//") && description == "" {
					// First comment line is the description
					desc := strings.TrimPrefix(text, "//")
					desc = strings.TrimSpace(desc)
					if desc != "" && !strings.Contains(desc, "GET ") && !strings.Contains(desc, "POST ") {
						description = desc
					}
				}
			}

			if method != "" && path != "" {
				// Look for request body binding in function body
				requestType, hasBody = findRequestType(fn)

				endpoints = append(endpoints, Endpoint{
					Handler:     handlerName,
					Method:      method,
					Path:        path,
					Description: description,
					RequestType: requestType,
					HasBody:     hasBody,
				})
			}

			return true
		})
	}

	return endpoints, nil
}

func extractHandlerName(filename string) string {
	name := strings.TrimSuffix(filename, "_handler.go")
	name = strings.TrimSuffix(name, ".go")
	// Convert to title case
	parts := strings.Split(name, "_")
	for i, part := range parts {
		if len(part) > 0 {
			parts[i] = strings.ToUpper(part[:1]) + part[1:]
		}
	}
	return strings.Join(parts, " ")
}

func findRequestType(fn *ast.FuncDecl) (string, bool) {
	var requestType string
	hasBody := false

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}

		// Look for ShouldBindJSON or ShouldBind calls
		if sel.Sel.Name == "ShouldBindJSON" || sel.Sel.Name == "ShouldBind" {
			hasBody = true
			// Try to find the type from the variable declaration
			if len(call.Args) > 0 {
				if unary, ok := call.Args[0].(*ast.UnaryExpr); ok {
					if ident, ok := unary.X.(*ast.Ident); ok {
						// Find the variable declaration
						for _, stmt := range fn.Body.List {
							if decl, ok := stmt.(*ast.DeclStmt); ok {
								if genDecl, ok := decl.Decl.(*ast.GenDecl); ok {
									for _, spec := range genDecl.Specs {
										if valueSpec, ok := spec.(*ast.ValueSpec); ok {
											for _, name := range valueSpec.Names {
												if name.Name == ident.Name {
													if sel, ok := valueSpec.Type.(*ast.SelectorExpr); ok {
														requestType = fmt.Sprintf("%s.%s", sel.X, sel.Sel.Name)
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}

		return true
	})

	return requestType, hasBody
}

func generatePostmanCollection(endpoints []Endpoint, name, baseURL string) PostmanCollection {
	collection := PostmanCollection{
		Info: PostmanInfo{
			Name:   name,
			Schema: "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
		},
	}

	// Group endpoints by handler
	groups := make(map[string][]Endpoint)
	for _, ep := range endpoints {
		groups[ep.Handler] = append(groups[ep.Handler], ep)
	}

	for handler, eps := range groups {
		folder := PostmanItem{
			Name: handler,
			Item: make([]PostmanItem, 0, len(eps)),
		}

		for _, ep := range eps {
			item := createRequestItem(ep, baseURL)
			folder.Item = append(folder.Item, item)
		}

		collection.Item = append(collection.Item, folder)
	}

	return collection
}

func createRequestItem(ep Endpoint, baseURL string) PostmanItem {
	// Parse base URL
	protocol := "http"
	host := "localhost"
	port := "8888"

	if strings.HasPrefix(baseURL, "https://") {
		protocol = "https"
		baseURL = strings.TrimPrefix(baseURL, "https://")
	} else if strings.HasPrefix(baseURL, "http://") {
		baseURL = strings.TrimPrefix(baseURL, "http://")
	}

	parts := strings.Split(baseURL, ":")
	host = parts[0]
	if len(parts) > 1 {
		port = parts[1]
	}

	// Parse path
	pathParts := strings.Split(strings.TrimPrefix(ep.Path, "/"), "/")

	name := ep.Description
	if name == "" {
		name = fmt.Sprintf("%s %s", ep.Method, ep.Path)
	}

	request := &Request{
		Method: ep.Method,
		Header: []Header{
			{Key: "Content-Type", Value: "application/json", Type: "text"},
		},
		URL: URL{
			Raw:      fmt.Sprintf("%s://%s:%s%s", protocol, host, port, ep.Path),
			Protocol: protocol,
			Host:     []string{host},
			Port:     port,
			Path:     pathParts,
		},
	}

	// Add Authorization header for authenticated endpoints
	if !isPublicEndpoint(ep.Path) {
		request.Header = append(request.Header, Header{
			Key:   "Authorization",
			Value: "Bearer {{access_token}}",
			Type:  "text",
		})
	}

	// Add request body if applicable
	if ep.HasBody && (ep.Method == "POST" || ep.Method == "PUT" || ep.Method == "PATCH") {
		bodyContent := getRequestBody(ep.RequestType, ep.Path)
		if bodyContent != "" {
			// Check if it's form data (for token endpoint)
			if strings.Contains(bodyContent, "=") && !strings.HasPrefix(bodyContent, "{") {
				request.Header[0].Value = "application/x-www-form-urlencoded"
				request.Body = &Body{
					Mode: "urlencoded",
					Raw:  bodyContent,
				}
			} else {
				request.Body = &Body{
					Mode: "raw",
					Raw:  bodyContent,
					Options: &BodyOptions{
						Raw: RawOptions{Language: "json"},
					},
				}
			}
		}
	}

	return PostmanItem{
		Name:    name,
		Request: request,
	}
}

func isPublicEndpoint(path string) bool {
	publicPaths := []string{
		"/health",
		"/ready",
		"/live",
		"/auth/register",
		"/auth/login",
		"/.well-known/openid-configuration",
		"/jwks.json",
		"/token",
		"/authorize",
		"/fcm/register",
	}

	for _, p := range publicPaths {
		if path == p || strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

func getRequestBody(requestType, path string) string {
	if body, ok := requestBodies[requestType]; ok {
		return body
	}

	// Generate based on path
	switch {
	case strings.Contains(path, "/fcm/register"):
		return requestBodies["dto.RegisterFCMTokenRequest"]
	case strings.Contains(path, "/register"):
		return requestBodies["dto.RegisterRequest"]
	case strings.Contains(path, "/login"):
		return requestBodies["dto.LoginRequest"]
	case path == "/token":
		return requestBodies["dto.TokenRequest"]
	case strings.Contains(path, "/refresh"):
		return requestBodies["dto.RefreshTokenRequest"]
	case strings.Contains(path, "/revoke"):
		return requestBodies["dto.RevokeTokenRequest"]
	case strings.Contains(path, "/client"):
		return requestBodies["dto.CreateClientRequest"]
	default:
		return `{}`
	}
}
