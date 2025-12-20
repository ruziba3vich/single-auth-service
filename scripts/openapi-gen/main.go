package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

func main() {
	inputPath := flag.String("input", "api/openapi.yaml", "Path to OpenAPI YAML file")
	outputPath := flag.String("output", "", "Output file path (default: stdout for validation)")
	format := flag.String("format", "json", "Output format: json or yaml")
	validate := flag.Bool("validate", false, "Only validate the spec without generating output")
	bundle := flag.Bool("bundle", true, "Bundle all $ref references into a single file")

	flag.Parse()

	// Get the base directory for resolving relative paths
	baseDir := filepath.Dir(*inputPath)

	// Read and parse input file
	spec, err := loadYAMLFile(*inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading file: %v\n", err)
		os.Exit(1)
	}

	// Bundle all references if enabled
	if *bundle {
		bundled, err := bundleRefs(spec, baseDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error bundling references: %v\n", err)
			os.Exit(1)
		}
		var ok bool
		spec, ok = bundled.(map[string]interface{})
		if !ok {
			fmt.Fprintf(os.Stderr, "Error: bundled spec is not a map\n")
			os.Exit(1)
		}
	}

	// Basic validation
	if err := validateOpenAPISpec(spec); err != nil {
		fmt.Fprintf(os.Stderr, "Validation error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("OpenAPI specification is valid")

	if *validate {
		return
	}

	// Generate output
	var output []byte
	switch *format {
	case "json":
		output, err = json.MarshalIndent(spec, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating JSON: %v\n", err)
			os.Exit(1)
		}
	case "yaml":
		output, err = yaml.Marshal(spec)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating YAML: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "Unknown format: %s\n", *format)
		os.Exit(1)
	}

	// Write output
	if *outputPath == "" {
		fmt.Println(string(output))
	} else {
		dir := filepath.Dir(*outputPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating directory: %v\n", err)
			os.Exit(1)
		}

		if err := os.WriteFile(*outputPath, output, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Generated: %s\n", *outputPath)
	}
}

func loadYAMLFile(path string) (map[string]interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var spec map[string]interface{}
	if err := yaml.Unmarshal(data, &spec); err != nil {
		return nil, err
	}

	return spec, nil
}

// bundleRefs recursively resolves all $ref references and inlines them
func bundleRefs(data interface{}, baseDir string) (interface{}, error) {
	switch v := data.(type) {
	case map[string]interface{}:
		// Check if this is a $ref
		if ref, ok := v["$ref"].(string); ok {
			// Only process file references (not internal references)
			if !strings.HasPrefix(ref, "#") {
				resolved, err := resolveRef(ref, baseDir)
				if err != nil {
					return nil, fmt.Errorf("resolving %s: %w", ref, err)
				}
				return resolved, nil
			}
		}

		// Recursively process all keys
		result := make(map[string]interface{})
		for key, val := range v {
			processed, err := bundleRefs(val, baseDir)
			if err != nil {
				return nil, err
			}
			result[key] = processed
		}
		return result, nil

	case []interface{}:
		result := make([]interface{}, len(v))
		for i, val := range v {
			processed, err := bundleRefs(val, baseDir)
			if err != nil {
				return nil, err
			}
			result[i] = processed
		}
		return result, nil

	default:
		return data, nil
	}
}

// resolveRef resolves a $ref to its actual content
func resolveRef(ref string, baseDir string) (interface{}, error) {
	// Split file path and JSON pointer
	parts := strings.SplitN(ref, "#", 2)
	filePath := parts[0]
	var jsonPointer string
	if len(parts) > 1 {
		jsonPointer = parts[1]
	}

	// Load the referenced file
	fullPath := filepath.Join(baseDir, filePath)
	fileData, err := loadYAMLFile(fullPath)
	if err != nil {
		return nil, fmt.Errorf("loading %s: %w", fullPath, err)
	}

	// Get the base dir of the new file for nested refs
	newBaseDir := filepath.Dir(fullPath)

	// If there's a JSON pointer, navigate to it
	var result interface{} = fileData
	if jsonPointer != "" && jsonPointer != "/" {
		result, err = navigateJSONPointer(fileData, jsonPointer)
		if err != nil {
			return nil, fmt.Errorf("navigating pointer %s: %w", jsonPointer, err)
		}
	}

	// Recursively bundle any nested refs
	return bundleRefs(result, newBaseDir)
}

// navigateJSONPointer navigates a JSON pointer path in the data
func navigateJSONPointer(data interface{}, pointer string) (interface{}, error) {
	// Remove leading slash
	pointer = strings.TrimPrefix(pointer, "/")
	if pointer == "" {
		return data, nil
	}

	parts := strings.Split(pointer, "/")
	current := data

	for _, part := range parts {
		// Unescape JSON pointer special characters
		part = strings.ReplaceAll(part, "~1", "/")
		part = strings.ReplaceAll(part, "~0", "~")

		switch v := current.(type) {
		case map[string]interface{}:
			var ok bool
			current, ok = v[part]
			if !ok {
				return nil, fmt.Errorf("key not found: %s", part)
			}
		default:
			return nil, fmt.Errorf("cannot navigate into %T with key %s", current, part)
		}
	}

	return current, nil
}

func validateOpenAPISpec(spec map[string]interface{}) error {
	// Check OpenAPI version
	openapi, ok := spec["openapi"].(string)
	if !ok {
		return fmt.Errorf("missing or invalid 'openapi' field")
	}
	if openapi[:1] != "3" {
		return fmt.Errorf("only OpenAPI 3.x is supported, found: %s", openapi)
	}

	// Check info section
	info, ok := spec["info"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("missing or invalid 'info' section")
	}
	if _, ok := info["title"].(string); !ok {
		return fmt.Errorf("missing 'info.title'")
	}
	if _, ok := info["version"].(string); !ok {
		return fmt.Errorf("missing 'info.version'")
	}

	// Check paths section
	paths, ok := spec["paths"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("missing or invalid 'paths' section")
	}
	if len(paths) == 0 {
		return fmt.Errorf("'paths' section is empty")
	}

	// Validate each path
	for path, pathItem := range paths {
		pathItemMap, ok := pathItem.(map[string]interface{})
		if !ok {
			return fmt.Errorf("invalid path item for %s", path)
		}

		// Check for valid HTTP methods
		validMethods := map[string]bool{
			"get": true, "post": true, "put": true, "delete": true,
			"patch": true, "options": true, "head": true, "trace": true,
			"parameters": true, "summary": true, "description": true, "servers": true,
		}
		for method := range pathItemMap {
			if !validMethods[method] {
				return fmt.Errorf("invalid method '%s' in path %s", method, path)
			}
		}
	}

	// Check components section if exists
	if components, ok := spec["components"].(map[string]interface{}); ok {
		// Validate schemas if present
		if schemas, ok := components["schemas"].(map[string]interface{}); ok {
			for name, schema := range schemas {
				if _, ok := schema.(map[string]interface{}); !ok {
					return fmt.Errorf("invalid schema definition: %s", name)
				}
			}
		}
	}

	return nil
}
