/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package util

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	gopacketLayerTypesURL = "https://raw.githubusercontent.com/gopacket/gopacket/master/layers/layertypes.go"
	netcapDecoderDir      = "decoder/packet"
)

// layerInfo contains information about a layer type
type layerInfo struct {
	Name       string
	Value      string
	IsUsed     bool
	NetcapFile string
	Category   string
}

// analyzeGoPacketCoverage analyzes gopacket layer coverage and displays unused layer types
func analyzeGoPacketCoverage() {
	fmt.Println("Analyzing gopacket layer type coverage...")
	fmt.Println()

	// Get the NETCAP root directory
	netcapRoot, err := findNetcapRoot()
	if err != nil {
		log.Fatal("Error finding NETCAP root: ", err)
	}

	// Fetch gopacket layer types
	gopacketLayers, err := fetchGoPacketLayerTypes()
	if err != nil {
		log.Fatal("Error fetching gopacket layer types: ", err)
	}

	// Scan NETCAP decoders
	netcapLayers, err := scanNetcapDecoders(filepath.Join(netcapRoot, netcapDecoderDir))
	if err != nil {
		log.Fatal("Error scanning NETCAP decoders: ", err)
	}

	// Mark used layers and collect statistics
	unusedLayers := buildUnusedLayersList(gopacketLayers, netcapLayers)

	// Display results
	displayUnusedLayers(unusedLayers, len(gopacketLayers))
}

// findNetcapRoot finds the NETCAP project root directory
func findNetcapRoot() (string, error) {
	// Try current directory
	if _, err := os.Stat("go.mod"); err == nil {
		if data, err := os.ReadFile("go.mod"); err == nil {
			if strings.Contains(string(data), "github.com/dreadl0ck/netcap") {
				return ".", nil
			}
		}
	}

	// Try parent directories
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			if data, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil {
				if strings.Contains(string(data), "github.com/dreadl0ck/netcap") {
					return dir, nil
				}
			}
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return "", fmt.Errorf("could not find NETCAP root directory")
}

// fetchGoPacketLayerTypes fetches and parses gopacket layer types from GitHub
func fetchGoPacketLayerTypes() (map[string]*layerInfo, error) {
	resp, err := http.Get(gopacketLayerTypesURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch layertypes.go: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP request failed with status: %d", resp.StatusCode)
	}

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return parseLayerTypes(string(content))
}

// parseLayerTypes parses layer type declarations from the layertypes.go file
func parseLayerTypes(content string) (map[string]*layerInfo, error) {
	layers := make(map[string]*layerInfo)

	// Create a file set for parsing
	fset := token.NewFileSet()

	// Parse the content as a Go file
	f, err := parser.ParseFile(fset, "layertypes.go", content, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Go file: %w", err)
	}

	// Walk through declarations to find LayerType constants
	for _, decl := range f.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.VAR {
			continue
		}

		for _, spec := range genDecl.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}

			for i, name := range valueSpec.Names {
				nameStr := name.Name

				// Only process LayerType* variables
				if !strings.HasPrefix(nameStr, "LayerType") {
					continue
				}

				// Extract the value expression
				var value string
				if i < len(valueSpec.Values) {
					switch v := valueSpec.Values[i].(type) {
					case *ast.CallExpr:
						// RegisterLayerType(...) call
						if len(v.Args) >= 1 {
							if lit, ok := v.Args[0].(*ast.BasicLit); ok {
								value = lit.Value
							}
						}
					case *ast.BasicLit:
						value = v.Value
					}
				}

				layers[nameStr] = &layerInfo{
					Name:   nameStr,
					Value:  value,
					IsUsed: false,
				}
			}
		}
	}

	return layers, nil
}

// scanNetcapDecoders scans NETCAP decoder files to find which layer types are used
func scanNetcapDecoders(decoderDir string) (map[string]string, error) {
	usedLayers := make(map[string]string)

	// Pattern to match layer type usage in decoder files
	layerTypePattern := regexp.MustCompile(`layers\.(LayerType\w+)`)

	err := filepath.Walk(decoderDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Only process .go files
		if info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}

		// Read file content
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", path, err)
		}

		// Find all layer type references
		matches := layerTypePattern.FindAllStringSubmatch(string(content), -1)
		for _, match := range matches {
			if len(match) > 1 {
				layerType := match[1]
				usedLayers[layerType] = filepath.Base(path)
			}
		}

		return nil
	})

	return usedLayers, err
}

// buildUnusedLayersList creates a list of unused layers with categorization
func buildUnusedLayersList(gopacketLayers map[string]*layerInfo, netcapLayers map[string]string) []*layerInfo {
	// Mark used layers
	for layerName, fileName := range netcapLayers {
		if layer, ok := gopacketLayers[layerName]; ok {
			layer.IsUsed = true
			layer.NetcapFile = fileName
		}
	}

	// Collect unused layers
	var unusedList []*layerInfo

	for _, layer := range gopacketLayers {
		// Add category to layer info
		layer.Category = categorizeLayer(layer.Name)

		if !layer.IsUsed {
			unusedList = append(unusedList, layer)
		}
	}

	// Sort by name
	sort.Slice(unusedList, func(i, j int) bool {
		return unusedList[i].Name < unusedList[j].Name
	})

	return unusedList
}

// displayUnusedLayers prints the unused layers in a readable format
func displayUnusedLayers(unusedLayers []*layerInfo, totalLayers int) {
	usedCount := totalLayers - len(unusedLayers)
	coveragePercent := 0.0
	if totalLayers > 0 {
		coveragePercent = float64(usedCount) / float64(totalLayers) * 100
	}

	// Print statistics
	fmt.Println("=== Coverage Statistics ===")
	fmt.Printf("Total gopacket layer types: %d\n", totalLayers)
	fmt.Printf("Layer types used in NETCAP: %d (%.1f%%)\n", usedCount, coveragePercent)
	fmt.Printf("Layer types NOT used in NETCAP: %d (%.1f%%)\n", len(unusedLayers), 100-coveragePercent)
	fmt.Println()

	// Check if all layers are used
	if len(unusedLayers) == 0 {
		fmt.Println("✓ All gopacket layer types are used in NETCAP!")
		return
	}

	// Print unused layers grouped by category
	fmt.Println("=== Unused Layer Types ===")
	categories := groupLayersByCategory(unusedLayers)

	// Define category order for better presentation
	categoryOrder := []string{
		"Security/Encryption",
		"Tunneling/Encapsulation",
		"Network Layer",
		"Wireless",
		"Network Discovery",
		"Monitoring/Mirroring",
		"Authentication",
		"MPLS/VLAN",
		"Internal/Special",
		"Other",
	}

	for _, category := range categoryOrder {
		layers, ok := categories[category]
		if !ok || len(layers) == 0 {
			continue
		}

		fmt.Printf("\n%s (%d):\n", category, len(layers))
		for _, layer := range layers {
			fmt.Printf("  ✗ %s\n", layer.Name)
		}
	}

	// Print high-priority recommendations
	fmt.Println("\n=== High-Priority Recommendations ===")
	fmt.Println("Consider implementing decoders for these commonly used protocols:")

	priority := []string{}
	for _, layer := range unusedLayers {
		name := layer.Name
		// Common protocols that might be high priority
		if strings.Contains(name, "TLS") || strings.Contains(name, "HTTP") ||
			strings.Contains(name, "Radius") || strings.Contains(name, "PPP") ||
			strings.Contains(name, "ERSPAN") || strings.Contains(name, "STP") ||
			strings.Contains(name, "RadioTap") {
			priority = append(priority, name)
		}
	}

	if len(priority) > 0 {
		for _, name := range priority {
			fmt.Printf("  • %s\n", name)
		}
	} else {
		fmt.Println("  No high-priority protocols identified")
	}

	fmt.Println()
}

// categorizeLayer determines the category of a layer based on its name
func categorizeLayer(name string) string {
	// Categorize based on name patterns
	switch {
	case strings.Contains(name, "Payload") || strings.Contains(name, "Decode") ||
		name == "LayerTypeZero" || name == "LayerTypeFragment":
		return "Internal/Special"
	case strings.Contains(name, "TLS") || strings.Contains(name, "SSL"):
		return "Security/Encryption"
	case strings.Contains(name, "Radius") || strings.Contains(name, "EAP"):
		return "Authentication"
	case strings.Contains(name, "PPP") || strings.Contains(name, "GTP"):
		return "Tunneling/Encapsulation"
	case strings.Contains(name, "LLDP") || strings.Contains(name, "CDP") ||
		strings.Contains(name, "STP"):
		return "Network Discovery"
	case strings.Contains(name, "MPLS") || strings.Contains(name, "VLAN"):
		return "MPLS/VLAN"
	case strings.Contains(name, "PrismHeader") || strings.Contains(name, "RadioTap"):
		return "Wireless"
	case strings.Contains(name, "ERSPAN") || strings.Contains(name, "GRE"):
		return "Monitoring/Mirroring"
	case strings.Contains(name, "IPv") || strings.Contains(name, "IP"):
		return "Network Layer"
	default:
		return "Other"
	}
}

// groupLayersByCategory groups layers by their category
func groupLayersByCategory(layers []*layerInfo) map[string][]*layerInfo {
	categories := make(map[string][]*layerInfo)

	for _, layer := range layers {
		categories[layer.Category] = append(categories[layer.Category], layer)
	}

	return categories
}
