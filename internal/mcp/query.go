/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package mcp

import (
	"net/url"
	"strconv"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

// queryArg describes one optional MCP argument that maps directly to a
// query-string parameter on the backing HTTP endpoint. The MCP argument
// type is mirrored in the JSON schema so the LLM gets sensible hints.
type queryArg struct {
	Name        string
	QueryName   string // defaults to Name when empty
	Description string
	Kind        argKind
	Enum        []string
	Default     string // string repr; converted per Kind
	MaxNumber   float64
}

type argKind int

const (
	argString argKind = iota
	argNumber
	argBoolean
)

func (q queryArg) toolOption() mcplib.ToolOption {
	opts := []mcplib.PropertyOption{mcplib.Description(q.Description)}
	switch q.Kind {
	case argString:
		if len(q.Enum) > 0 {
			opts = append(opts, mcplib.Enum(q.Enum...))
		}
		if q.Default != "" {
			opts = append(opts, mcplib.DefaultString(q.Default))
		}
		return mcplib.WithString(q.Name, opts...)
	case argNumber:
		if q.MaxNumber > 0 {
			opts = append(opts, mcplib.Max(q.MaxNumber))
		}
		if q.Default != "" {
			if f, err := strconv.ParseFloat(q.Default, 64); err == nil {
				opts = append(opts, mcplib.DefaultNumber(f))
			}
		}
		return mcplib.WithNumber(q.Name, opts...)
	case argBoolean:
		if q.Default != "" {
			opts = append(opts, mcplib.DefaultBool(q.Default == "true"))
		}
		return mcplib.WithBoolean(q.Name, opts...)
	}
	return mcplib.WithString(q.Name, opts...)
}

// buildQuery extracts the queryArgs from req and returns a url.Values
// ready to attach to a GET request. Arguments that weren't provided are
// omitted (so backend defaults apply).
func buildQuery(req mcplib.CallToolRequest, args []queryArg) url.Values {
	out := url.Values{}
	for _, a := range args {
		key := a.QueryName
		if key == "" {
			key = a.Name
		}
		switch a.Kind {
		case argString:
			if v := req.GetString(a.Name, ""); v != "" {
				out.Set(key, v)
			}
		case argNumber:
			if v := req.GetInt(a.Name, 0); v != 0 {
				out.Set(key, strconv.Itoa(v))
			}
		case argBoolean:
			if v := req.GetBool(a.Name, false); v {
				out.Set(key, "true")
			}
		}
	}
	return out
}

// Common queryArg presets reused across tools.

func qLimit(maxN float64) queryArg {
	return queryArg{
		Name:        "limit",
		Description: "Maximum number of results to return.",
		Kind:        argNumber,
		MaxNumber:   maxN,
	}
}

func qOffset() queryArg {
	return queryArg{
		Name:        "offset",
		Description: "Pagination offset.",
		Kind:        argNumber,
	}
}

func qSearch() queryArg {
	return queryArg{
		Name:        "search",
		Description: "Substring filter applied server-side.",
		Kind:        argString,
	}
}
