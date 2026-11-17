package filter

import "testing"

func TestHeaderPredicates(t *testing.T) {
	headers := map[string]string{"x-example-state": "active", "X-Other": "", "not-x-example": "value"}
	if HeaderValue(headers, "X-EXAMPLE-STATE") != "active" || HeaderValue(nil, "absent") != "" {
		t.Fatal("header lookup changed")
	}
	if !HasHeaderPrefix(headers, "X-Example-") || HasHeaderPrefix(headers, "X-Other") || HasHeaderPrefix(nil, "X-") {
		t.Fatal("header prefix accepted absent or empty evidence")
	}
}
