package webui

import (
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
)

// The Explore page opens on a view from lib/securityViews.ts. A misspelled
// type or field there falls back silently to an arbitrary field, which is the
// behaviour the list exists to replace, so every entry is checked against the
// record schema here.
func TestSecurityViewsNameRealFields(t *testing.T) {
	src, err := os.ReadFile("frontend/packages/netcap-ui/src/lib/securityViews.ts")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`\{ type: '([^']+)', field: '([^']+)', chartType: '([^']+)'`)
	views := re.FindAllStringSubmatch(string(src), -1)
	if len(views) < 30 {
		t.Fatalf("parsed only %d views; did the entry format change?", len(views))
	}
	numericOnly := map[string]bool{"line": true, "area": true, "scatter": true}
	for _, v := range views {
		typ, field, chart := v[1], v[2], v[3]
		code, ok := types.Type_value["NC_"+typ]
		if !ok {
			t.Errorf("%s: unknown record type", typ)
			continue
		}
		rec := netio.InitRecord(types.Type(code))
		if rec == nil {
			t.Errorf("%s: no record constructor", typ)
			continue
		}
		ft, ok := fieldType(reflect.TypeOf(rec).Elem(), strings.Split(field, "."))
		if !ok {
			t.Errorf("%s.%s: no such field", typ, field)
			continue
		}
		if numericOnly[chart] && !isNumericKind(ft.Kind()) {
			t.Errorf("%s.%s is %s, but %s needs a numeric field", typ, field, ft, chart)
		}
	}
}

// fieldType follows a dotted path the way /api/chart/fields names nested
// fields, descending through pointers, slices and map values.
func fieldType(t reflect.Type, path []string) (reflect.Type, bool) {
	for len(path) > 0 {
		for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice {
			t = t.Elem()
		}
		if t.Kind() == reflect.Map {
			// RequestHeader.User-Agent: the key is data, not schema.
			return t.Elem(), true
		}
		if t.Kind() != reflect.Struct {
			return nil, false
		}
		f, ok := t.FieldByName(path[0])
		if !ok {
			return nil, false
		}
		t, path = f.Type, path[1:]
	}
	return t, true
}

func isNumericKind(k reflect.Kind) bool {
	switch k {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return true
	}
	return false
}
