package licenses

import (
	"bytes"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap"
)

func TestRunListsDocuments(t *testing.T) {
	var output bytes.Buffer
	if err := Run(&output, nil, false); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Fields(output.String()), netcap.LicenseNames(); len(got) != len(want) {
		t.Fatalf("listed %d documents, want %d", len(got), len(want))
	} else {
		for index := range want {
			if got[index] != want[index] {
				t.Fatalf("document %d = %q, want %q", index, got[index], want[index])
			}
		}
	}
}

func TestRunPrintsDocument(t *testing.T) {
	var output bytes.Buffer
	if err := Run(&output, []string{"LICENSE"}, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "GNU GENERAL PUBLIC LICENSE") {
		t.Fatal("GPL text is missing")
	}
}

func TestRunPrintsAllDocuments(t *testing.T) {
	var output bytes.Buffer
	if err := Run(&output, nil, true); err != nil {
		t.Fatal(err)
	}
	for _, name := range netcap.LicenseNames() {
		if !strings.Contains(output.String(), "===== "+name+" =====") {
			t.Fatalf("header for %q is missing", name)
		}
	}
}

func TestRunRejectsInvalidArguments(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		all  bool
	}{
		{name: "unknown", args: []string{"missing.txt"}},
		{name: "multiple", args: []string{"LICENSE", "legal/THIRD_PARTY_NOTICES.txt"}},
		{name: "all with name", args: []string{"LICENSE"}, all: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := Run(&bytes.Buffer{}, test.args, test.all); err == nil {
				t.Fatal("Run() succeeded")
			}
		})
	}
}
