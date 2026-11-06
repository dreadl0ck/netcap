package dbs

import (
	"strings"
	"testing"
)

func TestCommunityTrustIsBundledAndDoesNotAuthorizePublication(t *testing.T) {
	trust, err := loadClientTrust("", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(trust.Reviews) != 4 || trust.SHA256 != communityRegistrySHA256 {
		t.Fatal("unexpected bundled community registry")
	}
	if _, err := loadApprovalTrust("", ""); err == nil {
		t.Fatal("publisher accepted implicit community trust")
	}
	for _, pair := range [][2]string{{"", communityRegistrySHA256}, {"missing", ""}} {
		if _, err := loadClientTrust(pair[0], pair[1]); err == nil {
			t.Fatal("partial operator configuration silently fell back to community trust")
		}
	}
	if _, err := parseApprovalTrust([]byte(communityRegistry+" "), communityRegistrySHA256); err == nil {
		t.Fatal("changed registry accepted")
	}
}

func TestCommunityTrustRejectsSelfAuthorizedRelease(t *testing.T) {
	_, _, manifest := reviewedFixture(t)
	trust, err := loadClientTrust("", "")
	if err != nil {
		t.Fatal(err)
	}
	manifest.ApprovalRegistrySHA256 = trust.SHA256
	if err := trust.authorize(manifest); err == nil || !strings.Contains(err.Error(), "not present") {
		t.Fatalf("foreign reviews accepted with a forged registry identity: %v", err)
	}
}
