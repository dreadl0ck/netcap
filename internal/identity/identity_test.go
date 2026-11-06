package identity

import (
	"github.com/dreadl0ck/netcap/types"
	"testing"
)

func TestDirectoryNamesJoinAccountsNotLDAPServer(t *testing.T) {
	e := New()
	e.Observe("vlan1", &types.Kerberos{Timestamp: 10, MessageTypeCode: 10, SrcIP: "10.0.0.2", DstIP: "10.0.0.1", ClientName: "analyst", Realm: "EXAMPLE.TEST"})
	e.Observe("vlan1", &types.LDAP{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Operation: "SearchResultEntry", DN: "CN=Analyst,DC=example,DC=test", Attributes: []*types.LDAPAttribute{{Name: "sAMAccountName", Values: [][]byte{[]byte("analyst")}}, {Name: "givenName", Values: [][]byte{[]byte("Test")}}, {Name: "sn", Values: [][]byte{[]byte("Analyst")}}}})
	r := e.Report()
	if len(r.Hosts) != 1 || r.Hosts[0].IP != "10.0.0.2" || len(r.Hosts[0].Accounts) != 1 || r.Hosts[0].Accounts[0].FullName != "Test Analyst" {
		t.Fatal(r)
	}
	e.Observe("vlan2", &types.Kerberos{Timestamp: 10, MessageTypeCode: 10, SrcIP: "10.0.0.2", ClientName: "analyst", Realm: "EXAMPLE.TEST"})
	for _, h := range e.Report().Hosts {
		if h.Scope == "vlan2" && h.Accounts[0].FullName != "" {
			t.Fatal("cross-scope identity join")
		}
	}
}
func TestStrayMACDoesNotReplaceDominantOrAuthoritativeBinding(t *testing.T) {
	e := New()
	for range 100 {
		e.Bind("scope", "10.0.0.2", "real", "observed-link-source")
	}
	e.Bind("scope", "10.0.0.2", "stray", "observed-link-source")
	h := e.Report().Hosts[0]
	if h.MAC != "real" || h.MACState != "dominant-link-source" || len(h.Bindings) != 2 {
		t.Fatal(h)
	}
	e.Bind("scope", "10.0.0.2", "leased", "DHCP ACK")
	h = e.Report().Hosts[0]
	if h.MAC != "leased" || h.MACState != "binding-observed" {
		t.Fatal(h)
	}
}
func TestMachineAccountAndRealmHaveDifferentSemantics(t *testing.T) {
	e := New()
	e.Observe("scope", &types.Kerberos{SrcIP: "10.0.0.2", MessageTypeCode: 10, ClientName: "DESKTOP-LAB$", Realm: "WORKGROUP.TEST"})
	h := e.Report().Hosts[0]
	if h.Hostname != "DESKTOP-LAB" || len(h.Accounts) != 0 {
		t.Fatal(h)
	}
}

func TestUnframedNTLMTokenDoesNotBecomeHostIdentity(t *testing.T) {
	e := New()
	e.Observe("scope", &types.Secret{Service: "NTLMSSP Token", Flow: "192.0.2.1:1234->192.0.2.2:445", User: "UntrustedFileContent", Workstation: "ForgedHost"})
	if len(e.Report().Hosts) != 0 {
		t.Fatal("arbitrary payload token attributed to a host")
	}
}

func TestDirectorySubjectWithoutAccountIsRetainedUnattributed(t *testing.T) {
	e := New()
	e.Observe("scope", &types.LDAP{Timestamp: 42, Flow: "ldap-flow", SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Operation: "SearchResultEntry", DN: "CN=Analyst,DC=example,DC=test", Attributes: []*types.LDAPAttribute{{Name: "displayName", Values: [][]byte{[]byte("Test Analyst")}}}})
	r := e.Report()
	if len(r.Hosts) != 0 || len(r.Directory) != 1 || r.Directory[0].Account != "" || r.Directory[0].FullName != "Test Analyst" || r.Directory[0].Evidence.At != 42 {
		t.Fatal(r)
	}
}

func TestSAMRUnknownDomainMatchIsLimitedToObservedClient(t *testing.T) {
	e := New()
	for _, ip := range []string{"10.0.0.2", "10.0.0.3"} {
		for _, realm := range []string{"EXAMPLE", "EXAMPLE.TEST"} {
			e.Observe("scope", &types.Kerberos{SrcIP: ip, ClientName: "analyst", Realm: realm, MessageTypeCode: 10})
		}
	}
	e.Observe("scope", &types.DCERPC{Timestamp: 42, PacketType: 2, SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Identities: []*types.WindowsIdentity{{AccountName: "analyst", FullName: "Test Analyst"}}})
	for _, h := range e.Report().Hosts {
		for _, a := range h.Accounts {
			if h.IP == "10.0.0.2" {
				if a.FullName != "Test Analyst" || a.FullNameState != "account-name-match-domain-unconfirmed" {
					t.Fatal(h)
				}
			} else if a.FullName != "" {
				t.Fatal("SAMR subject leaked across clients", h)
			}
		}
	}
}
