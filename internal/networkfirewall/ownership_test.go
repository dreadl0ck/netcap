package networkfirewall

import "testing"

func TestPersistentOwnershipCannotFailOpen(t *testing.T) {
	evaluate := evaluatorFunc(func(PacketEvent) (Decision, error) { return Decision{Deny}, nil })
	for _, mutate := range []func(*Config){
		func(c *Config) { c.FailureVerdict = Allow },
		func(c *Config) { c.BypassWithoutListener = true },
		func(c *Config) { c.FailOpenOnOverflow = true },
		func(c *Config) { c.OwnershipNonce = "invalid" },
		func(c *Config) { c.OwnershipNonce = ""; c.RecoverOwned = true },
	} {
		c := testConfig()
		c.OwnershipNonce = "b6f81728b38f4b93b0ca9de8c191db72"
		mutate(&c)
		if _, err := New(c, evaluate); err == nil {
			t.Fatal("unsafe persistent ownership configuration accepted")
		}
	}
	c := testConfig()
	c.OwnershipNonce = "b6f81728b38f4b93b0ca9de8c191db72"
	c.RecoverOwned = true
	if _, err := New(c, evaluate); err != nil {
		t.Fatal(err)
	}
}
