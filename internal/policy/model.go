// Package policy compiles bounded application policies independently of alerts.
package policy

const (
	MaxBundleBytes     = 1 << 20
	MaxRules           = 1024
	MaxExpressionBytes = 4096
	MaxEventBytes      = 2 << 20
	MaxGroups          = 4096
)

type Bundle struct {
	Version  string         `json:"version" yaml:"version"`
	ID       string         `json:"id" yaml:"id"`
	Mode     string         `json:"mode" yaml:"mode"`
	Default  string         `json:"default" yaml:"default"`
	Rules    []Rule         `json:"rules" yaml:"rules"`
	Defaults *PhaseDefaults `json:"defaults,omitempty" yaml:"defaults,omitempty"`
}

// PhaseDefaults overrides Default for either phase; empty fields inherit Default.
type PhaseDefaults struct {
	Request  string `json:"request,omitempty" yaml:"request,omitempty"`
	Response string `json:"response,omitempty" yaml:"response,omitempty"`
}

type Rule struct {
	ID         string     `json:"id" yaml:"id"`
	Phase      string     `json:"phase" yaml:"phase"`
	Expression string     `json:"expression" yaml:"expression"`
	Action     string     `json:"action" yaml:"action"`
	Status     int        `json:"status" yaml:"status"`
	Priority   int        `json:"priority" yaml:"priority"`
	Enabled    *bool      `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	Threshold  *Threshold `json:"threshold,omitempty" yaml:"threshold,omitempty"`
	Sequence   *Sequence  `json:"sequence,omitempty" yaml:"sequence,omitempty"`
}

// Sequence matches 2..16 ordered step expressions within one total fixed window.
// One event advances at most one step. Unrelated events are ignored; a first-step
// match restarts an incomplete sequence if it does not match the expected step.
// Expression, when present, filters all steps. Threshold counts completions.
type Sequence struct {
	Name    string   `json:"name" yaml:"name"`
	Steps   []string `json:"steps" yaml:"steps"`
	Window  string   `json:"window" yaml:"window"`
	GroupBy string   `json:"group_by" yaml:"group_by"`
}

// Threshold counts matching events in a fixed window starting at the first match.
// GroupBy selects an allowed scalar event field; empty means global. State exhaustion
// returns an error rather than evicting a live counter and bypassing enforcement.
type Threshold struct {
	Count   int    `json:"count" yaml:"count"`
	Window  string `json:"window" yaml:"window"`
	GroupBy string `json:"group_by" yaml:"group_by"`
}

// Event is also the typed expression environment; header keys are canonical HTTP names.
// Callers must not mutate Headers during evaluation.
type Event struct {
	Protocol string              `json:"protocol" yaml:"protocol"`
	Modbus   ModbusEvent         `json:"modbus" yaml:"modbus"`
	DNS      DNSEvent            `json:"dns" yaml:"dns"`
	Method   string              `json:"method" yaml:"method"`
	Host     string              `json:"host" yaml:"host"`
	Path     string              `json:"path" yaml:"path"`
	RawQuery string              `json:"raw_query" yaml:"raw_query"`
	ClientIP string              `json:"client_ip" yaml:"client_ip"`
	Body     string              `json:"body" yaml:"body"`
	Headers  map[string][]string `json:"headers" yaml:"headers"`
	Status   int                 `json:"status" yaml:"status"`
	Phase    string              `json:"phase" yaml:"phase"`
}

// ModbusEvent describes validated request ranges, including both sides of FC23.
// Address/Quantity is the write range for writes and the read range otherwise.
type ModbusEvent struct {
	Function       int  `json:"function" yaml:"function"`
	UnitID         int  `json:"unit_id" yaml:"unit_id"`
	Address        int  `json:"address" yaml:"address"`
	Quantity       int  `json:"quantity" yaml:"quantity"`
	EndAddress     int  `json:"end_address" yaml:"end_address"`
	IsWrite        bool `json:"is_write" yaml:"is_write"`
	ReadAddress    int  `json:"read_address" yaml:"read_address"`
	ReadQuantity   int  `json:"read_quantity" yaml:"read_quantity"`
	ReadEndAddress int  `json:"read_end_address" yaml:"read_end_address"`
}

type DNSEvent struct {
	Name string `json:"name" yaml:"name"`
	Type int    `json:"type" yaml:"type"`
}

type Decision struct {
	Verdict  string `json:"verdict"`
	Status   int    `json:"status"`
	RuleID   string `json:"rule_id"`
	Revision string `json:"revision"`
	Monitor  bool   `json:"monitor"`
}

// Explanation contains policy metadata only, never event values or expressions.
type Explanation struct {
	Decision Decision `json:"decision"`
	Reason   string   `json:"reason"`
}
