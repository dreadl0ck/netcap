package waf

import (
	"errors"
	"regexp"
	"time"
)

type CRSProfile struct {
	ParanoiaLevel     int            `json:"paranoiaLevel" yaml:"paranoiaLevel"`
	InboundThreshold  int            `json:"inboundThreshold" yaml:"inboundThreshold"`
	OutboundThreshold int            `json:"outboundThreshold" yaml:"outboundThreshold"`
	Exclusions        []CRSExclusion `json:"exclusions,omitempty" yaml:"exclusions,omitempty"`
}

// Exclusions affect one CRS detector on this binding only, never native policies or parsers.
type CRSExclusion struct {
	RuleID    int       `json:"ruleID" yaml:"ruleID"`
	Parameter string    `json:"parameter,omitempty" yaml:"parameter,omitempty"`
	Owner     string    `json:"owner" yaml:"owner"`
	Reason    string    `json:"reason" yaml:"reason"`
	ExpiresAt time.Time `json:"expiresAt" yaml:"expiresAt"`
}

var parameterToken = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

func validateProfile(c Config) error {
	p := c.CRSProfile
	if p == nil {
		return nil
	}
	if !c.CorazaCRS {
		return errors.New("crsProfile requires corazaCRS")
	}
	if p.ParanoiaLevel < 1 || p.ParanoiaLevel > 4 || p.InboundThreshold < 1 || p.InboundThreshold > 100 || p.OutboundThreshold < 1 || p.OutboundThreshold > 100 || len(p.Exclusions) > 64 {
		return errors.New("invalid CRS profile bounds")
	}
	for _, e := range p.Exclusions {
		// Only attack detectors, never initialization, protocol or blocking evaluation rules.
		if e.RuleID < 930000 || e.RuleID >= 945000 || e.Owner == "" || len(e.Owner) > 128 || e.Reason == "" || len(e.Reason) > 512 || e.ExpiresAt.IsZero() || e.ExpiresAt.After(time.Now().Add(90*24*time.Hour)) || (e.Parameter != "" && !parameterToken.MatchString(e.Parameter)) {
			return errors.New("invalid bounded CRS detector exclusion")
		}
	}
	return nil
}
