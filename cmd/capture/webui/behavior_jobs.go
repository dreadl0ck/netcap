package webui

import (
	"path/filepath"
	"strconv"

	"github.com/dreadl0ck/netcap/internal/behavior"
)

func (s *Server) behaviorOptionsForJob(job *AnalysisJob) (BehaviorOptions, error) {
	s.mu.RLock()
	var options BehaviorOptions
	if s.runtimeConfig != nil && s.runtimeConfig.Behavior != nil {
		options = *s.runtimeConfig.Behavior
		options.Prefixes = append([]string(nil), options.Prefixes...)
		if options.Policy != nil {
			policy := *options.Policy
			policy.ApprovedSources = append([]string(nil), options.Policy.ApprovedSources...)
			policy.DeniedCountries = append([]string(nil), options.Policy.DeniedCountries...)
			policy.DeniedASNs = append([]string(nil), options.Policy.DeniedASNs...)
			options.Policy = &policy
		}
	}
	s.mu.RUnlock()
	if options.Enabled && options.Baseline != "" {
		if err := behavior.SeedTemplate(options.Baseline, filepath.Join(job.OutputDir, "Behavior.json")); err != nil {
			return options, err
		}
	}
	// Sessions own their baseline; a configured path is an immutable seed.
	options.Baseline = ""
	return options, nil
}

func behaviorJobArgs(options BehaviorOptions) []string {
	if !options.Enabled {
		return nil
	}
	args := []string{"-behavior", "-behavior-sensor", options.Sensor, "-behavior-learning", options.Learning.String(),
		"-behavior-min-samples", strconv.FormatUint(options.MinSamples, 10), "-behavior-max-facts", strconv.Itoa(options.MaxFacts)}
	for _, prefix := range options.Prefixes {
		args = append(args, "-behavior-prefix", prefix)
	}
	if options.Policy != nil {
		args = append(args, "-behavior-window", strconv.FormatInt(options.Policy.WindowNS, 10)+"ns", "-behavior-fanout", strconv.Itoa(options.Policy.Fanout), "-behavior-rdp-attempts", strconv.Itoa(options.Policy.RDPAttempts))
		for _, source := range options.Policy.ApprovedSources {
			args = append(args, "-behavior-approved-source", source)
		}
		for _, country := range options.Policy.DeniedCountries {
			args = append(args, "-behavior-deny-country", country)
		}
		for _, asn := range options.Policy.DeniedASNs {
			args = append(args, "-behavior-deny-asn", asn)
		}
	}
	return args
}
