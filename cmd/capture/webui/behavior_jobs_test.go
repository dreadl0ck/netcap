package webui

import (
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/behavior"
	behaviorcommand "github.com/dreadl0ck/netcap/internal/behavior/command"
	"github.com/dreadl0ck/netcap/internal/rules"
)

func TestBehaviorJobsOwnTheirTemplateCopies(t *testing.T) {
	fixture := behaviorServerFixture(t)
	template := filepath.Join(fixture.outDir, "Behavior.json")
	options := BehaviorOptions{Enabled: true, Baseline: template, Sensor: "office", Prefixes: []string{"192.0.2.0/24"}, Learning: time.Second, MinSamples: 2, MaxFacts: 10}
	s := &Server{runtimeConfig: &RuntimeConfig{Behavior: &options}}
	job := &AnalysisJob{OutputDir: t.TempDir()}
	copy, err := s.behaviorOptionsForJob(job)
	if err != nil {
		t.Fatal(err)
	}
	if copy.Baseline != "" || !copy.Enabled {
		t.Fatalf("job options = %+v", copy)
	}
	sink, err := rules.NewFileAlertWriter(job.OutputDir)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	engine, err := behavior.Open(behavior.Config{Path: filepath.Join(job.OutputDir, "Behavior.json"), MaxFacts: 10}, sink)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Change("approve", nil, "session-specific approval"); err != nil {
		t.Fatal(err)
	}
	if err := engine.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.behaviorOptionsForJob(job); err != nil {
		t.Fatal(err)
	}
	owned, err := behavior.ReadSnapshot(filepath.Join(job.OutputDir, "Behavior.json"))
	if err != nil || owned.Mode != behavior.Monitoring {
		t.Fatal("template overwrote session decision")
	}
	original, err := behavior.ReadSnapshot(template)
	if err != nil || original.Mode != behavior.Learning {
		t.Fatal("session changed template")
	}
	copy.Prefixes[0] = "changed"
	if options.Prefixes[0] != "192.0.2.0/24" {
		t.Fatal("job options alias runtime configuration")
	}
	expected := []string{"-behavior", "-behavior-sensor", "office", "-behavior-learning", "1s", "-behavior-min-samples", "2", "-behavior-max-facts", "10", "-behavior-prefix", "192.0.2.0/24"}
	if !reflect.DeepEqual(behaviorJobArgs(options), expected) {
		t.Fatalf("args = %v", behaviorJobArgs(options))
	}
	if len(behaviorJobArgs(behaviorcommand.Options{})) != 0 {
		t.Fatal("disabled behavior enabled in helper")
	}
}
