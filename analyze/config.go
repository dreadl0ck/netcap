package analyze

import (
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
)

// Config structure for analyzer plugins.
type Config struct {
	WorkDir string   `yaml:"workDir"`
	Command string   `yaml:"command"`
	Args    []string `yaml:"args"`

	Epochs int `yaml:"epochs"`

	// TODO: handle
	AuditRecords []string `yaml:"auditRecords"`
}

// ParseConfig parses and returns a config instance.
func ParseConfig(path string) *Config {
	var conf = new(Config)
	contents, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}

	err = yaml.UnmarshalStrict(contents, conf)
	if err != nil {
		log.Fatal(err)
	}

	return conf
}
