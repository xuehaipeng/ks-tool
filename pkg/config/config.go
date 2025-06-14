package config

import (
	"fmt"
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

// Host represents a single host configuration
type Host struct {
	IP           string `yaml:"ip"`
	Username     string `yaml:"username"`
	Password     string `yaml:"password"`
	SudoPassword string `yaml:"sudo_password"`
	Port         int    `yaml:"port"`
}

// HostGroup represents a group of hosts
type HostGroup struct {
	Name  string `yaml:"name"`
	Hosts []Host `yaml:"hosts"`
}

// Config represents the entire configuration
type Config struct {
	Groups []HostGroup `yaml:"groups"`
}

// LoadConfig loads configuration from a YAML file
func LoadConfig(filename string) (*Config, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}

	return &config, nil
}

// GetGroup returns a host group by name
func (c *Config) GetGroup(groupName string) (*HostGroup, error) {
	for _, group := range c.Groups {
		if group.Name == groupName {
			return &group, nil
		}
	}
	return nil, fmt.Errorf("group '%s' not found", groupName)
}

// GetGroups returns multiple host groups by names
func (c *Config) GetGroups(groupNames []string) ([]HostGroup, error) {
	var groups []HostGroup
	for _, name := range groupNames {
		group, err := c.GetGroup(name)
		if err != nil {
			return nil, err
		}
		groups = append(groups, *group)
	}
	return groups, nil
}
