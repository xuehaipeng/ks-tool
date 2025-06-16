package config

import (
	"fmt"
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

// Host represents a single host configuration
type Host struct {
	IP           string `yaml:"ip"`
	Username     string `yaml:"username,omitempty"`
	Password     string `yaml:"password,omitempty"`
	SudoPassword string `yaml:"sudo_password,omitempty"`
	Port         int    `yaml:"port,omitempty"`
}

// HostGroup represents a group of hosts with optional group-level credentials
type HostGroup struct {
	Name         string `yaml:"name"`
	Hosts        []Host `yaml:"hosts"`
	Username     string `yaml:"username,omitempty"`      // Group-level username
	Password     string `yaml:"password,omitempty"`      // Group-level password
	SudoPassword string `yaml:"sudo_password,omitempty"` // Group-level sudo password
	Port         int    `yaml:"port,omitempty"`          // Group-level port
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

	// Process groups to inherit credentials
	for i := range config.Groups {
		config.Groups[i].processHosts()
	}

	return &config, nil
}

// processHosts processes hosts in a group to inherit group-level credentials
func (g *HostGroup) processHosts() {
	for i := range g.Hosts {
		host := &g.Hosts[i]

		// Inherit username from group if not set on host
		if host.Username == "" && g.Username != "" {
			host.Username = g.Username
		}

		// Inherit password from group if not set on host
		if host.Password == "" && g.Password != "" {
			host.Password = g.Password
		}

		// Inherit sudo password from group if not set on host
		if host.SudoPassword == "" && g.SudoPassword != "" {
			host.SudoPassword = g.SudoPassword
		}

		// Inherit port from group if not set on host
		if host.Port == 0 && g.Port != 0 {
			host.Port = g.Port
		}
	}
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
