package ansible

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"regexp"
	"strconv"
	"strings"

	"github.com/xuehaipeng/ks-tool/pkg/config"
	"gopkg.in/yaml.v2"
)

// InventoryParser parses Ansible inventory files
type InventoryParser struct {
	groups     map[string][]string          // group name -> list of host entries
	hostVars   map[string]map[string]string // host ip -> variables
	globalVars map[string]string            // global variables from [all:vars]
	groupVars  map[string]map[string]string // group name -> variables
}

// NewInventoryParser creates a new inventory parser
func NewInventoryParser() *InventoryParser {
	return &InventoryParser{
		groups:     make(map[string][]string),
		hostVars:   make(map[string]map[string]string),
		globalVars: make(map[string]string),
		groupVars:  make(map[string]map[string]string),
	}
}

// ParseInventory parses an Ansible inventory file from an io.Reader
func (p *InventoryParser) ParseInventory(reader io.Reader) error {
	scanner := bufio.NewScanner(reader)
	var currentGroup string
	var currentGroupVars string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check for group header
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			groupName := strings.Trim(line, "[]")

			// Check if it's a group vars section
			if strings.HasSuffix(groupName, ":vars") {
				currentGroupVars = strings.TrimSuffix(groupName, ":vars")
				currentGroup = ""
				if p.groupVars[currentGroupVars] == nil {
					p.groupVars[currentGroupVars] = make(map[string]string)
				}
			} else {
				currentGroup = groupName
				currentGroupVars = ""
				if p.groups[currentGroup] == nil {
					p.groups[currentGroup] = make([]string, 0)
				}
			}
			continue
		}

		// Parse group variables
		if currentGroupVars != "" {
			if strings.Contains(line, "=") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					key := strings.TrimSpace(parts[0])
					value := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
					if currentGroupVars == "all" {
						p.globalVars[key] = value
					} else {
						p.groupVars[currentGroupVars][key] = value
					}
				}
			}
			continue
		}

		// Parse host entries
		if currentGroup != "" {
			p.groups[currentGroup] = append(p.groups[currentGroup], line)

			// Parse host variables
			ip, vars := p.parseHostLine(line)
			if ip != "" && len(vars) > 0 {
				if p.hostVars[ip] == nil {
					p.hostVars[ip] = make(map[string]string)
				}
				for k, v := range vars {
					p.hostVars[ip][k] = v
				}
			}
		}
	}

	return scanner.Err()
}

// parseHostLine extracts IP and variables from a host line
func (p *InventoryParser) parseHostLine(line string) (string, map[string]string) {
	// Regular expression to match IP address at the beginning
	ipRegex := regexp.MustCompile(`^(\d+\.\d+\.\d+\.\d+)`)
	matches := ipRegex.FindStringSubmatch(line)
	if len(matches) == 0 {
		return "", nil
	}

	ip := matches[1]
	vars := make(map[string]string)

	// Extract variables from the rest of the line
	remaining := strings.TrimSpace(line[len(ip):])
	if remaining != "" {
		// Parse key=value pairs
		parts := strings.Fields(remaining)
		for _, part := range parts {
			if strings.Contains(part, "=") {
				kv := strings.SplitN(part, "=", 2)
				if len(kv) == 2 {
					key := strings.TrimSpace(kv[0])
					value := strings.Trim(strings.TrimSpace(kv[1]), `"'`)
					vars[key] = value
				}
			}
		}
	}

	return ip, vars
}

// ConvertToHostsConfig converts the parsed inventory to the tool's hosts.yaml format
func (p *InventoryParser) ConvertToHostsConfig() *config.Config {
	hostConfig := &config.Config{
		Groups: make([]config.HostGroup, 0),
	}

	// Get global SSH settings
	globalUser := p.getGlobalVar("ansible_ssh_user", "ansible_user", "root")
	globalPassword := p.getGlobalVar("ansible_ssh_pass", "ansible_password", "")
	globalPort := p.getGlobalIntVar("ansible_port", "ansible_ssh_port", "22")
	globalSudoPassword := p.getGlobalVar("ansible_sudo_pass", "ansible_become_pass", "")

	// Process each group
	for groupName, hostEntries := range p.groups {
		// Skip empty groups or groups that don't contain actual hosts
		if len(hostEntries) == 0 || p.isSpecialGroup(groupName) {
			continue
		}

		group := config.HostGroup{
			Name:  groupName,
			Hosts: make([]config.Host, 0),
		}

		// Set group-level defaults
		group.Username = globalUser
		group.Password = globalPassword
		group.Port = globalPort
		group.SudoPassword = globalSudoPassword

		// Process each host in the group
		for _, hostEntry := range hostEntries {
			ip, _ := p.parseHostLine(hostEntry)
			if ip == "" {
				continue
			}

			host := config.Host{
				IP: ip,
			}

			// Get host-specific variables
			hostVars := p.hostVars[ip]
			if hostVars != nil {
				if user, exists := hostVars["ansible_ssh_user"]; exists {
					host.Username = user
				} else if user, exists := hostVars["ansible_user"]; exists {
					host.Username = user
				}

				if password, exists := hostVars["ansible_ssh_pass"]; exists {
					host.Password = password
				} else if password, exists := hostVars["ansible_password"]; exists {
					host.Password = password
				}

				if portStr, exists := hostVars["ansible_port"]; exists {
					if port, err := strconv.Atoi(portStr); err == nil {
						host.Port = port
					}
				} else if portStr, exists := hostVars["ansible_ssh_port"]; exists {
					if port, err := strconv.Atoi(portStr); err == nil {
						host.Port = port
					}
				}

				if sudoPass, exists := hostVars["ansible_sudo_pass"]; exists {
					host.SudoPassword = sudoPass
				} else if sudoPass, exists := hostVars["ansible_become_pass"]; exists {
					host.SudoPassword = sudoPass
				}
			}

			group.Hosts = append(group.Hosts, host)
		}

		if len(group.Hosts) > 0 {
			hostConfig.Groups = append(hostConfig.Groups, group)
		}
	}

	return hostConfig
}

// getGlobalVar gets a global variable with fallback options
func (p *InventoryParser) getGlobalVar(keys ...string) string {
	for _, key := range keys {
		if val, exists := p.globalVars[key]; exists {
			return val
		}
	}
	return ""
}

// getGlobalIntVar gets a global integer variable with fallback options
func (p *InventoryParser) getGlobalIntVar(keys ...string) int {
	for _, key := range keys[:len(keys)-1] { // Exclude the default value
		if val, exists := p.globalVars[key]; exists {
			if intVal, err := strconv.Atoi(val); err == nil {
				return intVal
			}
		}
	}
	// Return the default value (last parameter)
	if len(keys) > 0 {
		if defaultVal, err := strconv.Atoi(keys[len(keys)-1]); err == nil {
			return defaultVal
		}
	}
	return 22
}

// isSpecialGroup checks if a group name should be skipped
func (p *InventoryParser) isSpecialGroup(groupName string) bool {
	specialGroups := []string{
		"add_master", "add_node", "add_etcd", "add_etcd_event",
		"del_master", "del_node", "del_etcd", "del_etcd_event",
	}

	for _, special := range specialGroups {
		if groupName == special {
			return true
		}
	}
	return false
}

// SaveToYAML saves the configuration to a YAML file
func (p *InventoryParser) SaveToYAML(filename string, config *config.Config) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config to YAML: %v", err)
	}

	return p.writeFile(filename, data)
}

// writeFile writes data to a file
func (p *InventoryParser) writeFile(filename string, data []byte) error {
	return ioutil.WriteFile(filename, data, 0644)
}
