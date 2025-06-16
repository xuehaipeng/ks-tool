package hosts

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/xuehaipeng/ks-tool/pkg/ansible"
	"github.com/xuehaipeng/ks-tool/pkg/config"
	"k8s.io/klog/v2"
)

// ParseAdhocHosts parses individual host specifications
func ParseAdhocHosts(hostSpecs []string, user, pass string, port int, sudoPass string) ([]config.Host, error) {
	var hosts []config.Host

	for _, hostSpec := range hostSpecs {
		// hostSpec can be just IP or IP:PORT
		ip, hostPort, err := ParseHostSpec(hostSpec)
		if err != nil {
			return nil, fmt.Errorf("invalid host specification '%s': %v", hostSpec, err)
		}

		// Use specified port if not provided in host spec
		if hostPort == 0 {
			hostPort = port
		}

		host := config.Host{
			IP:           ip,
			Username:     user,
			Password:     pass,
			Port:         hostPort,
			SudoPassword: sudoPass,
		}

		hosts = append(hosts, host)
	}

	return hosts, nil
}

// ParseAdhocHostsWithLookup parses individual host specifications with credential lookup
func ParseAdhocHostsWithLookup(hostSpecs []string, user, pass string, port int, sudoPass, configFile string) ([]config.Host, error) {
	var hosts []config.Host

	for _, hostSpec := range hostSpecs {
		// hostSpec can be just IP or IP:PORT
		ip, hostPort, err := ParseHostSpec(hostSpec)
		if err != nil {
			return nil, fmt.Errorf("invalid host specification '%s': %v", hostSpec, err)
		}

		// Use specified port if not provided in host spec
		if hostPort == 0 {
			hostPort = port
		}

		// Create initial host configuration
		host := config.Host{
			IP:           ip,
			Username:     user,
			Password:     pass,
			Port:         hostPort,
			SudoPassword: sudoPass,
		}

		// If credentials are missing, try to look them up
		if user == "" || pass == "" || sudoPass == "" {
			lookupHost, err := lookupHostCredentials(ip, configFile)
			if err != nil {
				klog.V(2).Infof("Could not lookup credentials for host %s: %v", ip, err)
			} else {
				// Fill in missing credentials
				if user == "" && lookupHost.Username != "" {
					host.Username = lookupHost.Username
				}
				if pass == "" && lookupHost.Password != "" {
					host.Password = lookupHost.Password
				}
				if sudoPass == "" && lookupHost.SudoPassword != "" {
					host.SudoPassword = lookupHost.SudoPassword
				}
				if host.Port == 22 && lookupHost.Port != 0 {
					host.Port = lookupHost.Port
				}
				klog.V(2).Infof("Found credentials for host %s from config", ip)
			}
		}

		// Validate that we have at least username
		if host.Username == "" {
			host.Username = "root" // Default fallback
		}

		hosts = append(hosts, host)
	}

	return hosts, nil
}

// lookupHostCredentials looks up host credentials from config files
func lookupHostCredentials(ip, configFile string) (*config.Host, error) {
	// First try to find in hosts.yaml config file
	if configFile != "" {
		if _, err := os.Stat(configFile); err == nil {
			cfg, err := config.LoadConfig(configFile)
			if err == nil {
				for _, group := range cfg.Groups {
					for _, host := range group.Hosts {
						if host.IP == ip {
							return &host, nil
						}
					}
				}
			}
		}
	}

	// If not found in hosts.yaml, try default ansible inventory
	defaultAnsibleFile := "/etc/kubeasz/clusters/tecoai/hosts"
	if _, err := os.Stat(defaultAnsibleFile); err == nil {
		return lookupFromAnsibleInventory(ip, defaultAnsibleFile)
	}

	return nil, fmt.Errorf("host %s not found in any config file", ip)
}

// lookupFromAnsibleInventory looks up host credentials from ansible inventory
func lookupFromAnsibleInventory(ip, inventoryFile string) (*config.Host, error) {
	file, err := os.Open(inventoryFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open ansible inventory: %v", err)
	}
	defer file.Close()

	parser := ansible.NewInventoryParser()
	if err := parser.ParseInventory(file); err != nil {
		return nil, fmt.Errorf("failed to parse ansible inventory: %v", err)
	}

	// Convert to hosts config and search for the IP
	hostConfig := parser.ConvertToHostsConfig()
	for _, group := range hostConfig.Groups {
		for _, host := range group.Hosts {
			if host.IP == ip {
				return &host, nil
			}
		}
	}

	return nil, fmt.Errorf("host %s not found in ansible inventory", ip)
}

// ParseHostSpec parses a host specification (IP or IP:PORT)
func ParseHostSpec(hostSpec string) (string, int, error) {
	// Check if port is specified
	if strings.Contains(hostSpec, ":") {
		host, portStr, err := net.SplitHostPort(hostSpec)
		if err != nil {
			return "", 0, err
		}

		port, err := strconv.Atoi(portStr)
		if err != nil {
			return "", 0, fmt.Errorf("invalid port '%s': %v", portStr, err)
		}

		return host, port, nil
	}

	// Just IP address
	ip := net.ParseIP(hostSpec)
	if ip == nil {
		return "", 0, fmt.Errorf("invalid IP address '%s'", hostSpec)
	}

	return hostSpec, 0, nil
}
