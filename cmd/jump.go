package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/xuehaipeng/ks-tool/pkg/config"
	"github.com/xuehaipeng/ks-tool/pkg/hosts"
	"github.com/xuehaipeng/ks-tool/pkg/ssh"
	"k8s.io/klog/v2"
)

// NewJumpCmd creates a new jump command
func NewJumpCmd() *cobra.Command {
	var (
		groups    []string
		hostList  []string
		user      string
		pass      string
		port      int
		sudoPass  string
		hostIndex int
	)

	jumpCmd := &cobra.Command{
		Use:   "jump",
		Short: "Start an interactive SSH session to a remote host",
		Long: `Start an interactive SSH session to a remote host using credentials from hosts.yaml.

You can specify either a group (with optional host selection) or individual hosts.
When connecting to a group with multiple hosts, you can specify which host to connect to using --host-index.

Examples:
  # Jump to first host in a group
  ks jump --groups web-servers
  
  # Jump to specific host in a group (0-indexed)
  ks jump --groups web-servers --host-index 1
  
  # Jump to specific host by IP
  ks jump --hosts 192.168.1.10
  
  # Jump with explicit credentials (override config)
  ks jump --hosts 192.168.1.10 --user admin --pass password123
  
  # Jump using smart credential lookup
  ks jump --hosts 192.168.1.10  # Will lookup credentials from hosts.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var targetHost config.Host

			// Handle group selection
			if len(groups) > 0 {
				if len(groups) > 1 {
					return fmt.Errorf("can only jump to one group at a time, got %d groups", len(groups))
				}

				// Load configuration
				cfg, err := config.LoadConfig(configFile)
				if err != nil {
					return fmt.Errorf("failed to load config: %v", err)
				}

				// Get the specified group
				selectedGroups, err := cfg.GetGroups(groups)
				if err != nil {
					return fmt.Errorf("failed to get group: %v", err)
				}

				if len(selectedGroups) == 0 {
					return fmt.Errorf("group '%s' not found", groups[0])
				}

				group := selectedGroups[0]
				if len(group.Hosts) == 0 {
					return fmt.Errorf("group '%s' has no hosts", groups[0])
				}

				// Validate host index
				if hostIndex < 0 || hostIndex >= len(group.Hosts) {
					return fmt.Errorf("host index %d is out of range for group '%s' (0-%d)", hostIndex, groups[0], len(group.Hosts)-1)
				}

				targetHost = group.Hosts[hostIndex]

				if len(group.Hosts) > 1 {
					klog.Infof("Group '%s' has %d hosts, connecting to host %d: %s", groups[0], len(group.Hosts), hostIndex, targetHost.IP)
					for i, h := range group.Hosts {
						marker := "  "
						if i == hostIndex {
							marker = "→ "
						}
						klog.Infof("%s[%d] %s", marker, i, h.IP)
					}
				} else {
					klog.Infof("Connecting to %s from group '%s'", targetHost.IP, groups[0])
				}
			}

			// Handle individual host selection
			if len(hostList) > 0 {
				if len(groups) > 0 {
					return fmt.Errorf("cannot specify both --groups and --hosts")
				}

				if len(hostList) > 1 {
					return fmt.Errorf("can only jump to one host at a time, got %d hosts", len(hostList))
				}

				// Parse the single host
				adhocHosts, err := hosts.ParseAdhocHostsWithLookup(hostList, user, pass, port, sudoPass, configFile)
				if err != nil {
					return fmt.Errorf("failed to parse ad-hoc host: %v", err)
				}

				targetHost = adhocHosts[0]
				klog.Infof("Connecting to %s", targetHost.IP)
			}

			// Validate that we have a target host
			if targetHost.IP == "" {
				return fmt.Errorf("no host specified: use --groups or --hosts")
			}

			// Start interactive SSH session
			return jumpToHost(targetHost)
		},
	}

	jumpCmd.Flags().StringSliceVarP(&groups, "groups", "g", []string{}, "Host group to jump to (only one group allowed)")
	jumpCmd.Flags().StringSliceVarP(&hostList, "hosts", "H", []string{}, "Individual host to jump to (only one host allowed)")
	jumpCmd.Flags().StringVarP(&user, "user", "u", "", "Username for ad-hoc host (will lookup from config if not provided)")
	jumpCmd.Flags().StringVarP(&pass, "pass", "p", "", "Password for ad-hoc host (will lookup from config if not provided)")
	jumpCmd.Flags().IntVar(&port, "port", 22, "SSH port for ad-hoc host")
	jumpCmd.Flags().StringVar(&sudoPass, "sudo-pass", "", "Sudo password for ad-hoc host (will lookup from config if not provided)")
	jumpCmd.Flags().IntVar(&hostIndex, "host-index", 0, "Index of host to connect to within a group (0-based)")

	return jumpCmd
}

// jumpToHost establishes an interactive SSH session to the specified host
func jumpToHost(host config.Host) error {
	klog.Infof("Establishing SSH connection to %s", host.IP)

	// Show connection info
	userInfo := host.Username
	if host.Port != 0 && host.Port != 22 {
		userInfo += fmt.Sprintf(" (port %d)", host.Port)
	}
	fmt.Printf("Connecting to %s@%s...\n", userInfo, host.IP)

	// Create SSH client
	client, err := ssh.NewClient(host)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %v", host.IP, err)
	}
	defer client.Close()

	fmt.Printf("Connected! Starting interactive session...\n")
	fmt.Printf("Type 'exit' to close the connection.\n")
	fmt.Printf("================================\n")

	// Start interactive session
	if err := client.StartInteractiveSession(); err != nil {
		return fmt.Errorf("interactive session failed: %v", err)
	}

	fmt.Printf("\n================================\n")
	fmt.Printf("SSH session to %s closed.\n", host.IP)

	return nil
}
