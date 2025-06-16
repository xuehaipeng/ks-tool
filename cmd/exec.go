package cmd

import (
	"fmt"
	"strings"
	"sync"

	"github.com/spf13/cobra"
	"github.com/xuehaipeng/ks-tool/pkg/config"
	"github.com/xuehaipeng/ks-tool/pkg/hosts"
	"github.com/xuehaipeng/ks-tool/pkg/ssh"
	"k8s.io/klog/v2"
)

// NewExecCmd creates a new exec command
func NewExecCmd() *cobra.Command {
	var (
		groups   []string
		hostList []string
		user     string
		pass     string
		port     int
		sudoPass string
	)

	execCmd := &cobra.Command{
		Use:   "exec [command]",
		Short: "Execute shell command on remote hosts",
		Long: `Execute a shell command on one or more groups of remote hosts or individual hosts as root user.

You can specify either groups from your hosts.yaml file or individual hosts with connection details.
Supports complex shell operations including pipelines, redirections, and command chaining.

Examples:
  # Execute on groups
  ks exec "uptime" --groups web-servers,db-servers
  
  # Pipeline operations
  ks exec "lscpu | grep 'Model name'" --groups web-servers
  ks exec "ps aux | grep nginx | wc -l" --groups web-servers
  
  # Command chaining and redirections
  ks exec "df -h > /tmp/disk_usage.txt && cat /tmp/disk_usage.txt" --groups web-servers
  
  # Execute on individual hosts
  ks exec "uptime" --hosts 192.168.1.10,192.168.1.11 --user root --pass password123
  
  # Complex pipeline on individual hosts
  ks exec "cat /proc/cpuinfo | grep processor | wc -l" --hosts 192.168.1.10 --user admin
  
  # Mix of groups and individual hosts
  ks exec "systemctl status nginx | head -5" --groups web-servers --hosts 192.168.1.20 --user admin --pass secret`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			command := args[0]

			var allHosts []config.Host

			// Process groups if specified
			if len(groups) > 0 {
				// Load configuration
				cfg, err := config.LoadConfig(configFile)
				if err != nil {
					return fmt.Errorf("failed to load config: %v", err)
				}

				// Get specified groups
				selectedGroups, err := cfg.GetGroups(groups)
				if err != nil {
					return fmt.Errorf("failed to get groups: %v", err)
				}

				// Collect all hosts from groups
				for _, group := range selectedGroups {
					allHosts = append(allHosts, group.Hosts...)
				}
			}

			// Process individual hosts if specified
			if len(hostList) > 0 {
				adhocHosts, err := hosts.ParseAdhocHostsWithLookup(hostList, user, pass, port, sudoPass, configFile)
				if err != nil {
					return fmt.Errorf("failed to parse ad-hoc hosts: %v", err)
				}
				allHosts = append(allHosts, adhocHosts...)
			}

			// Validate that at least one host or group is specified
			if len(allHosts) == 0 {
				return fmt.Errorf("no hosts specified: use --groups or --hosts")
			}

			// Execute command on all hosts
			return executeCommandOnHosts(allHosts, command)
		},
	}

	execCmd.Flags().StringSliceVarP(&groups, "groups", "g", []string{}, "Host groups to execute command on")
	execCmd.Flags().StringSliceVarP(&hostList, "hosts", "H", []string{}, "Individual hosts to execute command on (IP addresses)")
	execCmd.Flags().StringVarP(&user, "user", "u", "", "Username for ad-hoc hosts (will lookup from config if not provided)")
	execCmd.Flags().StringVarP(&pass, "pass", "p", "", "Password for ad-hoc hosts (will lookup from config if not provided)")
	execCmd.Flags().IntVar(&port, "port", 22, "SSH port for ad-hoc hosts")
	execCmd.Flags().StringVar(&sudoPass, "sudo-pass", "", "Sudo password for ad-hoc hosts (will lookup from config if not provided)")

	return execCmd
}

// executeCommandOnHosts executes a command on multiple hosts
func executeCommandOnHosts(hosts []config.Host, command string) error {
	var wg sync.WaitGroup
	var mu sync.Mutex
	errors := make([]string, 0)

	klog.Infof("Executing command on %d hosts", len(hosts))

	for _, host := range hosts {
		wg.Add(1)
		go func(h config.Host) {
			defer wg.Done()

			if err := executeCommandOnHost(h, command); err != nil {
				mu.Lock()
				errors = append(errors, fmt.Sprintf("Host %s: %v", h.IP, err))
				mu.Unlock()
			}
		}(host)
	}

	wg.Wait()

	if len(errors) > 0 {
		return fmt.Errorf("execution failed on some hosts:\n%s", strings.Join(errors, "\n"))
	}

	return nil
}

// executeCommandOnHost executes a command on a single host
func executeCommandOnHost(host config.Host, command string) error {
	klog.Infof("Connecting to host: %s", host.IP)

	client, err := ssh.NewClient(host)
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	defer client.Close()

	output, err := client.ExecuteCommand(command)
	if err != nil {
		klog.Errorf("Command failed on %s: %v", host.IP, err)
		if output != "" {
			klog.Errorf("Output from %s: %s", host.IP, output)
		}
		return err
	}

	klog.Infof("Command succeeded on %s", host.IP)
	if output != "" {
		fmt.Printf("=== Output from %s ===\n%s\n", host.IP, output)
	}

	return nil
}
