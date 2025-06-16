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

// NewScpCmd creates a new scp command
func NewScpCmd() *cobra.Command {
	var (
		groups     []string
		hostList   []string
		remotePath string
		user       string
		pass       string
		port       int
		sudoPass   string
	)

	scpCmd := &cobra.Command{
		Use:   "scp [local-file]",
		Short: "Copy files to remote hosts via SCP",
		Long: `Copy a local file to one or more groups of remote hosts or individual hosts via SCP as root user.

You can specify either groups from your hosts.yaml file or individual hosts with connection details.

Examples:
  # Copy to groups
  ks scp script.sh --groups web-servers,db-servers --remote-path /tmp/script.sh
  
  # Copy to individual hosts
  ks scp config.conf --hosts 192.168.1.10,192.168.1.11 --user root --pass password123 --remote-path /etc/config.conf
  
  # Mix of groups and individual hosts
  ks scp deploy.sh --groups web-servers --hosts 192.168.1.20 --user admin --pass secret --remote-path /tmp/deploy.sh`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			localPath := args[0]

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

			// Copy file to all hosts
			return copyFileToHosts(allHosts, localPath, remotePath)
		},
	}

	scpCmd.Flags().StringSliceVarP(&groups, "groups", "g", []string{}, "Host groups to copy file to")
	scpCmd.Flags().StringSliceVarP(&hostList, "hosts", "H", []string{}, "Individual hosts to copy file to (IP addresses)")
	scpCmd.Flags().StringVarP(&remotePath, "remote-path", "r", "", "Remote path to copy file to (required)")
	scpCmd.Flags().StringVarP(&user, "user", "u", "", "Username for ad-hoc hosts (will lookup from config if not provided)")
	scpCmd.Flags().StringVarP(&pass, "pass", "p", "", "Password for ad-hoc hosts (will lookup from config if not provided)")
	scpCmd.Flags().IntVar(&port, "port", 22, "SSH port for ad-hoc hosts")
	scpCmd.Flags().StringVar(&sudoPass, "sudo-pass", "", "Sudo password for ad-hoc hosts (will lookup from config if not provided)")
	scpCmd.MarkFlagRequired("remote-path")

	return scpCmd
}

// copyFileToHosts copies a file to multiple hosts
func copyFileToHosts(hosts []config.Host, localPath, remotePath string) error {
	var wg sync.WaitGroup
	var mu sync.Mutex
	errors := make([]string, 0)

	klog.Infof("Copying file to %d hosts", len(hosts))

	for _, host := range hosts {
		wg.Add(1)
		go func(h config.Host) {
			defer wg.Done()

			if err := copyFileToHost(h, localPath, remotePath); err != nil {
				mu.Lock()
				errors = append(errors, fmt.Sprintf("Host %s: %v", h.IP, err))
				mu.Unlock()
			}
		}(host)
	}

	wg.Wait()

	if len(errors) > 0 {
		return fmt.Errorf("file copy failed on some hosts:\n%s", strings.Join(errors, "\n"))
	}

	return nil
}

// copyFileToHost copies a file to a single host
func copyFileToHost(host config.Host, localPath, remotePath string) error {
	klog.Infof("Connecting to host: %s", host.IP)

	client, err := ssh.NewClient(host)
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	defer client.Close()

	if err := client.CopyFile(localPath, remotePath); err != nil {
		klog.Errorf("File copy failed on %s: %v", host.IP, err)
		return err
	}

	klog.Infof("File copy succeeded on %s: %s -> %s", host.IP, localPath, remotePath)
	fmt.Printf("Successfully copied %s to %s:%s\n", localPath, host.IP, remotePath)

	return nil
}
