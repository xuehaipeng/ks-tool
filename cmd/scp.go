package cmd

import (
	"fmt"
	"path/filepath"
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
		recursive  bool
	)

	scpCmd := &cobra.Command{
		Use:   "scp [local-file-or-directory]...",
		Short: "Copy files or directories to remote hosts via SCP",
		Long: `Copy one or more local files or directories to one or more groups of remote hosts or individual hosts via SCP as root user.

You can specify either groups from your hosts.yaml file or individual hosts with connection details.
Use the --recursive flag to copy directories and their contents recursively.

When the remote path ends with '/', it is treated as a directory and the source file/directory name 
will be automatically appended to create the full destination path.

Examples:
  # Copy file to groups
  ks scp script.sh --groups web-servers,db-servers --remote-path /tmp/script.sh
  
  # Copy multiple files to directory (auto-append filename)
  ks scp ./certs/kubelet.pem ./certs/kubelet-key.pem --hosts 192.168.1.10 --remote-path /etc/kubernetes/ssl/
  # Equivalent to: --remote-path /etc/kubernetes/ssl/kubelet.pem and /etc/kubernetes/ssl/kubelet-key.pem
  
  # Copy directory recursively to groups
  ks scp ./config-dir --groups web-servers --remote-path /etc/myapp --recursive
  
  # Copy multiple directories to target directory (auto-append source dir name)
  ks scp ./deploy ./scripts --hosts 192.168.1.10 --remote-path /opt/
  # Equivalent to: --remote-path /opt/deploy and /opt/scripts
  
  # Copy to individual hosts with explicit path
  ks scp config.conf --hosts 192.168.1.10,192.168.1.11 --user root --pass password123 --remote-path /etc/config.conf
  
  # Mix of groups and individual hosts
  ks scp deploy.sh --groups web-servers --hosts 192.168.1.20 --user admin --pass secret --remote-path /tmp/deploy.sh`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			localPaths := args

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

			// Copy all files/directories to all hosts
			return copyPathsToHosts(allHosts, localPaths, remotePath, recursive)
		},
	}

	scpCmd.Flags().StringSliceVarP(&groups, "groups", "g", []string{}, "Host groups to copy file/directory to")
	scpCmd.Flags().StringSliceVarP(&hostList, "hosts", "H", []string{}, "Individual hosts to copy file/directory to (IP addresses)")
	scpCmd.Flags().StringVarP(&remotePath, "remote-path", "r", "", "Remote path to copy file/directory to (required)")
	scpCmd.Flags().StringVarP(&user, "user", "u", "", "Username for ad-hoc hosts (will lookup from config if not provided)")
	scpCmd.Flags().StringVarP(&pass, "pass", "p", "", "Password for ad-hoc hosts (will lookup from config if not provided)")
	scpCmd.Flags().IntVar(&port, "port", 22, "SSH port for ad-hoc hosts")
	scpCmd.Flags().StringVar(&sudoPass, "sudo-pass", "", "Sudo password for ad-hoc hosts (will lookup from config if not provided)")
	scpCmd.Flags().BoolVar(&recursive, "recursive", true, "Copy directories recursively")
	scpCmd.MarkFlagRequired("remote-path")

	return scpCmd
}

// copyPathsToHosts copies one or more files or directories to multiple hosts
func copyPathsToHosts(hosts []config.Host, localPaths []string, remotePath string, recursive bool) error {
	var wg sync.WaitGroup
	var mu sync.Mutex
	errors := make([]string, 0)

	klog.Infof("Copying %d files/directories to %d hosts", len(localPaths), len(hosts))

	// For each local path, copy it to all hosts
	for _, localPath := range localPaths {
		klog.Infof("Copying %s to %d hosts", localPath, len(hosts))
		
		// Copy this local path to all hosts
		for _, host := range hosts {
			wg.Add(1)
			go func(h config.Host, path string) {
				defer wg.Done()

				if err := copyPathToHost(h, path, remotePath, recursive); err != nil {
					mu.Lock()
					errors = append(errors, fmt.Sprintf("Host %s, path %s: %v", h.IP, path, err))
					mu.Unlock()
				}
			}(host, localPath)
		}
		
		// Wait for all hosts to finish copying this path before moving to the next
		wg.Wait()
	}

	if len(errors) > 0 {
		return fmt.Errorf("copy failed on some hosts:\n%s", strings.Join(errors, "\n"))
	}

	return nil
}

// copyPathToHost copies a file or directory to a single host
func copyPathToHost(host config.Host, localPath, remotePath string, recursive bool) error {
	klog.Infof("Connecting to host: %s", host.IP)

	client, err := ssh.NewClient(host)
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	defer client.Close()

	// Handle directory-style remote paths (ending with '/')
	finalRemotePath := remotePath
	if strings.HasSuffix(remotePath, "/") {
		// Extract the base name from local path and append to remote directory
		baseName := filepath.Base(localPath)
		finalRemotePath = filepath.Join(remotePath, baseName)
		// Convert to forward slashes for remote Unix systems
		finalRemotePath = strings.ReplaceAll(finalRemotePath, "\\", "/")
		klog.V(2).Infof("Remote path ends with '/', using full path: %s", finalRemotePath)
	}

	if recursive {
		if err := client.CopyPath(localPath, finalRemotePath); err != nil {
			klog.Errorf("Path copy failed on %s: %v", host.IP, err)
			return err
		}
	} else {
		if err := client.CopyFile(localPath, finalRemotePath); err != nil {
			klog.Errorf("File copy failed on %s: %v", host.IP, err)
			return err
		}
	}

	klog.Infof("Copy succeeded on %s: %s -> %s", host.IP, localPath, finalRemotePath)
	fmt.Printf("Successfully copied %s to %s:%s\n", localPath, host.IP, finalRemotePath)

	return nil
}
