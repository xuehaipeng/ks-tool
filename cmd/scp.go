package cmd

import (
	"fmt"
	"strings"
	"sync"

	"github.com/spf13/cobra"
	"github.com/xuehaipeng/ks-tool/pkg/config"
	"github.com/xuehaipeng/ks-tool/pkg/ssh"
	"k8s.io/klog/v2"
)

// NewScpCmd creates a new scp command
func NewScpCmd() *cobra.Command {
	var (
		groups     []string
		remotePath string
	)

	scpCmd := &cobra.Command{
		Use:   "scp [local-file]",
		Short: "Copy files to remote hosts via SCP",
		Long:  `Copy a local file to one or more groups of remote hosts via SCP as root user.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			localPath := args[0]

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

			// Copy file to all hosts
			return copyFileToGroups(selectedGroups, localPath, remotePath)
		},
	}

	scpCmd.Flags().StringSliceVarP(&groups, "groups", "g", []string{}, "Host groups to copy file to (required)")
	scpCmd.Flags().StringVarP(&remotePath, "remote-path", "r", "", "Remote path to copy file to (required)")
	scpCmd.MarkFlagRequired("groups")
	scpCmd.MarkFlagRequired("remote-path")

	return scpCmd
}

// copyFileToGroups copies a file to multiple host groups
func copyFileToGroups(groups []config.HostGroup, localPath, remotePath string) error {
	var wg sync.WaitGroup
	var mu sync.Mutex
	errors := make([]string, 0)

	for _, group := range groups {
		klog.Infof("Copying file to group: %s", group.Name)

		for _, host := range group.Hosts {
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
