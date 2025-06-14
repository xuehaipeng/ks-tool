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

// NewExecCmd creates a new exec command
func NewExecCmd() *cobra.Command {
	var (
		groups []string
	)

	execCmd := &cobra.Command{
		Use:   "exec [command]",
		Short: "Execute shell command on remote hosts",
		Long:  `Execute a shell command on one or more groups of remote hosts as root user.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			command := args[0]

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

			// Execute command on all hosts
			return executeCommandOnGroups(selectedGroups, command)
		},
	}

	execCmd.Flags().StringSliceVarP(&groups, "groups", "g", []string{}, "Host groups to execute command on (required)")
	execCmd.MarkFlagRequired("groups")

	return execCmd
}

// executeCommandOnGroups executes a command on multiple host groups
func executeCommandOnGroups(groups []config.HostGroup, command string) error {
	var wg sync.WaitGroup
	var mu sync.Mutex
	errors := make([]string, 0)

	for _, group := range groups {
		klog.Infof("Executing command on group: %s", group.Name)

		for _, host := range group.Hosts {
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
