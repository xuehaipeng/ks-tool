package cmd

import (
	"github.com/spf13/cobra"
	"k8s.io/klog/v2"
)

var (
	configFile string
)

// NewRootCmd creates a new root command
func NewRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "ks-tool",
		Short: "A tool for managing and executing commands on multiple hosts",
		Long: `ks-tool is a command-line tool that allows you to:
- Execute shell commands on multiple hosts
- Copy files to multiple hosts via SCP
- Manage groups of hosts with different configurations`,
		Run: func(cmd *cobra.Command, args []string) {
			klog.Info("Use 'ks-tool --help' for more information")
		},
	}

	// Global flags
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "hosts.yaml", "Path to hosts configuration file")

	// Add subcommands
	rootCmd.AddCommand(NewExecCmd())
	rootCmd.AddCommand(NewScpCmd())

	return rootCmd
}
