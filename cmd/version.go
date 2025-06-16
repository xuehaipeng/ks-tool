package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/xuehaipeng/ks-tool/pkg/version"
)

// NewVersionCmd creates a new version command
func NewVersionCmd() *cobra.Command {
	var short bool

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Long:  `Display version information for ks-tool including build time and commit information.`,
		Run: func(cmd *cobra.Command, args []string) {
			if short {
				fmt.Println(version.GetShortVersion())
			} else {
				fmt.Println(version.GetVersion())
			}
		},
	}

	versionCmd.Flags().BoolVar(&short, "short", false, "Print only the version number")

	return versionCmd
}
