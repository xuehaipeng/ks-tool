package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/xuehaipeng/ks-tool/cmd"
	"k8s.io/klog/v2"
)

func main() {
	// Create root command first
	rootCmd := cmd.NewRootCmd()

	// Initialize klog flags and add them to the root command
	klog.InitFlags(nil)
	rootCmd.PersistentFlags().AddGoFlagSet(flag.CommandLine)

	// Execute the command
	if err := rootCmd.Execute(); err != nil {
		klog.Errorf("Error executing command: %v", err)
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
