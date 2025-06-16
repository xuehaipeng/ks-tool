package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/xuehaipeng/ks-tool/pkg/ansible"
	"k8s.io/klog/v2"
)

var (
	inputFile  string
	outputFile string
)

// NewExtractCmd creates a new extract command
func NewExtractCmd() *cobra.Command {
	extractCmd := &cobra.Command{
		Use:   "extract",
		Short: "Extract SSH information from Ansible inventory file",
		Long: `Extract SSH configuration from an Ansible inventory file and convert it to hosts.yaml format.
		
This command parses an Ansible inventory file and extracts:
- Host IP addresses from different groups (etcd, kube_master, kube_node, etc.)
- SSH connection details (username, password, port, sudo password)
- Group-level and host-level configurations

Example:
  ks-tool extract -i /path/to/ansible/inventory -o hosts.yaml`,
		RunE: runExtract,
	}

	// Add flags
	extractCmd.Flags().StringVarP(&inputFile, "input", "i", "/etc/kubeasz/clusters/tecoai/hosts", "Path to the Ansible inventory file (required)")
	extractCmd.Flags().StringVarP(&outputFile, "output", "o", "hosts.yaml", "Path to the output hosts.yaml file")

	// Mark input as required
	extractCmd.MarkFlagRequired("input")

	return extractCmd
}

// runExtract executes the extract command
func runExtract(cmd *cobra.Command, args []string) error {
	klog.Infof("Extracting SSH information from Ansible inventory file: %s", inputFile)

	// Check if input file exists
	if _, err := os.Stat(inputFile); os.IsNotExist(err) {
		return fmt.Errorf("input file does not exist: %s", inputFile)
	}

	// Open the input file
	file, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("failed to open input file: %v", err)
	}
	defer file.Close()

	// Create parser and parse the inventory
	parser := ansible.NewInventoryParser()
	if err := parser.ParseInventory(file); err != nil {
		return fmt.Errorf("failed to parse inventory file: %v", err)
	}

	// Convert to hosts configuration
	hostConfig := parser.ConvertToHostsConfig()

	// Save to output file
	if err := parser.SaveToYAML(outputFile, hostConfig); err != nil {
		return fmt.Errorf("failed to save hosts configuration: %v", err)
	}

	klog.Infof("Successfully extracted SSH information to: %s", outputFile)
	klog.Infof("Found %d groups with the following hosts:", len(hostConfig.Groups))

	// Print summary
	for _, group := range hostConfig.Groups {
		klog.Infof("  Group '%s': %d hosts", group.Name, len(group.Hosts))
		for _, host := range group.Hosts {
			userInfo := ""
			if host.Username != "" {
				userInfo = fmt.Sprintf(" (user: %s", host.Username)
				if host.Port != 0 {
					userInfo += fmt.Sprintf(", port: %d", host.Port)
				}
				userInfo += ")"
			}
			klog.Infof("    - %s%s", host.IP, userInfo)
		}
	}

	return nil
}
