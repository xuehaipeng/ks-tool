package cmd

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"github.com/xuehaipeng/ks-tool/pkg/config"
	"github.com/xuehaipeng/ks-tool/pkg/hosts"
	"github.com/xuehaipeng/ks-tool/pkg/ssh"
	"k8s.io/klog/v2"
)

// NewDNSCmd creates a new dns command
func NewDNSCmd() *cobra.Command {
	var (
		groups            []string
		hostList          []string
		user              string
		pass              string
		port              int
		sudoPass          string
		kubeletConfigPath string
		dnsServiceName    string
		dnsServiceNS      string
	)

	dnsCmd := &cobra.Command{
		Use:   "dns-update",
		Short: "Update kubelet DNS configuration with kube-dns service IP",
		Long: `Update kubelet DNS configuration by querying the kube-dns service IP from Kubernetes cluster
and updating the clusterDNS setting in kubelet config file on specified hosts.

The command will:
1. Query kube-dns service IP using: kubectl get svc -n kube-system kube-dns
2. Update /var/lib/kubelet/config.yaml on specified hosts with the DNS service IP
3. Restart kubelet service to apply the changes

Examples:
  # Update DNS config on web-servers group
  ks dns-update --groups web-servers
  
  # Update DNS config on specific hosts
  ks dns-update --hosts 192.168.1.10,192.168.1.11 --user root --pass password123
  
  # Update with custom kubelet config path
  ks dns-update --groups web-servers --kubelet-config /custom/path/kubelet/config.yaml
  
  # Update with custom DNS service name and namespace
  ks dns-update --groups web-servers --dns-service coredns --dns-namespace kube-system`,
		RunE: func(cmd *cobra.Command, args []string) error {
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

			// Query DNS service IP
			dnsIP, err := queryDNSServiceIP(dnsServiceName, dnsServiceNS)
			if err != nil {
				return fmt.Errorf("failed to query DNS service IP: %v", err)
			}

			klog.Infof("Found DNS service IP: %s", dnsIP)

			// Update kubelet config on all hosts
			return updateKubeletDNSOnHosts(allHosts, dnsIP, kubeletConfigPath)
		},
	}

	dnsCmd.Flags().StringSliceVarP(&groups, "groups", "g", []string{}, "Host groups to update DNS config on")
	dnsCmd.Flags().StringSliceVarP(&hostList, "hosts", "H", []string{}, "Individual hosts to update DNS config on (IP addresses)")
	dnsCmd.Flags().StringVarP(&user, "user", "u", "", "Username for ad-hoc hosts (will lookup from config if not provided)")
	dnsCmd.Flags().StringVarP(&pass, "pass", "p", "", "Password for ad-hoc hosts (will lookup from config if not provided)")
	dnsCmd.Flags().IntVar(&port, "port", 22, "SSH port for ad-hoc hosts")
	dnsCmd.Flags().StringVar(&sudoPass, "sudo-pass", "", "Sudo password for ad-hoc hosts (will lookup from config if not provided)")
	dnsCmd.Flags().StringVar(&kubeletConfigPath, "kubelet-config", "/var/lib/kubelet/config.yaml", "Path to kubelet config file on remote hosts")
	dnsCmd.Flags().StringVar(&dnsServiceName, "dns-service", "kube-dns", "Name of the DNS service to query")
	dnsCmd.Flags().StringVar(&dnsServiceNS, "dns-namespace", "kube-system", "Namespace of the DNS service")

	return dnsCmd
}

// queryDNSServiceIP queries the DNS service IP using kubectl
func queryDNSServiceIP(serviceName, namespace string) (string, error) {
	klog.V(2).Infof("Querying DNS service IP: %s in namespace %s", serviceName, namespace)

	// Run kubectl command to get service cluster IP
	cmd := exec.Command("kubectl", "get", "svc", "-n", namespace, serviceName, "-o", "jsonpath={.spec.clusterIP}")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("kubectl command failed: %v\nOutput: %s", err, string(output))
	}

	dnsIP := strings.TrimSpace(string(output))
	if dnsIP == "" {
		return "", fmt.Errorf("DNS service IP is empty, service may not exist")
	}

	// Validate IP format
	ipRegex := regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
	if !ipRegex.MatchString(dnsIP) {
		return "", fmt.Errorf("invalid IP format: %s", dnsIP)
	}

	return dnsIP, nil
}

// updateKubeletDNSOnHosts updates kubelet DNS configuration on multiple hosts
func updateKubeletDNSOnHosts(hosts []config.Host, dnsIP, kubeletConfigPath string) error {
	var wg sync.WaitGroup
	var mu sync.Mutex
	errors := make([]string, 0)

	klog.Infof("Updating kubelet DNS config on %d hosts with IP: %s", len(hosts), dnsIP)

	for _, host := range hosts {
		wg.Add(1)
		go func(h config.Host) {
			defer wg.Done()

			if err := updateKubeletDNSOnHost(h, dnsIP, kubeletConfigPath); err != nil {
				mu.Lock()
				errors = append(errors, fmt.Sprintf("Host %s: %v", h.IP, err))
				mu.Unlock()
			}
		}(host)
	}

	wg.Wait()

	if len(errors) > 0 {
		return fmt.Errorf("DNS update failed on some hosts:\n%s", strings.Join(errors, "\n"))
	}

	return nil
}

// updateKubeletDNSOnHost updates kubelet DNS configuration on a single host
func updateKubeletDNSOnHost(host config.Host, dnsIP, kubeletConfigPath string) error {
	klog.Infof("Updating kubelet DNS config on host: %s", host.IP)

	client, err := ssh.NewClient(host)
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	defer client.Close()

	// Backup original config file
	backupPath := kubeletConfigPath + ".backup." + fmt.Sprintf("%d", getCurrentTimestamp())
	backupCmd := fmt.Sprintf("cp %s %s", kubeletConfigPath, backupPath)
	if _, err := client.ExecuteCommand(backupCmd); err != nil {
		klog.Warningf("Failed to backup config file on %s: %v", host.IP, err)
	} else {
		klog.V(2).Infof("Backed up config file to %s on %s", backupPath, host.IP)
	}

	// Read current config file
	readCmd := fmt.Sprintf("cat %s", kubeletConfigPath)
	currentConfig, err := client.ExecuteCommand(readCmd)
	if err != nil {
		return fmt.Errorf("failed to read kubelet config: %v", err)
	}

	// Update DNS configuration
	updatedConfig, err := updateDNSInConfig(currentConfig, dnsIP)
	if err != nil {
		return fmt.Errorf("failed to update DNS config: %v", err)
	}

	// Write updated config back to file
	writeCmd := fmt.Sprintf("cat > %s << 'EOF'\n%sEOF", kubeletConfigPath, updatedConfig)
	if _, err := client.ExecuteCommand(writeCmd); err != nil {
		return fmt.Errorf("failed to write updated config: %v", err)
	}

	// Restart kubelet service
	restartCmd := "systemctl restart kubelet"
	if _, err := client.ExecuteCommand(restartCmd); err != nil {
		klog.Warningf("Failed to restart kubelet on %s: %v", host.IP, err)
		return fmt.Errorf("failed to restart kubelet service: %v", err)
	}

	// Verify kubelet status
	statusCmd := "systemctl is-active kubelet"
	status, err := client.ExecuteCommand(statusCmd)
	if err != nil || strings.TrimSpace(status) != "active" {
		klog.Warningf("Kubelet may not be running properly on %s: %s", host.IP, strings.TrimSpace(status))
	}

	klog.Infof("Successfully updated kubelet DNS config on %s", host.IP)
	fmt.Printf("Successfully updated DNS config on %s: clusterDNS set to %s\n", host.IP, dnsIP)

	return nil
}

// updateDNSInConfig updates the clusterDNS setting in kubelet config YAML
func updateDNSInConfig(configContent, dnsIP string) (string, error) {
	lines := strings.Split(configContent, "\n")
	var updatedLines []string
	inClusterDNSSection := false
	clusterDNSFound := false

	for _, line := range lines {
		// Check if we're at the clusterDNS line
		if strings.Contains(line, "clusterDNS:") {
			updatedLines = append(updatedLines, line)
			clusterDNSFound = true
			inClusterDNSSection = true
			continue
		}

		// If we're in the clusterDNS section and find a list item (starts with -)
		if inClusterDNSSection && strings.TrimSpace(line) != "" {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "-") {
				// Replace the first DNS entry with our new IP
				updatedLines = append(updatedLines, fmt.Sprintf("- %s", dnsIP))
				inClusterDNSSection = false
				continue
			} else if !strings.HasPrefix(trimmed, " ") && !strings.HasPrefix(trimmed, "-") {
				// We've moved to a different section
				inClusterDNSSection = false
			}
		}

		updatedLines = append(updatedLines, line)
	}

	// If clusterDNS section wasn't found, add it
	if !clusterDNSFound {
		return "", fmt.Errorf("clusterDNS section not found in kubelet config")
	}

	return strings.Join(updatedLines, "\n"), nil
}

// getCurrentTimestamp returns current timestamp for backup file naming
func getCurrentTimestamp() int64 {
	return time.Now().Unix()
}
