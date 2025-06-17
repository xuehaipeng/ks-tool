package cmd

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
	"k8s.io/klog/v2"
)

// NewGenCertCmd creates a new gencert command
func NewGenCertCmd() *cobra.Command {
	var (
		hostname             string
		ipAddress            string
		apiServer            string
		caFile               string
		caKeyFile            string
		certFile             string
		keyFile              string
		kubeconfigFile       string
		kubeProxyConfigFile  string
		outputDir            string
		country              string
		state                string
		locality             string
		organization         string
		orgUnit              string
		clusterCIDR          string
		kubeletDataDir       string
		generateServiceFiles bool
	)

	genCertCmd := &cobra.Command{
		Use:   "gencert",
		Short: "Generate kubelet certificates, kubeconfig files, and service configurations",
		Long: `Generate kubelet certificates, kubeconfig files, and service configurations for Kubernetes nodes.

This command creates kubelet certificates signed by the specified CA certificate
and generates corresponding kubeconfig files with base64-encoded certificates.
It generates both kubelet.kubeconfig and kube-proxy.kubeconfig files using the
same certificates. The generated certificates include proper subject alternative 
names (SANs) for both hostname and IP address.

Additionally, it can generate node-specific service configuration files:
- kubelet.service systemd unit file with proper hostname and IP configuration
- kube-proxy-config.yaml with cluster CIDR and hostname settings

The command automatically detects configuration from the local master node:
- Cluster CIDR is read from /var/lib/kube-proxy/kube-proxy-config.yaml
- Kubelet data directory is read from /etc/systemd/system/kubelet.service
- Falls back to defaults if local files are not found or cannot be parsed

Examples:
  # Generate kubelet cert and kubeconfig files for a node (auto-detects config)
  ks gencert --hostname worker-1 --ip 192.168.1.100
  
  # Generate with custom API server address (auto-detects cluster CIDR and data dir)
  ks gencert --hostname master-1 --ip 10.0.1.10 --apiserver https://10.0.1.10:6443
  
  # Override auto-detected values with custom settings
  ks gencert --hostname master-1 --ip 10.0.1.10 --cluster-cidr 10.244.0.0/16 --kubelet-data-dir /var/lib/kubelet
  
  # Generate without service files (certificates and kubeconfig only)
  ks gencert --hostname node-1 --ip 172.16.1.50 --generate-service-files=false
  
  # Generate with custom certificate details
  ks gencert --hostname node-1 --ip 192.168.1.10 --country US --state California --locality "San Francisco"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return generateKubeletCert(hostname, ipAddress, apiServer, caFile, caKeyFile, certFile, keyFile, kubeconfigFile, kubeProxyConfigFile, outputDir,
				country, state, locality, organization, orgUnit, clusterCIDR, kubeletDataDir, generateServiceFiles)
		},
	}

	genCertCmd.Flags().StringVar(&hostname, "hostname", "", "Hostname of the target node (required)")
	genCertCmd.Flags().StringVar(&ipAddress, "ip", "", "IP address of the target node (required)")
	genCertCmd.Flags().StringVar(&apiServer, "apiserver", "https://127.0.0.1:6443", "Kubernetes API server address")
	genCertCmd.Flags().StringVar(&caFile, "ca-file", "/etc/kubernetes/ssl/ca.pem", "Path to CA certificate file")
	genCertCmd.Flags().StringVar(&caKeyFile, "ca-key-file", "/etc/kubernetes/ssl/ca-key.pem", "Path to CA private key file")
	genCertCmd.Flags().StringVar(&certFile, "cert-file", "/etc/kubernetes/ssl/kubelet.pem", "Output path for kubelet certificate")
	genCertCmd.Flags().StringVar(&keyFile, "key-file", "/etc/kubernetes/ssl/kubelet-key.pem", "Output path for kubelet private key")
	genCertCmd.Flags().StringVar(&kubeconfigFile, "kubeconfig-file", "/etc/kubernetes/kubelet.kubeconfig", "Output path for kubelet kubeconfig")
	genCertCmd.Flags().StringVar(&kubeProxyConfigFile, "kube-proxy-config-file", "/etc/kubernetes/kube-proxy.kubeconfig", "Output path for kube-proxy kubeconfig")
	genCertCmd.Flags().StringVar(&outputDir, "output-dir", "", "Output directory for generated files (overrides cert-file, key-file, and kubeconfig files)")
	genCertCmd.Flags().StringVar(&country, "country", "CN", "Country name for certificate subject")
	genCertCmd.Flags().StringVar(&state, "state", "HangZhou", "State or province name for certificate subject")
	genCertCmd.Flags().StringVar(&locality, "locality", "XS", "Locality name for certificate subject")
	genCertCmd.Flags().StringVar(&organization, "organization", "system:nodes", "Organization name for certificate subject")
	genCertCmd.Flags().StringVar(&orgUnit, "org-unit", "System", "Organizational unit for certificate subject")
	genCertCmd.Flags().StringVar(&clusterCIDR, "cluster-cidr", "200.20.0.0/18", "Cluster CIDR for kube-proxy configuration (auto-detected from /var/lib/kube-proxy/kube-proxy-config.yaml)")
	genCertCmd.Flags().StringVar(&kubeletDataDir, "kubelet-data-dir", "/data/kubelet", "Kubelet data directory (auto-detected from /etc/systemd/system/kubelet.service)")
	genCertCmd.Flags().BoolVar(&generateServiceFiles, "generate-service-files", true, "Generate kubelet.service and kube-proxy-config.yaml files")

	genCertCmd.MarkFlagRequired("hostname")
	genCertCmd.MarkFlagRequired("ip")

	return genCertCmd
}

// KubeProxyConfig represents the structure of kube-proxy-config.yaml
type KubeProxyConfig struct {
	ClusterCIDR string `yaml:"clusterCIDR"`
}

// readClusterCIDRFromConfig reads the clusterCIDR from the local kube-proxy-config.yaml file
func readClusterCIDRFromConfig(configPath string) (string, error) {
	// Check if file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		klog.V(2).Infof("Kube-proxy config file not found at %s, using default", configPath)
		return "", nil
	}

	// Read the file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("failed to read kube-proxy config file: %v", err)
	}

	// Parse YAML
	var config KubeProxyConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return "", fmt.Errorf("failed to parse kube-proxy config YAML: %v", err)
	}

	if config.ClusterCIDR != "" {
		klog.V(2).Infof("Read clusterCIDR from %s: %s", configPath, config.ClusterCIDR)
		return config.ClusterCIDR, nil
	}

	return "", nil
}

// readKubeletDataDirFromService reads the kubelet data directory from the local kubelet.service file
func readKubeletDataDirFromService(servicePath string) (string, error) {
	// Check if file exists
	if _, err := os.Stat(servicePath); os.IsNotExist(err) {
		klog.V(2).Infof("Kubelet service file not found at %s, using default", servicePath)
		return "", nil
	}

	// Read the file
	file, err := os.Open(servicePath)
	if err != nil {
		return "", fmt.Errorf("failed to open kubelet service file: %v", err)
	}
	defer file.Close()

	// Regular expression to match --root-dir parameter
	rootDirRegex := regexp.MustCompile(`--root-dir[=\s]+([^\s\\]+)`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if matches := rootDirRegex.FindStringSubmatch(line); len(matches) > 1 {
			dataDir := strings.TrimSpace(matches[1])
			klog.V(2).Infof("Read kubelet data directory from %s: %s", servicePath, dataDir)
			return dataDir, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("failed to read kubelet service file: %v", err)
	}

	return "", nil
}

// generateKubeletCert generates kubelet certificate, key, and kubeconfig files
func generateKubeletCert(hostname, ipAddress, apiServer, caFile, caKeyFile, certFile, keyFile, kubeconfigFile, kubeProxyConfigFile, outputDir,
	country, state, locality, organization, orgUnit, clusterCIDR, kubeletDataDir string, generateServiceFiles bool) error {

	// Show warning if using default API server address
	if apiServer == "https://127.0.0.1:6443" {
		klog.Warningf("Using default API server address: %s", apiServer)
		klog.Warningf("Please double-check if this is the correct API server address for your cluster")
	}

	// Auto-detect clusterCIDR from local kube-proxy config if not provided or using default
	if clusterCIDR == "200.20.0.0/18" {
		if detectedCIDR, err := readClusterCIDRFromConfig("/var/lib/kube-proxy/kube-proxy-config.yaml"); err != nil {
			klog.Warningf("Failed to read clusterCIDR from local config: %v", err)
			klog.Infof("Using default clusterCIDR: %s", clusterCIDR)
		} else if detectedCIDR != "" {
			clusterCIDR = detectedCIDR
			klog.Infof("Auto-detected clusterCIDR from local config: %s", clusterCIDR)
		} else {
			klog.Infof("Using default clusterCIDR: %s", clusterCIDR)
		}
	}

	// Auto-detect kubelet data directory from local kubelet service if not provided or using default
	if kubeletDataDir == "/data/kubelet" {
		if detectedDataDir, err := readKubeletDataDirFromService("/etc/systemd/system/kubelet.service"); err != nil {
			klog.Warningf("Failed to read kubelet data directory from local service: %v", err)
			klog.Infof("Using default kubelet data directory: %s", kubeletDataDir)
		} else if detectedDataDir != "" {
			kubeletDataDir = detectedDataDir
			klog.Infof("Auto-detected kubelet data directory from local service: %s", kubeletDataDir)
		} else {
			klog.Infof("Using default kubelet data directory: %s", kubeletDataDir)
		}
	}

	// Determine output paths
	var finalCertFile, finalKeyFile, finalKubeconfigFile, finalKubeProxyConfigFile, finalKubeletServiceFile, finalKubeProxyConfigYamlFile string
	if outputDir != "" {
		// Ensure output directory exists
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %v", err)
		}
		finalCertFile = filepath.Join(outputDir, "kubelet.pem")
		finalKeyFile = filepath.Join(outputDir, "kubelet-key.pem")
		finalKubeconfigFile = filepath.Join(outputDir, "kubelet.kubeconfig")
		finalKubeProxyConfigFile = filepath.Join(outputDir, "kube-proxy.kubeconfig")
		finalKubeletServiceFile = filepath.Join(outputDir, "kubelet.service")
		finalKubeProxyConfigYamlFile = filepath.Join(outputDir, "kube-proxy-config.yaml")
	} else {
		finalCertFile = certFile
		finalKeyFile = keyFile
		finalKubeconfigFile = kubeconfigFile
		finalKubeProxyConfigFile = kubeProxyConfigFile
		finalKubeletServiceFile = "/etc/systemd/system/kubelet.service"
		finalKubeProxyConfigYamlFile = "/var/lib/kube-proxy/kube-proxy-config.yaml"

		// Ensure output directories exist
		certDir := filepath.Dir(finalCertFile)
		keyDir := filepath.Dir(finalKeyFile)
		kubeconfigDir := filepath.Dir(finalKubeconfigFile)
		kubeProxyConfigDir := filepath.Dir(finalKubeProxyConfigFile)

		for _, dir := range []string{certDir, keyDir, kubeconfigDir, kubeProxyConfigDir} {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return fmt.Errorf("failed to create directory %s: %v", dir, err)
			}
		}
	}

	// Backup existing files if they are critical system files
	if err := backupExistingFiles(finalCertFile, finalKeyFile, finalKubeconfigFile, finalKubeProxyConfigFile); err != nil {
		return fmt.Errorf("failed to backup existing files: %v", err)
	}

	// Validate CA files exist
	if _, err := os.Stat(caFile); os.IsNotExist(err) {
		return fmt.Errorf("CA certificate file not found: %s", caFile)
	}
	if _, err := os.Stat(caKeyFile); os.IsNotExist(err) {
		return fmt.Errorf("CA private key file not found: %s", caKeyFile)
	}

	klog.Infof("Generating kubelet certificate for hostname: %s, IP: %s", hostname, ipAddress)

	// Create temporary directory for intermediate files
	tempDir, err := os.MkdirTemp("", "kubelet-cert-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	csrConfFile := filepath.Join(tempDir, "kubelet-csr.conf")
	csrFile := filepath.Join(tempDir, "kubelet.csr")
	tempKeyFile := filepath.Join(tempDir, "kubelet-key.pem")

	// Generate CSR configuration file
	if err := generateCSRConfig(csrConfFile, hostname, ipAddress, country, state, locality, organization, orgUnit); err != nil {
		return fmt.Errorf("failed to generate CSR config: %v", err)
	}

	// Generate private key
	klog.V(2).Infof("Generating private key...")
	if err := runCommand("openssl", "genrsa", "-out", tempKeyFile, "2048"); err != nil {
		return fmt.Errorf("failed to generate private key: %v", err)
	}

	// Generate certificate signing request
	klog.V(2).Infof("Generating certificate signing request...")
	subject := fmt.Sprintf("/C=%s/ST=%s/L=%s/O=%s/OU=%s/CN=system:node:%s",
		country, state, locality, organization, orgUnit, hostname)

	if err := runCommand("openssl", "req", "-new", "-key", tempKeyFile,
		"-out", csrFile, "-config", csrConfFile, "-subj", subject); err != nil {
		return fmt.Errorf("failed to generate CSR: %v", err)
	}

	// Sign certificate with CA
	klog.V(2).Infof("Signing certificate with CA...")
	tempCertFile := filepath.Join(tempDir, "kubelet.pem")
	if err := runCommand("openssl", "x509", "-req", "-in", csrFile,
		"-CA", caFile, "-CAkey", caKeyFile, "-CAcreateserial",
		"-out", tempCertFile, "-days", "18250", "-extensions", "v3_req",
		"-extfile", csrConfFile); err != nil {
		return fmt.Errorf("failed to sign certificate: %v", err)
	}

	// Copy generated files to final locations
	if err := copyFile(tempCertFile, finalCertFile); err != nil {
		return fmt.Errorf("failed to copy certificate: %v", err)
	}
	if err := copyFile(tempKeyFile, finalKeyFile); err != nil {
		return fmt.Errorf("failed to copy private key: %v", err)
	}

	// Set appropriate permissions
	if err := os.Chmod(finalCertFile, 0644); err != nil {
		klog.Warningf("Failed to set certificate permissions: %v", err)
	}
	if err := os.Chmod(finalKeyFile, 0600); err != nil {
		klog.Warningf("Failed to set private key permissions: %v", err)
	}

	// Generate kubelet kubeconfig file
	klog.V(2).Infof("Generating kubelet kubeconfig file...")
	if err := generateKubeconfig(finalKubeconfigFile, apiServer, caFile, finalCertFile, finalKeyFile, hostname); err != nil {
		return fmt.Errorf("failed to generate kubelet kubeconfig: %v", err)
	}

	// Generate kube-proxy kubeconfig file
	klog.V(2).Infof("Generating kube-proxy kubeconfig file...")
	if err := generateKubeProxyConfig(finalKubeProxyConfigFile, apiServer, caFile, finalCertFile, finalKeyFile); err != nil {
		return fmt.Errorf("failed to generate kube-proxy kubeconfig: %v", err)
	}

	// Set kubeconfig permissions
	if err := os.Chmod(finalKubeconfigFile, 0600); err != nil {
		klog.Warningf("Failed to set kubelet kubeconfig permissions: %v", err)
	}
	if err := os.Chmod(finalKubeProxyConfigFile, 0600); err != nil {
		klog.Warningf("Failed to set kube-proxy kubeconfig permissions: %v", err)
	}

	// Generate service files if requested
	if generateServiceFiles {
		// Generate kubelet.service file
		klog.V(2).Infof("Generating kubelet.service file...")
		if err := generateKubeletService(finalKubeletServiceFile, hostname, ipAddress, kubeletDataDir); err != nil {
			return fmt.Errorf("failed to generate kubelet.service: %v", err)
		}

		// Generate kube-proxy-config.yaml file
		klog.V(2).Infof("Generating kube-proxy-config.yaml file...")
		if err := generateKubeProxyConfigYaml(finalKubeProxyConfigYamlFile, hostname, clusterCIDR); err != nil {
			return fmt.Errorf("failed to generate kube-proxy-config.yaml: %v", err)
		}

		klog.Infof("Successfully generated kubelet certificate, kubeconfig, and service files:")
		klog.Infof("  Certificate: %s", finalCertFile)
		klog.Infof("  Private Key: %s", finalKeyFile)
		klog.Infof("  Kubelet Kubeconfig: %s", finalKubeconfigFile)
		klog.Infof("  Kube-proxy Kubeconfig: %s", finalKubeProxyConfigFile)
		klog.Infof("  Kubelet Service: %s", finalKubeletServiceFile)
		klog.Infof("  Kube-proxy Config: %s", finalKubeProxyConfigYamlFile)
	} else {
		klog.Infof("Successfully generated kubelet certificate and kubeconfig files:")
		klog.Infof("  Certificate: %s", finalCertFile)
		klog.Infof("  Private Key: %s", finalKeyFile)
		klog.Infof("  Kubelet Kubeconfig: %s", finalKubeconfigFile)
		klog.Infof("  Kube-proxy Kubeconfig: %s", finalKubeProxyConfigFile)
	}

	// Verify certificate
	klog.V(2).Infof("Verifying generated certificate...")
	if err := runCommand("openssl", "x509", "-in", finalCertFile, "-text", "-noout"); err != nil {
		klog.Warningf("Failed to verify certificate: %v", err)
	}

	return nil
}

// generateKubeconfig creates the kubeconfig file with base64-encoded certificates
func generateKubeconfig(kubeconfigFile, apiServer, caFile, certFile, keyFile, hostname string) error {
	// Read and encode CA certificate
	caData, err := os.ReadFile(caFile)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %v", err)
	}
	caBase64 := base64.StdEncoding.EncodeToString(caData)

	// Read and encode client certificate
	certData, err := os.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("failed to read client certificate: %v", err)
	}
	certBase64 := base64.StdEncoding.EncodeToString(certData)

	// Read and encode client key
	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("failed to read client key: %v", err)
	}
	keyBase64 := base64.StdEncoding.EncodeToString(keyData)

	// Generate kubeconfig content
	kubeconfigContent := fmt.Sprintf(`apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: %s
    server: %s
  name: kubernetes
contexts:
- context:
    cluster: kubernetes
    user: system:node:%s
  name: default
current-context: default
kind: Config
preferences: {}
users:
- name: system:node:%s
  user:
    client-certificate-data: %s
    client-key-data: %s
`, caBase64, apiServer, hostname, hostname, certBase64, keyBase64)

	// Write kubeconfig file
	return os.WriteFile(kubeconfigFile, []byte(kubeconfigContent), 0600)
}

// generateKubeProxyConfig creates the kube-proxy kubeconfig file with base64-encoded certificates
func generateKubeProxyConfig(kubeconfigFile, apiServer, caFile, certFile, keyFile string) error {
	// Read and encode CA certificate
	caData, err := os.ReadFile(caFile)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %v", err)
	}
	caBase64 := base64.StdEncoding.EncodeToString(caData)

	// Read and encode client certificate
	certData, err := os.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("failed to read client certificate: %v", err)
	}
	certBase64 := base64.StdEncoding.EncodeToString(certData)

	// Read and encode client key
	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("failed to read client key: %v", err)
	}
	keyBase64 := base64.StdEncoding.EncodeToString(keyData)

	// Generate kube-proxy kubeconfig content
	kubeconfigContent := fmt.Sprintf(`apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: %s
    server: %s
  name: kubernetes
contexts:
- context:
    cluster: kubernetes
    user: kube-proxy
  name: default
current-context: default
kind: Config
preferences: {}
users:
- name: kube-proxy
  user:
    client-certificate-data: %s
    client-key-data: %s
`, caBase64, apiServer, certBase64, keyBase64)

	// Write kubeconfig file
	return os.WriteFile(kubeconfigFile, []byte(kubeconfigContent), 0600)
}

// generateCSRConfig creates the OpenSSL configuration file for CSR generation
func generateCSRConfig(configFile, hostname, ipAddress, country, state, locality, organization, orgUnit string) error {
	config := fmt.Sprintf(`[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name

[req_distinguished_name]
countryName = %s
stateOrProvinceName = %s
localityName = %s
organizationName = %s
organizationalUnitName = %s
commonName = system:node:%s

[v3_req]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = %s
IP.1 = 127.0.0.1
IP.2 = %s
`, country, state, locality, organization, orgUnit, hostname, hostname, ipAddress)

	return os.WriteFile(configFile, []byte(config), 0644)
}

// runCommand executes a shell command and returns error if it fails
func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	klog.V(3).Infof("Running command: %s %s", name, strings.Join(args, " "))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("command failed: %s\nOutput: %s", err, string(output))
	}

	if klog.V(4).Enabled() {
		klog.Infof("Command output: %s", string(output))
	}

	return nil
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}

// backupExistingFiles backs up critical system files if they exist
func backupExistingFiles(certFile, keyFile, kubeconfigFile, kubeProxyConfigFile string) error {
	// List of critical files that should be backed up
	criticalFiles := map[string]bool{
		"/etc/kubernetes/kubelet.kubeconfig":    true,
		"/etc/kubernetes/kube-proxy.kubeconfig": true,
		"/etc/kubernetes/ssl/kubelet.pem":       true,
		"/etc/kubernetes/ssl/kubelet-key.pem":   true,
	}

	filesToBackup := []string{certFile, keyFile, kubeconfigFile, kubeProxyConfigFile}

	for _, file := range filesToBackup {
		// Only backup if it's a critical system file and exists
		if criticalFiles[file] {
			if _, err := os.Stat(file); err == nil {
				backupFile := file + ".bak"
				klog.Infof("Backing up existing file: %s -> %s", file, backupFile)

				// Use os.Rename to move the file (atomic operation)
				if err := os.Rename(file, backupFile); err != nil {
					return fmt.Errorf("failed to backup %s: %v", file, err)
				}
				klog.Infof("Successfully backed up %s", file)
			}
		}
	}

	return nil
}

// generateKubeletService creates the kubelet.service systemd unit file
func generateKubeletService(serviceFile, hostname, ipAddress, kubeletDataDir string) error {
	serviceContent := fmt.Sprintf(`[Unit]
Description=Kubernetes Kubelet
Documentation=https://github.com/GoogleCloudPlatform/kubernetes

[Service]
WorkingDirectory=/var/lib/kubelet
ExecStartPre=/bin/mount -o remount,rw '/sys/fs/cgroup'
ExecStart=/opt/kube/bin/kubelet \
  --config=/var/lib/kubelet/config.yaml \
  --container-runtime-endpoint=unix:///run/containerd/containerd.sock \
  --hostname-override=%s \
  --node-ip=%s \
  --kubeconfig=/etc/kubernetes/kubelet.kubeconfig \
  --root-dir=%s \
  --v=2
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`, hostname, ipAddress, kubeletDataDir)

	// Ensure directory exists
	serviceDir := filepath.Dir(serviceFile)
	if err := os.MkdirAll(serviceDir, 0755); err != nil {
		return fmt.Errorf("failed to create service directory: %v", err)
	}

	return os.WriteFile(serviceFile, []byte(serviceContent), 0644)
}

// generateKubeProxyConfigYaml creates the kube-proxy-config.yaml configuration file
func generateKubeProxyConfigYaml(configFile, hostname, clusterCIDR string) error {
	configContent := fmt.Sprintf(`kind: KubeProxyConfiguration
apiVersion: kubeproxy.config.k8s.io/v1alpha1
bindAddress: 0.0.0.0
clientConnection:
  kubeconfig: "/etc/kubernetes/kube-proxy.kubeconfig"
# 根据clusterCIDR 判断集群内部和外部流量，配置clusterCIDR选项后，kube-proxy 会对访问 Service IP 的请求做 SNAT
clusterCIDR: "%s"
conntrack:
  maxPerCore: 32768
  min: 131072
  tcpCloseWaitTimeout: 1h0m0s
  tcpEstablishedTimeout: 24h0m0s
healthzBindAddress: 0.0.0.0:10256
# hostnameOverride 值必须与 kubelet 的对应一致，否则 kube-proxy 启动后会找不到该 Node，从而不会创建任何 iptables 规则
hostnameOverride: "%s"
metricsBindAddress: 0.0.0.0:10249
mode: "ipvs"
ipvs:
  excludeCIDRs: null
  minSyncPeriod: 0s
  scheduler: ""
  strictARP: False
  syncPeriod: 30s
  tcpFinTimeout: 0s
  tcpTimeout: 0s
  udpTimeout: 0s
`, clusterCIDR, hostname)

	// Ensure directory exists
	configDir := filepath.Dir(configFile)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}

	return os.WriteFile(configFile, []byte(configContent), 0644)
}
